package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type linuxAdmissionFunc func(MUEnvelopeEvent, time.Time) (LinuxAdmission, error)

func (f linuxAdmissionFunc) VerifyAdmission(e MUEnvelopeEvent, n time.Time) (LinuxAdmission, error) {
	return f(e, n)
}
func linuxSnapshotRig(g *linuxRig, issued *time.Time, extra *LinuxVerifiedSnapshot) {
	g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, n time.Time) (LinuxAdmission, error) {
		d, err := g.v.VerifyProjected(e, n)
		snapshots := []LinuxVerifiedSnapshot{{Signer: g.v.publisher, IssuedAt: *issued, Entries: g.v.revocations}}
		if extra != nil {
			snapshots = append(snapshots, *extra)
		}
		return LinuxAdmission{Decision: d, Snapshots: snapshots}, err
	})
}

// Claim: Per-signer marks survive local policy refusal and reopen; older marks refuse and equal/newer complete samples admit.
func TestLinuxReceiverSnapshotHighwater(t *testing.T) {
	g := newLinuxRig(t)
	issued := muNow.Add(-10 * time.Second)
	linuxSnapshotRig(g, &issued, nil)
	e := g.event(t, "$watermark")
	g.r.config.Paused[g.v.grant] = true
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUPaused) {
		t.Fatal(err)
	}
	// Reconstruct both receiver and journal: lower-but-still-fresh must fail.
	g.reopen()
	linuxSnapshotRig(g, &issued, nil)
	issued = issued.Add(-time.Second)
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURollback) {
		t.Fatal(err)
	}
	issued = issued.Add(time.Second)
	g.r.config.Paused[g.v.grant] = false
	if _, err := g.r.Handle(context.Background(), e); err != nil {
		t.Fatal("equal refused", err)
	}
	issued = issued.Add(time.Second)
	if _, err := g.r.Handle(context.Background(), g.event(t, "$advance")); err != nil {
		t.Fatal("newer refused", err)
	}
	if g.calls.Load() != 2 {
		t.Fatal(g.calls.Load())
	}
}

// Claim: One signer cannot borrow another signer's clock, and independently complete equal samples admit.
func TestLinuxReceiverHighwaterPerSigner(t *testing.T) {
	g := newLinuxRig(t)
	issued := muNow.Add(-5 * time.Second)
	extra := LinuxVerifiedSnapshot{Signer: "ed25519:synthetic-agent-revoker", IssuedAt: muNow.Add(-30 * time.Second)}
	linuxSnapshotRig(g, &issued, &extra)
	if _, err := g.r.Handle(context.Background(), g.event(t, "$a")); err != nil {
		t.Fatal(err)
	}
	g.reopen()
	linuxSnapshotRig(g, &issued, &extra)
	issued = issued.Add(time.Second)
	extra.IssuedAt = extra.IssuedAt.Add(-time.Second)
	if _, err := g.r.Handle(context.Background(), g.event(t, "$b")); !errors.Is(err, ErrMURollback) {
		t.Fatal("second signer rollback", err)
	}
	extra.IssuedAt = extra.IssuedAt.Add(time.Second)
	if _, err := g.r.Handle(context.Background(), g.event(t, "$c")); err != nil {
		t.Fatal("independent clocks", err)
	}
}

// Claim: Owner-root holds survive reopen without creating a publisher completeness obligation.
func TestLinuxReceiverRootsIndependentOfPublisher(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$root-unrelated")
	root := MURevocation{"record", "sha256:unrelated-owner-root"}
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{root}, nil }
	if _, err := g.r.Handle(context.Background(), e); err != nil {
		t.Fatal("publisher omitted unrelated root", err)
	}
	g.reopen()
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	if _, err := g.r.Handle(context.Background(), g.event(t, "$root-reopen")); err != nil {
		t.Fatal(err)
	}
	s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !s.revoked[root] {
		t.Fatal("root not durable")
	}
}

// Claim: Torn writes refuse reopen and a failed sync cannot allow an older snapshot or effect.
func TestLinuxReceiverHighwaterCrashControls(t *testing.T) {
	for _, mode := range []string{"short-write", "fsync"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			issued := muNow.Add(-10 * time.Second)
			linuxSnapshotRig(g, &issued, nil)
			g.r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, c, b)
				if err != nil {
					return nil, err
				}
				if mode == "short-write" {
					s.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
				} else {
					s.sync = func(*os.File) error { return errors.New("injected sync failure") }
				}
				return s, nil
			}
			e := g.event(t, "$highwater-crash")
			if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
				t.Fatal(err, g.calls.Load())
			}
			g.reopen()
			linuxSnapshotRig(g, &issued, nil)
			issued = issued.Add(-time.Second)
			_, err := g.r.Handle(context.Background(), e)
			want := ErrMURollback
			if mode == "short-write" {
				want = ErrMUState
			}
			if !errors.Is(err, want) || g.calls.Load() != 0 {
				t.Fatal("crash reopened unsafely", err)
			}
		})
	}
}

// Claim: Explicit recovery requires a distinct nonzero epoch, an empty private directory and reapplication of owner roots.
func TestLinuxReceiverExplicitRestore(t *testing.T) {
	g := newLinuxRig(t)
	old := g.r.config.State
	fresh := MUStateConfig{Directory: filepath.Join(t.TempDir(), "restore"), Epoch: sha256.Sum256([]byte("new-restore-epoch"))}
	if err := os.Mkdir(fresh.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	roots := func() ([]MURevocation, error) { return []MURevocation{{"key", g.v.publisher}}, nil }
	if err := RestoreLinuxReceiverState(fresh, g.r.config.Binding, fresh.Epoch, roots); !errors.Is(err, ErrMUState) {
		t.Fatal("same epoch allowed", err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.r.config.Binding, old.Epoch, nil); !errors.Is(err, ErrMUState) {
		t.Fatal("missing roots allowed", err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.r.config.Binding, old.Epoch, roots); err != nil {
		t.Fatal(err)
	}
	g.r.config.State = fresh
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	if _, err := g.r.Handle(context.Background(), g.event(t, "$restore")); !errors.Is(err, ErrMURevoked) {
		t.Fatal("roots not reapplied", err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.r.config.Binding, old.Epoch, roots); !errors.Is(err, ErrMUState) {
		t.Fatal("adopted existing", err)
	}
	// Externally supplied new epoch cannot open either old journal.
	g.r.config.State = old
	g.r.config.State.Epoch = fresh.Epoch
	if _, err := g.r.Handle(context.Background(), g.event(t, "$wrong-epoch")); !errors.Is(err, ErrMUState) {
		t.Fatal(err)
	}
}

// Claim: A missing MU journal refuses without any effect.
func TestLinuxReceiverMissingMUJournalFailsClosed(t *testing.T) {
	g := newLinuxRig(t)
	if err := os.Remove(filepath.Join(g.r.config.State.Directory, "mu.journal")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.Handle(context.Background(), g.event(t, "$missing")); !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
		t.Fatal(err)
	}
}

// Claim: A newly sampled owner-root hold at final admission prevents dispatch.
func TestLinuxReceiverFinalRootSample(t *testing.T) {
	g := newLinuxRig(t)
	reads := 0
	g.r.config.RootRevocations = func() ([]MURevocation, error) {
		reads++
		if reads == 2 {
			return []MURevocation{{"key", g.v.publisher}}, nil
		}
		return nil, nil
	}
	if _, err := g.r.Handle(context.Background(), g.event(t, "$new-root")); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
		t.Fatal(err, g.calls.Load())
	}
}

// Claim: Missing, duplicate, misbound, stale or malformed admission metadata refuses before effect.
func TestLinuxReceiverAdmissionMetadataRefuses(t *testing.T) {
	changes := map[string]func(*LinuxAdmission){
		"missing":           func(a *LinuxAdmission) { a.Snapshots = nil },
		"wrong-signer":      func(a *LinuxAdmission) { a.Snapshots[0].Signer = "p256:other" },
		"duplicate":         func(a *LinuxAdmission) { a.Snapshots = append(a.Snapshots, a.Snapshots[0]) },
		"future":            func(a *LinuxAdmission) { a.Snapshots[0].IssuedAt = muNow.Add(time.Second) },
		"stale":             func(a *LinuxAdmission) { a.Snapshots[0].IssuedAt = muNow.Add(-61 * time.Second) },
		"fraction":          func(a *LinuxAdmission) { a.Snapshots[0].IssuedAt = muNow.Add(-time.Nanosecond) },
		"entries-not-bound": func(a *LinuxAdmission) { a.Snapshots[0].Entries = []MURevocation{{"record", "sha256:unbound"}} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			g := newLinuxRig(t)
			g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, n time.Time) (LinuxAdmission, error) {
				a, err := g.v.VerifyAdmission(e, n)
				change(&a)
				return a, err
			})
			if _, err := g.r.Handle(context.Background(), g.event(t, "$invalid-metadata")); !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
				t.Fatal(err, g.calls.Load())
			}
		})
	}
}

// A complete old image remains valid under its OLD configured epoch. This is
// intentionally a negative control against claiming local rollback detection.
// Claim: A coherent old backup can replay under its old epoch, so local framing does not establish freshness.
func TestLinuxReceiverBackupCannotSelfDetect(t *testing.T) {
	g := newLinuxRig(t)
	accounting := g.journal(t)
	e := g.event(t, "$before-backup")
	if _, err := g.r.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.r.config.State.Directory, "mu.journal"), accounting, 0600); err != nil {
		t.Fatal(err)
	}
	g.reopen()
	// A custodian violating the restore contract can re-execute an old request.
	// Requiring the explicit external restore/new-epoch procedure is essential.
	if _, err := g.r.Handle(context.Background(), e); err != nil || g.calls.Load() != 2 {
		t.Fatal("unexpected self-detection claim", err, g.calls.Load())
	}
}

// Abrupt process exit after real synced journal writes, independently of the
// injected write/fsync failures above. No key provider or live effect is used.
// Claim: Abrupt exit after synced mark, reserve, intent or effect preserves durable holds after reopen.
func TestLinuxReceiverProcessCrash(t *testing.T) {
	type crashInput struct {
		State    MUStateConfig
		Binding  MUBinding
		Use      MUUse
		Decision MUDecision
		Event    MUEnvelopeEvent
		Mode     string
		Marker   string
	}
	if raw := os.Getenv("LINUX_RECEIVER_CRASH_INPUT"); raw != "" {
		var in crashInput
		if err := json.Unmarshal([]byte(raw), &in); err != nil {
			t.Fatal(err)
		}
		s, err := openMUState(context.Background(), in.State, in.Binding)
		if err != nil {
			t.Fatal(err)
		}
		snapshots, err := openLinuxRevocationState(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := snapshots.admit(s, []LinuxVerifiedSnapshot{{Signer: in.Decision.PublisherKey, IssuedAt: muNow}}, in.Decision, muNow); err != nil {
			t.Fatal(err)
		}
		if in.Mode == "highwater" {
			os.Exit(23)
		}
		seq, err := s.reserve(in.Use)
		if err != nil {
			t.Fatal(err)
		}
		if in.Mode == "reserve" {
			os.Exit(23)
		}
		if err := s.markIntent(seq); err != nil {
			t.Fatal(err)
		}
		if in.Mode == "intent" {
			os.Exit(23)
		}
		// A synthetic effect completes, then the process dies before outcome.
		marker, err := os.OpenFile(in.Marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := marker.Write([]byte("effect happened")); err != nil {
			t.Fatal(err)
		}
		if err := marker.Sync(); err != nil {
			t.Fatal(err)
		}
		os.Exit(23)
	}
	for _, mode := range []string{"highwater", "reserve", "intent", "effect"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$process-crash")
			d, err := g.v.VerifyProjected(e, muNow)
			if err != nil {
				t.Fatal(err)
			}
			in := crashInput{State: g.r.config.State, Binding: g.r.config.Binding, Decision: d, Event: e, Mode: mode, Marker: filepath.Join(t.TempDir(), "effect-marker"), Use: MUUse{GrantRoot: d.GrantRoot, GrantID: d.GrantID, Action: d.Action, TargetKind: d.TargetKind, TargetID: d.TargetID, Requester: d.Author, Nonce: d.Nonce, Audience: d.Audience, RequestHash: d.RequestHash}}
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(executable, "-test.run=^TestLinuxReceiverProcessCrash$")
			child.Env = append(os.Environ(), "LINUX_RECEIVER_CRASH_INPUT="+string(raw))
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatal("child did not crash at boundary", err, string(output))
			}
			g.reopen()
			want := ErrMUNonceHeld
			if mode == "highwater" {
				issued := muNow.Add(-time.Second)
				linuxSnapshotRig(g, &issued, nil)
				want = ErrMURollback
			}
			if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, want) || g.calls.Load() != 0 {
				t.Fatal("re-executed after process crash", err, g.calls.Load())
			}
			if mode == "effect" {
				if marker, err := os.ReadFile(in.Marker); err != nil || string(marker) != "effect happened" {
					t.Fatal("effect control", err)
				}
			}
		})
	}
}

// Claim: an adapter batch that breaks the snapshot contract (a signer outside
// the pinned Signers, or one signer twice) refuses with ErrMUState, runs no
// effect and leaves the journal byte-identical, even though the batch also
// carries a valid pinned snapshot. The control is the same pinned snapshot
// alone: it is retained and the request admits.
func TestLinuxReceiverMiswiredSnapshotBatch(t *testing.T) {
	entry := MURevocation{"record", "sha256:miswired-batch"}
	for _, mode := range []string{"unpinned-signer", "duplicate-signer", "control"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			issued := muNow
			g.v.revocations = []MURevocation{entry}
			var extra *LinuxVerifiedSnapshot
			switch mode {
			case "unpinned-signer":
				extra = &LinuxVerifiedSnapshot{Signer: "p256:unpinned", IssuedAt: issued, Entries: []MURevocation{entry}}
			case "duplicate-signer":
				extra = &LinuxVerifiedSnapshot{Signer: g.v.publisher, IssuedAt: issued, Entries: []MURevocation{entry}}
			}
			linuxSnapshotRig(g, &issued, extra)
			before := g.journal(t)
			_, err := g.r.Handle(context.Background(), g.event(t, "$batch"))
			if mode != "control" {
				if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
					t.Fatal("miswired batch admitted or persisted", err, g.calls.Load())
				}
				return
			}
			if err != nil || g.calls.Load() != 1 {
				t.Fatal("pinned snapshot alone refused", err, g.calls.Load())
			}
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if !s.unions[g.v.publisher][entry] {
				t.Fatal("pinned snapshot not retained", s.unions)
			}
		})
	}
}
