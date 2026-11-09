package grants

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These integration fixtures use ephemeral test-only records and countereffects.
// The published corpus is exercised separately, byte-for-byte by the harness.
type linuxCombinedRig struct {
	dock   *linuxVerifierDock
	config LinuxReceiverConfig
	calls  int
	effect MUEffect
}

func newLinuxCombinedRig(t *testing.T) *linuxCombinedRig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return newLinuxCombinedRigAt(t, filepath.Join(root, "state"))
}

func newLinuxCombinedRigAt(t *testing.T, dir string) *linuxCombinedRig {
	t.Helper()
	g := &linuxCombinedRig{dock: newLinuxVerifierDock(t)}
	d := g.dock
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	g.config = LinuxReceiverConfig{MUReceiverConfig: MUReceiverConfig{
		Binding: MUBinding{Audience: d.config.Audience, GrantRoot: d.config.GrantRoot},
		State:   MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("combined-fixture-epoch"))},
		Owner:   "owner:alexis", RoomScope: "swarma-space", Modules: map[string]bool{"swarma-keyvault": true},
		RootRevocations: func() ([]MURevocation, error) { return nil, nil },
		Signers:         map[string]bool{d.config.PublisherKey: true, d.config.AgentRevocationRoot: true},
	}, PublisherKey: d.config.PublisherKey, AgentRevocationRoot: d.config.AgentRevocationRoot, RoomID: d.config.RoomID, ReceiverMXID: d.config.ReceiverMXID}
	if err := InitializeLinuxReceiverState(g.config.State, g.config.Binding, g.config.RootRevocations); err != nil {
		t.Fatal(err)
	}
	g.effect = linuxEffectFunc(func(context.Context, MUDecision) ([]byte, error) {
		g.calls++
		return []byte("combined synthetic receipt"), nil
	})
	return g
}
func (g *linuxCombinedRig) receiver() *LinuxReceiver {
	return NewLinuxReceiver(g.config, g.dock.adapter(), fakeRegistry{keys: map[string]string{g.dock.event.Sender: g.dock.agentID}},
		map[string]MUEffect{"work.assign": g.effect}, func() (time.Time, error) { return g.dock.now, nil })
}
func (g *linuxCombinedRig) handle() error {
	_, err := g.receiver().Handle(context.Background(), g.dock.event)
	return err
}

// Claim: Per-signer older or incomplete history refuses across reopen, while equal complete history permits one effect.
func TestLinuxCombinedSignerDurability(t *testing.T) {
	for _, role := range []string{"publisher", "registry"} {
		for _, mode := range []string{"older", "dropped-union"} {
			t.Run(role+"/"+mode, func(t *testing.T) {
				g := newLinuxCombinedRig(t)
				d := g.dock
				signer := d.pub.id
				if role == "registry" {
					signer = d.revokerID
				}
				issued := d.now.Add(-10 * time.Second)
				hash := sha256.Sum256([]byte("unrelated fixture revocation"))
				entries := []any{map[string]any{"kind": "record", "id": "sha256:" + hex.EncodeToString(hash[:]), "from": d.now.Add(-time.Hour).Format(time.RFC3339)}}
				if mode == "older" {
					entries = nil
				}
				d.snapshot(signer, issued, entries)
				// Persist continuity even when local policy refuses before reserve.
				admission, err := d.adapter().VerifyAdmission(d.event, d.now)
				if err != nil || len(admission.Snapshots) != 2 {
					t.Fatal("real admission", err)
				}
				g.config.Paused = map[string]bool{admission.Decision.GrantID: true}
				if err := g.handle(); !errors.Is(err, ErrMUPaused) {
					t.Fatal(err)
				}
				if mode == "older" {
					d.snapshot(signer, issued.Add(-time.Second), nil)
				} else {
					d.snapshot(signer, issued.Add(time.Second), nil)
				}
				g.config.Paused = nil
				// Each handle constructs a new receiver and reloads the MU journal.
				if err := g.handle(); !errors.Is(err, ErrMURollback) || g.calls != 0 {
					t.Fatal("lost signer continuity", err, g.calls)
				}
				// Even a dropped-union refusal records the newer signed mark.
				// Restoring the union at the old mark must still refuse rollback.
				if mode == "dropped-union" {
					d.snapshot(signer, issued, entries)
					if err := g.handle(); !errors.Is(err, ErrMURollback) || g.calls != 0 {
						t.Fatal("refused snapshot lost its newer mark", err, g.calls)
					}
					issued = issued.Add(time.Second)
				}
				d.snapshot(signer, issued, entries)
				if err := g.handle(); err != nil || g.calls != 1 {
					t.Fatal("equal signed snapshot refused", err, g.calls)
				}
				if err := g.handle(); !errors.Is(err, ErrMUNonceHeld) || g.calls != 1 {
					t.Fatal("replay", err, g.calls)
				}
			})
		}
	}
}

// Claim: Authenticated owner-root holds survive refusal and reapplication into a new epoch; old-epoch state refuses.
func TestLinuxCombinedRootRestore(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	// Independently signed owner-root record is old and absent from publisher.
	raw := d.signRoot(map[string]any{"type": "revocation/1", "issuer": d.root.id, "issued_at": d.now.Add(-24 * time.Hour).Format(time.RFC3339), "complete": true,
		"entries": []any{map[string]any{"kind": "key", "id": d.pub.id, "from": d.now.Add(-24 * time.Hour).Format(time.RFC3339)}}})
	roots := func() ([]MURevocation, error) { return VerifyRootRevocations(d.root.id, [][]byte{raw}) }
	g.config.RootRevocations = roots
	if err := g.handle(); !errors.Is(err, ErrMURevoked) || g.calls != 0 {
		t.Fatal(err, g.calls)
	}
	g.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	if err := g.handle(); !errors.Is(err, ErrMURevoked) {
		t.Fatal("root not durable", err)
	}
	old := g.config.State
	fresh := MUStateConfig{Directory: filepath.Join(t.TempDir(), "restored"), Epoch: sha256.Sum256([]byte("new-external-epoch"))}
	if err := os.Mkdir(fresh.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.config.Binding, fresh.Epoch, roots); !errors.Is(err, ErrMUState) {
		t.Fatal("same epoch", err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.config.Binding, old.Epoch, nil); !errors.Is(err, ErrMUState) {
		t.Fatal("missing roots", err)
	}
	if err := RestoreLinuxReceiverState(fresh, g.config.Binding, old.Epoch, roots); err != nil {
		t.Fatal(err)
	}
	g.config.State = fresh
	if err := g.handle(); !errors.Is(err, ErrMURevoked) || g.calls != 0 {
		t.Fatal("restore lost roots", err, g.calls)
	}
	g.config.State = old
	g.config.State.Epoch = fresh.Epoch
	if err := g.handle(); !errors.Is(err, ErrMUState) {
		t.Fatal("old journal in new epoch", err)
	}
}

// Claim: Intent or outcome failure holds the reservation without redispatch, while successful dispatch records its outcome.
func TestLinuxCombinedAccountingUnknown(t *testing.T) {
	for _, mode := range []string{"success", "intent-write", "effect-unknown", "outcome-write"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			r := g.receiver()
			var locked *muState
			r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, c, b)
				if err != nil {
					return nil, err
				}
				locked = s
				writes := 0
				s.write = func(f *os.File, raw []byte) (int, error) {
					if filepath.Base(f.Name()) == "mu.journal" && (raw[10] == byte(journalReservation) || raw[10] == byte(journalDispatchIntent) || raw[10] == byte(journalOutcome)) {
						writes++
						if (mode == "intent-write" && writes == 2) || (mode == "outcome-write" && writes == 3) {
							return 0, errors.New("synthetic journal failure")
						}
					}
					return f.Write(raw)
				}
				return s, nil
			}
			r.effects["work.assign"] = linuxEffectFunc(func(context.Context, MUDecision) ([]byte, error) {
				if locked == nil || len(locked.reservations) != 1 {
					t.Fatal("effect before reservation")
				}
				for _, v := range locked.reservations {
					if !v.intent || v.complete {
						t.Fatal("effect before intent or after outcome")
					}
				}
				// Both actual per-signer highwaters must already be durable.
				snaps, err := openLinuxRevocationState(locked)
				if err != nil {
					t.Fatal(err)
				}
				if len(snaps.latest) != 2 {
					t.Fatal("effect before durable snapshots")
				}
				snaps.close()
				g.calls++
				if mode == "effect-unknown" {
					return nil, errors.New("synthetic unknown")
				}
				return []byte("synthetic receipt"), nil
			})
			out, err := r.Handle(context.Background(), g.dock.event)
			if mode == "success" {
				if err != nil || out == nil || out.State != "succeeded" {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrMUUnknown) || out == nil || out.State != "unknown" {
				t.Fatal("unknown lost", err)
			}
			want := 1
			if mode == "intent-write" {
				want = 0
			}
			if g.calls != want {
				t.Fatal("effects", g.calls, want)
			}
			// Real adapter rechecks, but durable reservation blocks dispatch.
			if err := g.handle(); !errors.Is(err, ErrMUNonceHeld) || g.calls != want {
				t.Fatal("unknown replayed", err, g.calls)
			}
			s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if len(s.reservations) != 1 {
				t.Fatal("missing durable reservation")
			}
			for _, v := range s.reservations {
				if v.complete != (mode == "success") || v.intent != (mode != "intent-write") {
					t.Fatal("wrong durable lifecycle")
				}
			}
		})
	}
}

type linuxSingleSampleSource struct {
	*linuxVerifierFake
	reads map[string]int
}

func (s *linuxSingleSampleSource) Snapshot(root string) (LinuxSnapshot, error) {
	s.reads[root]++
	if s.reads[root] > 1 {
		return LinuxSnapshot{}, errors.New("second source read prohibited")
	}
	return s.linuxVerifierFake.Snapshot(root)
}

// Claim: Admission uses each source once and retains the healthy signer when its peer is corrupt.
func TestLinuxCombinedSameCallCustody(t *testing.T) {
	d := newLinuxVerifierDock(t)
	source := &linuxSingleSampleSource{linuxVerifierFake: d.fake, reads: map[string]int{}}
	v, err := NewLinuxVerifier(d.config, source, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.VerifyAdmission(d.event, d.now)
	if err != nil || len(a.Snapshots) != 2 || source.reads[d.pub.id] != 1 || source.reads[d.revokerID] != 1 {
		t.Fatal("not same sample", err, source.reads)
	}
	// Corrupt publisher evidence contributes no candidate or publisher mark,
	// while the independently verified registry sample must retain custody.
	d.fake.snapshots[d.pub.id] = LinuxSnapshot{Wire: []byte("corrupt"), Available: true, RollbackSafe: true}
	source.reads = map[string]int{}
	refused, err := v.VerifyAdmission(d.event, d.now)
	if err == nil || refused.Decision.Author != "" || refused.Decision.Use != "" || refused.Decision.RequestHash != [32]byte{} {
		t.Fatal("refusal leaked candidate", refused.Decision, err)
	}
	if len(refused.Snapshots) != 1 || refused.Snapshots[0].Signer != d.revokerID ||
		!refused.Snapshots[0].IssuedAt.Equal(d.now.Add(-5*time.Second)) || len(refused.Snapshots[0].Entries) != 0 {
		t.Fatal("refusal lost healthy sample or retained corrupt publisher", refused.Snapshots)
	}
	if source.reads[d.pub.id] != 1 || source.reads[d.revokerID] != 1 {
		t.Fatal("refusal fetched a different sample", source.reads)
	}
}
