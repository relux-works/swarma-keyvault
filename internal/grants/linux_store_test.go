package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: missing, empty, mismatched or aliased signer pins refuse before any state write; explicit distinct pins permit one effect.
func TestLinuxStorePins(t *testing.T) {
	for _, mode := range []string{"valid", "nil", "empty", "missing-publisher", "missing-agent-root", "aliased", "reserved-publisher", "reserved-agent-root", "extra", "wrong-decision"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$pins")
			before := g.journal(t)
			switch mode {
			case "nil":
				g.r.config.Signers = nil
			case "empty":
				g.r.config.Signers = map[string]bool{}
			case "missing-publisher":
				g.r.config.PublisherKey = ""
			case "missing-agent-root":
				g.r.config.AgentRevocationRoot = ""
			case "aliased":
				g.r.config.AgentRevocationRoot = g.r.config.PublisherKey
			case "reserved-publisher":
				delete(g.r.config.Signers, g.r.config.PublisherKey)
				g.r.config.PublisherKey = MUOwnerRootSigner
				g.r.config.Signers[MUOwnerRootSigner] = true
			case "reserved-agent-root":
				delete(g.r.config.Signers, g.r.config.AgentRevocationRoot)
				g.r.config.AgentRevocationRoot = MUOwnerRootSigner
				g.r.config.Signers[MUOwnerRootSigner] = true
			case "extra":
				g.r.config.Signers["p256:foreign"] = true
			case "wrong-decision":
				g.v.publisher = "p256:foreign"
			}
			_, err := g.r.Handle(context.Background(), e)
			if mode == "valid" {
				if err != nil || g.calls.Load() != 1 {
					t.Fatal("valid pins refused", err, g.calls.Load())
				}
				return
			}
			if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatal("missing or invalid pins admitted state/effect", err, g.calls.Load())
			}
		})
	}
}

// Claim: every existing sidecar form refuses without writes; a fresh MU-only directory executes and creates no sidecar.
func TestLinuxStoreSidecarRefusal(t *testing.T) {
	for _, mode := range []string{"absent", "file", "directory", "dangling-symlink"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$sidecar")
			before := g.journal(t)
			path := filepath.Join(g.r.config.State.Directory, "linux-revocations.journal")
			var err error
			switch mode {
			case "file":
				err = os.WriteFile(path, []byte("retired state is not authority"), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "dangling-symlink":
				err = os.Symlink("missing", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = g.r.Handle(context.Background(), e)
			if mode == "absent" {
				if err != nil || g.calls.Load() != 1 {
					t.Fatal("MU-only positive refused", err, g.calls.Load())
				}
				if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("created sidecar", err)
				}
				return
			}
			if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatal("existing sidecar admitted state/effect", err, g.calls.Load())
			}
		})
	}
}

// Claim: foreign union-only and mark-only history or same-epoch pin rotation refuses unchanged; pinned history and owner-root unions reopen.
func TestLinuxStoreForeignHistory(t *testing.T) {
	for _, mode := range []string{"pinned-union", "pinned-mark", "owner-root", "foreign-union", "foreign-mark", "owner-root-mark", "rotation"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$history")
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			signer := g.v.publisher
			if strings.HasPrefix(mode, "foreign") {
				signer = "p256:foreign"
			}
			if strings.HasPrefix(mode, "owner-root") {
				signer = MUOwnerRootSigner
			}
			if strings.HasSuffix(mode, "mark") {
				err = s.markSnapshots(map[string]time.Time{signer: muNow})
			} else {
				err = s.absorbSigned(signer, []MURevocation{{"record", "sha256:unrelated"}})
			}
			s.close()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "pinned-union" {
				g.v.revocations = []MURevocation{{"record", "sha256:unrelated"}}
			}
			if mode == "rotation" {
				g.r.config.PublisherKey = "p256:rotated"
				g.r.config.Signers = map[string]bool{"p256:rotated": true, g.r.config.AgentRevocationRoot: true}
				g.v.publisher = "p256:rotated"
			}
			before := g.journal(t)
			_, err = g.r.Handle(context.Background(), e)
			negative := strings.HasPrefix(mode, "foreign") || mode == "owner-root-mark" || mode == "rotation"
			if negative {
				if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
					t.Fatal("foreign history admitted or pruned", err, g.calls.Load())
				}
			} else if err != nil || g.calls.Load() != 1 {
				t.Fatal("pinned/root history refused", err, g.calls.Load())
			}
		})
	}
}

// Claim: signer union frames precede eligible marks on disk, including on refusal; future observations persist a union without a mark.
func TestLinuxStoreUnionBeforeMark(t *testing.T) {
	for _, mode := range []string{"healthy", "future", "fail-after-union"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$order")
			entry := MURevocation{"record", "sha256:unrelated"}
			g.v.revocations = []MURevocation{entry}
			issued := muNow
			if mode == "future" {
				issued = muNow.Add(time.Second)
			}
			linuxSnapshotRig(g, &issued, nil)
			if mode == "fail-after-union" {
				g.r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
					s, err := openMUState(ctx, c, b)
					if err != nil {
						return nil, err
					}
					write := s.write
					n := 0
					s.write = func(f *os.File, raw []byte) (int, error) {
						n++
						if n == 2 {
							return 0, errors.New("injected mark write failure")
						}
						return write(f, raw)
					}
					return s, nil
				}
			}
			_, err := g.r.Handle(context.Background(), e)
			if mode == "healthy" {
				if err != nil || g.calls.Load() != 1 {
					t.Fatal(err, g.calls.Load())
				}
			} else if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
				t.Fatal("failed/future observation executed", err, g.calls.Load())
			}
			// The fake future candidate is deliberately invalid; exercise its authenticated refusal observation port.
			if mode == "future" {
				g.v.refusal = ErrMURevoked
				_, err = g.r.Handle(context.Background(), e)
				if !errors.Is(err, ErrMURevoked) {
					t.Fatal(err)
				}
			}
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if !s.unions[g.v.publisher][entry] || !s.revoked[entry] {
				t.Fatal("union not durable before mark", s.unions)
			}
			_, marked := s.highWater[g.v.publisher]
			if marked != (mode == "healthy") {
				t.Fatal("unsupported mark after future/failure", s.highWater)
			}
			rd := bytes.NewReader(g.journal(t))
			link := journalFrameLink{sequence: 1, epoch: g.r.config.State.Epoch}
			unionSeen := false
			for {
				f, err := readJournalFrame(rd, link)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if f.kind == journalSignerRevocation {
					unionSeen = true
				}
				if f.kind == journalSnapshotMark && !unionSeen {
					t.Fatal("mark precedes signer union on disk")
				}
				link.sequence++
				link.previous = f.digest
			}
			if len(s.reservations) != int(g.calls.Load()) {
				t.Fatal("refusal reserved", len(s.reservations), g.calls.Load())
			}
		})
	}
}

// Claim: global-only legacy holds remain unattributed and block the target; unrelated requests do not acquire signer completeness duties.
func TestLinuxStoreLegacyHolds(t *testing.T) {
	for _, target := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrelated", true: "target"}[target], func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$legacy")
			entry := MURevocation{"record", "sha256:unrelated"}
			if target {
				entry.ID = g.v.grant
			}
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			err = s.absorbRevocations([]MURevocation{entry})
			s.close()
			if err != nil {
				t.Fatal(err)
			}
			_, err = g.r.Handle(context.Background(), e)
			if target {
				if !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
					t.Fatal(err, g.calls.Load())
				}
			} else if err != nil || g.calls.Load() != 1 {
				t.Fatal(err, g.calls.Load())
			}
			s, err = openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if !s.revoked[entry] {
				t.Fatal("lost legacy hold")
			}
			for _, union := range s.unions {
				if union[entry] {
					t.Fatal("invented legacy attribution")
				}
			}
		})
	}
}

// Claim: the canonical roster covers every known ID and refuses an unknown case witness without changing the canonical corpus.
func TestLinuxCaseCoverageGuard(t *testing.T) {
	for _, c := range loadLinuxInterop(t) {
		if !linuxCaseCovered(c.ID) {
			t.Fatal("known case unclassified", c.ID)
		}
	}
	raw, err := os.ReadFile("testdata/linux-coverage/unknown.json")
	if err != nil {
		t.Fatal(err)
	}
	var witness struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &witness); err != nil {
		t.Fatal(err)
	}
	if witness.ID == "" {
		t.Fatal("missing unknown-case witness")
	}
	if linuxCaseCovered(witness.ID) {
		t.Fatal("unknown case admitted by coverage guard", witness.ID)
	}
}

// Claim: overlapping global holds gain both signer attributions, and each signer must retain its own union without mirroring the peer.
func TestLinuxStoreOverlappingSigners(t *testing.T) {
	g := newLinuxRig(t)
	issued := muNow
	entry := MURevocation{"record", "sha256:overlap"}
	other := MURevocation{"record", "sha256:only-agent-root"}
	g.v.revocations = []MURevocation{entry}
	extra := LinuxVerifiedSnapshot{Signer: g.r.config.AgentRevocationRoot, IssuedAt: issued, Entries: []MURevocation{entry, other}}
	linuxSnapshotRig(g, &issued, &extra)
	if _, err := g.r.Handle(context.Background(), g.event(t, "$overlap")); err != nil || g.calls.Load() != 1 {
		t.Fatal("independent positive", err, g.calls.Load())
	}
	g.reopen()
	linuxSnapshotRig(g, &issued, &extra)
	extra.Entries = nil
	if _, err := g.r.Handle(context.Background(), g.event(t, "$drop")); !errors.Is(err, ErrMURollback) || g.calls.Load() != 1 {
		t.Fatal("overlap lost second attribution", err, g.calls.Load())
	}
	s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !s.unions[g.v.publisher][entry] || !s.unions[extra.Signer][entry] || !s.unions[extra.Signer][other] || s.unions[g.v.publisher][other] {
		t.Fatal("signer attribution merged or missing", s.unions)
	}
}

// Claim: a shared write failure after healthy A leaves its union and mark durable, holds any complete B prefix, and refuses before reservation; successful retry completes admission.
func TestLinuxStorePeerWriteFailure(t *testing.T) {
	for _, failAt := range []int{0, 3, 4} {
		t.Run(fmt.Sprintf("write-%d", failAt), func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			a := MURevocation{"record", "sha256:" + strings.Repeat("a", 64)}
			b := MURevocation{"record", "sha256:" + strings.Repeat("b", 64)}
			for signer, entry := range map[string]MURevocation{d.revokerID: a, d.pub.id: b} {
				d.snapshot(signer, d.now, []any{map[string]any{"kind": entry.Kind, "id": entry.ID, "from": d.now.Format(time.RFC3339)}})
			}
			r := g.receiver()
			r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, c, b)
				if err != nil {
					return nil, err
				}
				write := s.write
				n := 0
				s.write = func(f *os.File, raw []byte) (int, error) {
					n++
					if n == failAt {
						return 0, errors.New("injected peer observation write failure")
					}
					return write(f, raw)
				}
				return s, nil
			}
			_, err := r.Handle(context.Background(), d.event)
			if failAt == 0 {
				if err != nil || g.calls != 1 {
					t.Fatal("successful writes refused", err, g.calls)
				}
			} else if !errors.Is(err, ErrMUState) || g.calls != 0 {
				t.Fatal("write failure executed", err, g.calls)
			}
			s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			if !s.unions[d.revokerID][a] || !s.highWater[d.revokerID].Equal(d.now) {
				t.Fatal("healthy A lost after storage failure")
			}
			if s.unions[d.pub.id][b] != (failAt != 3) {
				t.Fatal("wrong B union prefix", s.unions[d.pub.id])
			}
			_, marked := s.highWater[d.pub.id]
			if marked != (failAt == 0) {
				t.Fatal("unsupported B mark", s.highWater)
			}
			if len(s.reservations) != g.calls {
				t.Fatal("failure reserved or effect not held")
			}
			s.close()
			err = g.handle()
			if failAt == 0 {
				if !errors.Is(err, ErrMUNonceHeld) || g.calls != 1 {
					t.Fatal(err, g.calls)
				}
			} else if err != nil || g.calls != 1 {
				t.Fatal("reopen retry lost complete history", err, g.calls)
			}
		})
	}
}

// Claim: owner-root grant, author and publisher holds revoke without publisher mirroring, while empty/unrelated roots pass and missing/error roots refuse.
func TestLinuxStoreOwnerRoots(t *testing.T) {
	for _, mode := range []string{"empty", "unrelated", "grant", "author", "publisher", "missing", "error"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$root")
			body, _ := muMessageBody(e.Envelope)
			entry := MURevocation{"record", "sha256:unrelated"}
			switch mode {
			case "grant":
				entry.ID = g.v.grant
			case "author":
				entry = MURevocation{"key", body["author"].(string)}
			case "publisher":
				entry = MURevocation{"key", g.v.publisher}
			}
			g.r.config.RootRevocations = func() ([]MURevocation, error) {
				if mode == "error" {
					return nil, ErrMUState
				}
				if mode == "empty" {
					return nil, nil
				}
				return []MURevocation{entry}, nil
			}
			if mode == "missing" {
				g.r.config.RootRevocations = nil
			}
			_, err := g.r.Handle(context.Background(), e)
			switch mode {
			case "empty", "unrelated":
				if err != nil || g.calls.Load() != 1 {
					t.Fatal("independent root positive refused", err, g.calls.Load())
				}
			case "missing", "error":
				if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
					t.Fatal(err, g.calls.Load())
				}
			default:
				if !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
					t.Fatal(err, g.calls.Load())
				}
			}
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			for signer, union := range s.unions {
				if signer != MUOwnerRootSigner && union[entry] {
					t.Fatal("owner-root leaked into snapshot union")
				}
			}
			if mode != "empty" && mode != "missing" && mode != "error" && !s.unions[MUOwnerRootSigner][entry] {
				t.Fatal("owner-root lost on reopen")
			}
			if _, exists := s.highWater[MUOwnerRootSigner]; exists {
				t.Fatal("owner-root acquired a snapshot mark")
			}
		})
	}
}

// Claim: corrupted, unsupported, foreign-binding and exhausted MU state refuses unchanged before effects; intact matching bounded state admits.
func TestLinuxStoreJournalAdmission(t *testing.T) {
	for _, mode := range []string{"intact", "wrong-binding", "wrong-epoch", "unknown-kind", "unknown-body", "unknown-version", "torn", "capacity", "capacity-fit"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$journal")
			switch mode {
			case "wrong-binding":
				g.r.config.Binding.Audience = "other-audience"
			case "wrong-epoch":
				g.r.config.State.Epoch[0] ^= 1
			case "unknown-kind", "unknown-body", "unknown-version", "torn":
				path := filepath.Join(g.r.config.State.Directory, "mu.journal")
				raw := g.journal(t)
				if mode == "unknown-kind" {
					raw[10] = 255
				}
				if mode == "unknown-version" {
					raw[9] = 2
				}
				if mode == "unknown-body" {
					raw[journalHeaderBytes] = 'X'
				}
				if mode == "torn" {
					raw = append(raw, []byte("partial frame")...)
				} else {
					sum := sha256.Sum256(raw[:len(raw)-journalTrailerBytes])
					copy(raw[len(raw)-journalTrailerBytes:], sum[:])
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "capacity", "capacity-fit":
				s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
				if err != nil {
					t.Fatal(err)
				}
				count := muMaxRevocations
				if mode == "capacity-fit" {
					count--
				}
				entries := make([]MURevocation, count)
				for i := range entries {
					entries[i] = MURevocation{"record", fmt.Sprintf("sha256:%064x", i)}
				}
				err = s.absorbSigned(MUOwnerRootSigner, entries)
				s.close()
				if err != nil {
					t.Fatal(err)
				}
				g.v.revocations = []MURevocation{{"record", "sha256:" + strings.Repeat("f", 64)}}
			}
			before := g.journal(t)
			_, err := g.r.Handle(context.Background(), e)
			if mode == "intact" || mode == "capacity-fit" {
				if err != nil || g.calls.Load() != 1 {
					t.Fatal("intact bounded positive refused", err, g.calls.Load())
				}
			} else if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatal("invalid state admitted, repaired or executed", err, g.calls.Load())
			}
		})
	}
}

// Claim: each signer's authenticated future union survives refusal without a future mark; present-time complete history permits an unrelated request and still revokes its target.
func TestLinuxStoreFutureSnapshots(t *testing.T) {
	for _, role := range []string{"publisher", "registry"} {
		for _, target := range []string{"unrelated", "author"} {
			t.Run(role+"/"+target, func(t *testing.T) {
				g := newLinuxCombinedRig(t)
				d := g.dock
				signer := d.pub.id
				if role == "registry" {
					signer = d.revokerID
				}
				entry := MURevocation{"record", "sha256:" + strings.Repeat("1", 64)}
				if target == "author" {
					entry = MURevocation{"key", d.agentID}
				}
				entries := []any{map[string]any{"kind": entry.Kind, "id": entry.ID, "from": d.now.Format(time.RFC3339)}}
				d.snapshot(signer, d.now.Add(time.Second), entries)
				if err := g.handle(); err == nil || g.calls != 0 {
					t.Fatal("future snapshot executed", err, g.calls)
				}
				s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
				if err != nil {
					t.Fatal(err)
				}
				_, marked := s.highWater[signer]
				if marked || !s.unions[signer][entry] || !s.revoked[entry] || len(s.reservations) != 0 {
					t.Fatal("future union/mark custody", s.highWater, s.unions)
				}
				s.close()
				d.snapshot(signer, d.now, nil)
				want := ErrMURollback
				if target == "author" {
					want = ErrMURevoked
				}
				if err := g.handle(); !errors.Is(err, want) || g.calls != 0 {
					t.Fatal("future union omission passed", err, want, g.calls)
				}
				d.snapshot(signer, d.now, entries)
				err = g.handle()
				if target == "unrelated" {
					if err != nil || g.calls != 1 {
						t.Fatal("present complete positive refused", err, g.calls)
					}
				} else if err == nil || g.calls != 0 {
					t.Fatal("held target executed", err, g.calls)
				}
				s, err = openMUState(context.Background(), g.config.State, g.config.Binding)
				if err != nil {
					t.Fatal(err)
				}
				defer s.close()
				if !s.highWater[signer].Equal(d.now) {
					t.Fatal("nonfuture mark not established", s.highWater)
				}
			})
		}
	}
}
