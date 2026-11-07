package grants

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
)

// These signed A1-minimum records exercise the existing platform grant-scope
// Authorize path. They do not change the production issuer's A2 minimum or
// manufacture future-request human assurance. Keys are ephemeral in-memory lab
// keys from the existing dock, never an installed owner root or a live grant.
func linuxContractScope(g *linuxVerifierDock, use string) {
	g.grantBody["min_assurance"] = map[string]any{"level": "A1", "presence": false}
	g.grantBody["caveats"].(map[string]any)["use"] = use
	g.config.Grants = [][]byte{g.signRoot(g.grantBody)}
	g.fake.state.Assurance = linuxVerifierAssurance(g.t, "A1")
}

func TestLinuxContractOnceScope(t *testing.T) {
	for _, shape := range []string{"single", "actions", "targets", "both", "empty-actions", "empty-targets", "malformed-actions", "malformed-targets", "duplicate-actions", "duplicate-targets"} {
		for _, use := range []string{"once", "until_expiry"} {
			t.Run(shape+"/"+use, func(t *testing.T) {
				g := newLinuxCombinedRig(t)
				d := g.dock
				linuxContractScope(d, use)
				switch shape {
				case "actions", "both":
					d.grantBody["actions"] = []any{"work.assign", "work.require"}
				case "empty-actions":
					d.grantBody["actions"] = []any{}
				case "malformed-actions":
					d.grantBody["actions"] = "work.assign"
				case "duplicate-actions":
					d.grantBody["actions"] = []any{"work.assign", "work.assign"}
				}
				switch shape {
				case "targets", "both":
					d.grantBody["targets"] = []any{map[string]any{"kind": "product", "id": "swarma-platform"}, map[string]any{"kind": "product", "id": "another-product"}}
				case "empty-targets":
					d.grantBody["targets"] = []any{}
				case "malformed-targets":
					d.grantBody["targets"] = "swarma-platform"
				case "duplicate-targets":
					target := map[string]any{"kind": "product", "id": "swarma-platform"}
					d.grantBody["targets"] = []any{target, target}
				}
				d.config.Grants = [][]byte{d.signRoot(d.grantBody)}
				err := g.handle()
				valid := shape == "single" || use == "until_expiry" && (shape == "actions" || shape == "targets" || shape == "both")
				if valid {
					if err != nil || g.calls != 1 {
						t.Fatal("valid grant-scope control refused", err, g.calls)
					}
				} else {
					if err == nil || g.calls != 0 {
						t.Fatal("invalid grant scope dispatched", err, g.calls)
					}
					linuxContractNoUse(t, g)
				}
			})
		}
	}
}

func linuxContractNoUse(t *testing.T, g *linuxCombinedRig) {
	t.Helper()
	s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if len(s.reservations) != 0 || len(s.nonces) != 0 || len(s.allowances) != 0 {
		t.Fatal("refused request consumed use or nonce")
	}
}

// A2 remains an independent requirement. A valid signed grant does not supply
// it; A1 refuses A2, absence stays unavailable, and asserted A3 is not admitted.
func TestLinuxContractNoAssuranceFromGrant(t *testing.T) {
	for _, level := range []string{"A1", "missing", "A3"} {
		t.Run(level, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			want := "grant_assurance_insufficient"
			if level == "missing" {
				d.fake.state.Assurance = verifier.Evidence{}
				want = "grant_assurance_unavailable"
			} else {
				d.fake.state.Assurance = linuxVerifierAssurance(t, level)
				if level == "A3" {
					want = "grant_assurance_unavailable"
				}
			}
			if err := g.handle(); linuxVerifierCode(err) != want || g.calls != 0 {
				t.Fatal("grant manufactured human assurance", err, g.calls)
			}
			linuxContractNoUse(t, g)
			// Repair only the signed minimum to a grant-scope A1 lab record;
			// no request human signature is invented by this positive control.
			linuxContractScope(d, "until_expiry")
			if err := g.handle(); err != nil || g.calls != 1 {
				t.Fatal("grant-scope control refused", err, g.calls)
			}
		})
	}
}

func TestLinuxContractOnceAtomicConcurrent(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	linuxContractScope(d, "once")
	// The receiver's existing journal lock serializes both real verifier
	// invocations and both effects; no producer fixture is shared unlocked.
	r := g.receiver()
	e := linuxCloneEvent(d.event)
	other := linuxCloneEvent(e)
	body, err := muMessageBody(other.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte("another-nonce-16"))
	other.Envelope = linuxVerifierSign(t, d.agentID, d.agent, body)
	other.EventID = "$other-request"
	done := make(chan error, 2)
	for _, event := range []MUEnvelopeEvent{e, other} {
		go func(event MUEnvelopeEvent) {
			_, err := r.Handle(context.Background(), event)
			done <- err
		}(event)
	}
	a, b := <-done, <-done
	if !((a == nil && errors.Is(b, ErrMUUseHeld)) || (b == nil && errors.Is(a, ErrMUUseHeld))) || g.calls != 1 {
		t.Fatal("concurrent once effects", a, b, g.calls)
	}
	if err := g.handle(); !errors.Is(err, ErrMUUseHeld) || g.calls != 1 {
		t.Fatal("reopen refilled once grant", err, g.calls)
	}
}

// The bounds precede the adapter's copy and the verifier's evidence allocation.
// A complete over-limit history refuses, with no truncation or use consumed.
func TestLinuxContractStateBounds(t *testing.T) {
	for _, mode := range []string{"bindings-at", "bindings-over", "bytes-at", "bytes-over", "envelope-over"} {
		t.Run(mode, func(t *testing.T) {
			d := newLinuxVerifierDock(t)
			journal := map[string][]byte{}
			valid := mode == "bindings-at" || mode == "bytes-at"
			switch mode {
			case "bindings-at", "bindings-over":
				n := 4096
				if !valid {
					n++
				}
				for i := 0; i < n; i++ {
					journal[fmt.Sprintf("id-%04d", i)] = nil
				}
			case "bytes-at", "bytes-over":
				// Exactly the pinned Evidence cost, including map/key overhead.
				journal[strings.Repeat("x", (1<<20)-32)] = nil
				if !valid {
					journal["over"] = nil
				}
			case "envelope-over":
				journal["id"] = make([]byte, 65537)
			}
			d.fake.state.IDJournal = journal
			s := linuxApplicationTestSource(t, linuxApplicationTestBindings(d))
			state, err := s.VerificationState([32]byte{})
			if valid {
				if err != nil || len(state.IDJournal) != len(journal) {
					t.Fatal("at-limit complete history refused", err)
				}
			} else if !errors.Is(err, ErrMUState) || state.IDJournal != nil || !state.Now.IsZero() {
				t.Fatal("over-limit partial state returned", err)
			}
			if len(d.fake.state.IDJournal) != len(journal) {
				t.Fatal("source history evicted")
			}
		})
	}
}

func TestLinuxContractGrantInterval(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, 0, time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			linuxContractScope(d, "once")
			expires := d.now.Add(offset).Format(time.RFC3339)
			d.grantBody["exp"], d.grantBody["expires"] = expires, expires
			d.grantBody["caveats"].(map[string]any)["expires"] = expires
			d.config.Grants = [][]byte{d.signRoot(d.grantBody)}
			err := g.handle()
			if offset > 0 {
				if err != nil || g.calls != 1 {
					t.Fatal("unexpired control refused", err)
				}
			} else {
				if linuxVerifierCode(err) != "expired" || g.calls != 0 {
					t.Fatal("expiry widened", err, g.calls)
				}
				linuxContractNoUse(t, g)
			}
		})
	}
}

// A failed/lost effect reply holds the entire once allowance durably. Repairing
// the effect and using a fresh nonce cannot refund or replay that unknown use.
func TestLinuxContractOnceUnknown(t *testing.T) {
	g := newLinuxCombinedRig(t)
	linuxContractScope(g.dock, "once")
	r := g.receiver()
	r.effects["work.assign"] = linuxEffectFunc(func(context.Context, MUDecision) ([]byte, error) {
		g.calls++
		return nil, errors.New("lab lost effect reply")
	})
	out, err := r.Handle(context.Background(), g.dock.event)
	if !errors.Is(err, ErrMUUnknown) || out == nil || out.State != "unknown" || g.calls != 1 {
		t.Fatal("unknown effect did not hold use", err, g.calls)
	}
	body, err := muMessageBody(g.dock.event.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte("another-nonce-16"))
	g.dock.event.Envelope = linuxVerifierSign(t, g.dock.agentID, g.dock.agent, body)
	if err := g.handle(); !errors.Is(err, ErrMUUseHeld) || g.calls != 1 {
		t.Fatal("unknown once grant refilled after reopen", err, g.calls)
	}
}

// An advisory success does not hide a change at final sampling. Refusals leave
// no use/nonce reservation, and repairing only the changed protected premise
// admits the identical request with all earlier journal observations retained.
func TestLinuxContractFinalInvalidation(t *testing.T) {
	for _, mode := range []string{"assurance-lost", "history-over-cap", "time-lost", "generation-changed", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			linuxContractScope(d, "once")
			b := linuxApplicationTestBindings(d)
			reads := 0
			b.VerificationState = func(hash [32]byte) (LinuxVerificationState, error) {
				reads++
				s, err := d.fake.VerificationState(hash)
				if reads == 2 {
					switch mode {
					case "assurance-lost":
						// The signed grant itself stays unchanged. Removing the
						// independent assurance cannot be repaired by its signature.
						s.Assurance = verifier.Evidence{}
					case "history-over-cap":
						s.IDJournal = map[string][]byte{}
						for i := 0; i < 4097; i++ {
							s.IDJournal[fmt.Sprint(i)] = nil
						}
					case "time-lost":
						return LinuxVerificationState{}, ErrMUState
					case "generation-changed":
						d.fake.agent.Generation = "changed-final"
					case "revoked":
						d.snapshot(d.pub.id, d.now, []any{map[string]any{"kind": "key", "id": d.agentID, "from": d.now.Add(-time.Second).Format(time.RFC3339)}})
					}
				}
				return s, err
			}
			source := linuxApplicationTestSource(t, b)
			v, err := NewLinuxVerifier(d.config, source, source, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := NewLinuxReceiver(g.config, v, fakeRegistry{keys: map[string]string{d.event.Sender: d.agentID}}, map[string]MUEffect{"work.assign": g.effect}, func() (time.Time, error) { return d.now, nil })
			out, err := r.Handle(context.Background(), d.event)
			if err == nil || out != nil || g.calls != 0 || reads != 2 {
				t.Fatal("final invalidation dispatched", err, g.calls, reads)
			}
			linuxContractNoUse(t, g)
			if mode == "revoked" {
				// The retained signed revocation is never undone by a repaired
				// callback. A later valid-looking old view must remain refused.
				d.snapshot(d.pub.id, d.now.Add(-5*time.Second), nil)
				source.bindings = linuxApplicationTestBindings(d)
				if _, err := r.Handle(context.Background(), d.event); err == nil || g.calls != 0 {
					t.Fatal("revocation rolled back", err)
				}
				return
			}
			d.fake.agent.Generation = "gen-1"
			source.bindings = linuxApplicationTestBindings(d)
			if _, err := r.Handle(context.Background(), d.event); err != nil || g.calls != 1 {
				t.Fatal("repaired premise refused", err, g.calls)
			}
		})
	}
}
