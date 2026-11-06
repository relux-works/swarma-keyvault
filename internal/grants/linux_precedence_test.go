package grants

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// Claim: a request refused by owner scope (step 8) still records the
// publisher snapshot that revokes its grant (section 2.4): the scope refusal
// wins, no effect runs, and the journal holds the revoking entry. Control: the
// same request in scope then refuses as revoked.
func TestLinuxReceiverScopeRefusalRecordsRevocation(t *testing.T) {
	g := newLinuxRig(t)
	issued := muNow
	entry := MURevocation{"record", g.v.grant}
	g.v.revocations = []MURevocation{entry}
	linuxSnapshotRig(g, &issued, nil)
	g.r.config.Modules = map[string]bool{"other-module": true}
	if _, err := g.r.Handle(context.Background(), g.event(t, "$scope")); !errors.Is(err, ErrMUScope) || g.calls.Load() != 0 {
		t.Fatal("scope refusal did not take precedence", err, g.calls.Load())
	}
	s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	recorded := s.unions[g.v.publisher][entry]
	s.close()
	if !recorded {
		t.Fatal("revoking snapshot not recorded before the scope refusal")
	}
	g.r.config.Modules = map[string]bool{"swarma-keyvault": true}
	if _, err := g.r.Handle(context.Background(), g.event(t, "$in-scope")); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
		t.Fatal("in-scope control not revoked", err, g.calls.Load())
	}
}

// Claim: a decision for a grant-authority action refuses with
// mu-request-widens-authority, not the generic action-target refusal, for each
// of the four actions; no effect runs. Control: the unchanged request admits.
// Limit: the verifier here is the synthetic adapter; a real verifier refuses
// these actions earlier.
func TestLinuxReceiverWideningReachable(t *testing.T) {
	for _, action := range []string{"", "grant.issue", "grant.widen", "grant.delegate", "attestation.issue"} {
		t.Run("action="+action, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$widen")
			if action != "" {
				from := []byte(`"action":"work.assign"`)
				if bytes.Count(e.Envelope, from) != 1 {
					t.Fatal("setup: envelope does not carry one work.assign action")
				}
				e.Envelope = bytes.Replace(e.Envelope, from, []byte(`"action":"`+action+`"`), 1)
			}
			_, err := g.r.Handle(context.Background(), e)
			if action == "" {
				if err != nil || g.calls.Load() != 1 {
					t.Fatal("control refused", err, g.calls.Load())
				}
				return
			}
			if !errors.Is(err, ErrMUWidening) || g.calls.Load() != 0 {
				t.Fatalf("got %v with %d effects, want %v", err, g.calls.Load(), ErrMUWidening)
			}
		})
	}
}

// Claim: at the final verification under the lock, the step-8 checks still
// take precedence over step 9, and a step-9 refusal found only there is
// returned: a pause and a root revocation that both appear between the two
// samples refuse as paused; a root revocation alone refuses as revoked; a
// rollback alone refuses as rollback. No case runs an effect. Control: the
// same request with unchanged samples admits once.
func TestLinuxReceiverFinalPassPrecedence(t *testing.T) {
	for _, mode := range []string{"control", "pause-and-root-revocation", "root-revocation", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			first, older := muNow, muNow.Add(-time.Second)
			admissions := 0
			g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, n time.Time) (LinuxAdmission, error) {
				admissions++
				issued := first
				if mode == "rollback" && admissions == 2 {
					issued = older
				}
				d, err := g.v.VerifyProjected(e, n)
				return LinuxAdmission{Decision: d, Snapshots: []LinuxVerifiedSnapshot{{Signer: g.v.publisher, IssuedAt: issued}}}, err
			})
			samples := 0
			g.r.config.RootRevocations = func() ([]MURevocation, error) {
				samples++
				if samples < 2 || mode == "control" || mode == "rollback" {
					return nil, nil
				}
				if mode == "pause-and-root-revocation" {
					g.r.config.Paused[g.v.grant] = true
				}
				return []MURevocation{{"record", g.v.grant}}, nil
			}
			_, err := g.r.Handle(context.Background(), g.event(t, "$final"))
			if admissions != 2 || samples != 2 {
				t.Fatalf("setup: %d admissions, %d root samples, want 2 each", admissions, samples)
			}
			want := map[string]error{"control": nil, "pause-and-root-revocation": ErrMUPaused, "root-revocation": ErrMURevoked, "rollback": ErrMURollback}[mode]
			calls := map[bool]int32{true: 1, false: 0}[want == nil]
			if !errors.Is(err, want) || (want == nil && err != nil) || g.calls.Load() != calls {
				t.Fatalf("got %v with %d effects, want %v with %d", err, g.calls.Load(), want, calls)
			}
		})
	}
}

// Claim: when the grant is already known revoked, the request refuses as
// revoked and still records the publisher snapshot that came with it
// (section 2.4), although continuity admission is not reached.
func TestLinuxReceiverKnownRevocationRecordsSnapshot(t *testing.T) {
	g := newLinuxRig(t)
	issued := muNow
	entry := MURevocation{"record", "sha256:recorded-while-revoked"}
	g.v.revocations = []MURevocation{entry}
	linuxSnapshotRig(g, &issued, nil)
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{{"record", g.v.grant}}, nil }
	if _, err := g.r.Handle(context.Background(), g.event(t, "$known")); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
		t.Fatal("known revocation not refused", err, g.calls.Load())
	}
	s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !s.unions[g.v.publisher][entry] {
		t.Fatal("snapshot not recorded on the known-revocation path", s.unions)
	}
}

// Claim: a paused grant refuses as paused even when the decision names a
// grant-authority action, because the contract orders pause before widening;
// no effect runs. Control: the same widening decision unpaused refuses as
// widening (TestLinuxReceiverWideningReachable).
func TestLinuxReceiverPauseBeforeWidening(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$paused-widen")
	from := []byte(`"action":"work.assign"`)
	if bytes.Count(e.Envelope, from) != 1 {
		t.Fatal("setup: envelope does not carry one work.assign action")
	}
	e.Envelope = bytes.Replace(e.Envelope, from, []byte(`"action":"grant.issue"`), 1)
	g.r.config.Paused[g.v.grant] = true
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUPaused) || g.calls.Load() != 0 {
		t.Fatalf("got %v with %d effects, want %v", err, g.calls.Load(), ErrMUPaused)
	}
}
