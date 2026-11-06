package grants

import (
	"bytes"
	"context"
	"errors"
	"testing"
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
