package grants

import (
	"errors"
	"testing"
	"time"
)

// Claim: a journal holding revocation frames in the format written before
// per-signer unions existed (kind 5, written here through absorbRevocations,
// whose encoding is unchanged) replays after a reopen. Its entries still
// revoke: a request whose grant is one of them refuses with ErrMURevoked.
// They carry no signer: no signer's union holds them, and a publisher
// snapshot that does not list them is not a rollback (positive control: the
// same request on an unrelated grant succeeds and records the publisher's
// own entries and mark). Limit: the legacy bytes come from the current
// writer of that frame kind, not from a journal file of an older build.
func TestMULegacyRevocationReplay(t *testing.T) {
	c, b := muFixture(t)
	legacyGrant := MURevocation{"record", "legacy-grant-id"}
	legacyKey := MURevocation{"key", "legacy-key-id"}
	s := muOpen(t, c, b)
	if err := s.absorbRevocations([]MURevocation{legacyGrant, legacyKey}); err != nil {
		t.Fatal(err)
	}
	s.close()

	s = muOpen(t, c, b)
	defer s.close()
	if !s.revoked[legacyGrant] || !s.revoked[legacyKey] {
		t.Fatal("legacy entries lost on replay", s.revoked)
	}
	for signer, u := range s.unions {
		if u[legacyGrant] || u[legacyKey] {
			t.Fatal("legacy entry attributed to a signer", signer)
		}
	}
	if len(s.highWater) != 0 {
		t.Fatal("legacy journal produced a mark", s.highWater)
	}

	r := &MUReceiver{}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	revoked := MUDecision{GrantID: legacyGrant.ID, Author: "p256:author", PublisherKey: "p256:publisher", SnapshotMarks: map[string]time.Time{"p256:publisher": at}}
	if err := r.revocations(s, revoked); !errors.Is(err, ErrMURevoked) {
		t.Fatal("legacy grant revocation not applied", err)
	}
	own := MURevocation{"record", "publisher-entry"}
	ok := MUDecision{GrantID: "current-grant-id", Author: "p256:author", PublisherKey: "p256:publisher", Revocations: []MURevocation{own}, SnapshotMarks: map[string]time.Time{"p256:publisher": at}}
	if err := r.revocations(s, ok); err != nil {
		t.Fatal("publisher snapshot without legacy entries judged a rollback", err)
	}
	if !s.unions["p256:publisher"][own] || !s.highWater["p256:publisher"].Equal(at) {
		t.Fatal("publisher entries or mark not recorded", s.unions, s.highWater)
	}
}
