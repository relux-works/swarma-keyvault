package grants

import (
	"context"
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

// Claim: a decision whose revocation publisher key is also its agent
// revocation key refuses before any state change: no root, union or mark
// entry is written. Positive control: the same decision with distinct keys
// is judged and records the publisher's mark.
func TestMURevocationsRefuseSharedSignerKey(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	defer s.close()
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	r := &MUReceiver{}
	shared := MUDecision{GrantID: "grant-id", Author: "p256:author", PublisherKey: "ed25519:shared", AgentRevocationKey: "ed25519:shared",
		SnapshotMarks: map[string]time.Time{"ed25519:shared": at}}
	if err := r.revocations(s, shared); !errors.Is(err, ErrMUState) {
		t.Fatal("shared publisher and agent revocation key admitted", err)
	}
	if len(s.unions) != 0 || len(s.highWater) != 0 || len(s.revoked) != 0 {
		t.Fatal("refusal changed state", s.unions, s.highWater, s.revoked)
	}
	distinct := shared
	distinct.AgentRevocationKey = "ed25519:agent-revocation"
	distinct.SnapshotMarks = map[string]time.Time{"ed25519:shared": at}
	if err := r.revocations(s, distinct); err != nil || !s.highWater["ed25519:shared"].Equal(at) {
		t.Fatal("distinct keys refused or mark not recorded", err, s.highWater)
	}
}

// Claim: a receiver pinned to one publisher refuses a journal that holds a
// union or mark from another snapshot signer (a publisher rotation without a
// new state epoch), and a decision naming a publisher it does not pin, before
// any state change. Positive controls: the pinned publisher is judged and
// records its mark beside owner-root entries, which are not a signer of the
// publisher's kind.
func TestMURevocationsRefuseUnpinnedSigner(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	defer s.close()
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if err := s.absorbSigned(MUOwnerRootSigner, []MURevocation{{"record", "root-revoked"}}); err != nil {
		t.Fatal(err)
	}
	pinned := &MUReceiver{config: MUReceiverConfig{Signers: map[string]bool{"p256:publisher": true}}}
	ok := MUDecision{GrantID: "grant-id", Author: "p256:author", PublisherKey: "p256:publisher", SnapshotMarks: map[string]time.Time{"p256:publisher": at}}
	if err := pinned.revocations(s, ok); err != nil || !s.highWater["p256:publisher"].Equal(at) {
		t.Fatal("pinned publisher refused", err)
	}
	unpinned := ok
	unpinned.PublisherKey = "ed25519:other"
	unpinned.SnapshotMarks = map[string]time.Time{"ed25519:other": at.Add(time.Second)}
	if err := pinned.revocations(s, unpinned); !errors.Is(err, ErrMUState) {
		t.Fatal("decision with an unpinned publisher admitted", err)
	}
	rotated := &MUReceiver{config: MUReceiverConfig{Signers: map[string]bool{"ed25519:new": true}}}
	next := ok
	next.PublisherKey = "ed25519:new"
	next.SnapshotMarks = map[string]time.Time{"ed25519:new": at.Add(time.Second)}
	unions, marks := len(s.unions), len(s.highWater)
	if err := rotated.revocations(s, next); !errors.Is(err, ErrMUState) {
		t.Fatal("journal of another publisher admitted after rotation", err)
	}
	if len(s.unions) != unions || len(s.highWater) != marks || s.unions["ed25519:new"] != nil {
		t.Fatal("refusal changed state", s.unions, s.highWater)
	}
}

// muSnapshotsOnly hands the receiver fixed verified snapshots; Verify is not
// reached in this test.
type muSnapshotsOnly struct{ snaps []MUSnapshot }

func (m muSnapshotsOnly) Verify(MUEvent, time.Time) (MUDecision, error) {
	return MUDecision{}, ErrMUState
}
func (m muSnapshotsOnly) VerifiedSnapshots(MUEvent) ([]MUSnapshot, error) { return m.snaps, nil }

// Claim: pre-verification recording writes nothing when two of the verified
// snapshots share one signer key (the publisher doubling as the agent
// revocation root); the decision refuses that pair, so no union or mark is
// left behind. Positive control: two distinct signers are both recorded.
func TestMUAbsorbSkipsSharedSignerKey(t *testing.T) {
	c, b := muFixture(t)
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	entry := []MURevocation{{"record", "revoked-id"}}
	run := func(snaps ...MUSnapshot) *muState {
		r := NewMUReceiver(MUReceiverConfig{State: c, Binding: b}, muSnapshotsOnly{snaps}, nil, nil)
		r.now = func() time.Time { return at.Add(time.Minute) }
		r.absorbSnapshots(context.Background(), MUEvent{})
		return muOpen(t, c, b)
	}
	s := run(MUSnapshot{Signer: "ed25519:shared", IssuedAt: at, Entries: entry}, MUSnapshot{Signer: "ed25519:shared", IssuedAt: at})
	if len(s.unions) != 0 || len(s.highWater) != 0 || len(s.revoked) != 0 {
		t.Fatal("shared signer key recorded", s.unions, s.highWater)
	}
	s.close()
	s = run(MUSnapshot{Signer: "ed25519:publisher", IssuedAt: at, Entries: entry}, MUSnapshot{Signer: "ed25519:agent-revocation", IssuedAt: at})
	defer s.close()
	if !s.unions["ed25519:publisher"][entry[0]] || !s.highWater["ed25519:agent-revocation"].Equal(at) {
		t.Fatal("distinct signers not recorded", s.unions, s.highWater)
	}
}
