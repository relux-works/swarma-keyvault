package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func muLegacyFixture(t *testing.T, flip bool) (MUStateConfig, MUBinding) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mu")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mu.journal", "mu.lock"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "mu-legacy-c0146d26", name))
		if err != nil {
			t.Fatal(err)
		}
		if flip && name == "mu.journal" {
			// Corrupt the final kind-5 frame's checksum, keeping all framing intact.
			raw[len(raw)-1] ^= 1
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("mu-legacy-c0146d26-test-epoch"))},
		MUBinding{Audience: "synthetic-mu-legacy-receiver", GrantRoot: "p256:synthetic-legacy-root"}
}

// Claim: actual c0146d26 writer bytes replay under the current code. Legacy
// record and key entries revoke without acquiring a signer or snapshot mark;
// a publisher can omit them. Both reserved nonces remain held after replay.
// This exercises local accounting, not envelope verification or Keychain.
func TestMULegacyC0146D26FixtureReplay(t *testing.T) {
	c, b := muLegacyFixture(t, false)
	raw, err := os.ReadFile(filepath.Join(c.Directory, "mu.journal"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "da363d7efd50da658578a30df608ed94d3e783480fffd63bc9c4e8d7774305fe" {
		t.Fatal("historical journal bytes changed")
	}
	// Pin the historical shape: activation, once and until_expiry reservations,
	// then two kind-5 frames. No current writer constructs these fixture bytes.
	reader := bytes.NewReader(raw)
	link := journalFrameLink{sequence: 1, epoch: c.Epoch}
	for _, kind := range []journalFrameKind{1, 2, 2, 5, 5} {
		f, err := readJournalFrame(reader, link)
		if err != nil || f.kind != kind {
			t.Fatalf("frame %d: want kind %d, got %v, error %v", link.sequence, kind, f, err)
		}
		link.sequence++
		link.previous = f.digest
	}
	if _, err := readJournalFrame(reader, link); err != io.EOF {
		t.Fatal("fixture has extra frames or trailing bytes", err)
	}
	s := muOpen(t, c, b)
	defer func() { s.close() }()
	legacyGrant := MURevocation{"record", "synthetic-revoked-grant"}
	legacyKey := MURevocation{"key", "p256:synthetic-revoked-key"}
	assertLegacy := func() {
		t.Helper()
		if !s.revoked[legacyGrant] || !s.revoked[legacyKey] {
			t.Fatal("historical revocations lost", s.revoked)
		}
		for signer, union := range s.unions {
			if union[legacyGrant] || union[legacyKey] {
				t.Fatal("historical revocation attributed to signer", signer)
			}
		}
	}
	assertLegacy()
	if len(s.revoked) != 2 || len(s.unions) != 0 || len(s.highWater) != 0 {
		t.Fatal("legacy state invented entries, signer unions or marks", s.revoked, s.unions, s.highWater)
	}
	if len(s.reservations) != 2 || len(s.nonces) != 2 || len(s.allowances) != 1 ||
		s.reservations[2] == nil || !s.reservations[2].once || s.reservations[3] == nil || s.reservations[3].once {
		t.Fatal("historical reservations lost or changed", s.reservations)
	}
	for _, nonce := range []string{"synthetic-nonce-1", "synthetic-nonce-2"} {
		u := MUUse{GrantRoot: b.GrantRoot, GrantID: "synthetic-reserved-grant",
			Action: "work.assign", TargetKind: "product", TargetID: "synthetic-product",
			Requester: "p256:synthetic-requester", Nonce: nonce, Audience: b.Audience,
			RequestHash: sha256.Sum256([]byte("synthetic-request/" + nonce))}
		if _, err := s.reserve(u); !errors.Is(err, ErrMUNonceHeld) {
			t.Fatal("historical nonce replay accepted", nonce, err)
		}
	}
	r := &MUReceiver{}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	ok := MUDecision{GrantID: "synthetic-current-grant", Author: "p256:synthetic-author", PublisherKey: "p256:synthetic-publisher",
		SnapshotMarks: map[string]time.Time{"p256:synthetic-publisher": at}}
	record, key := ok, ok
	record.GrantID = legacyGrant.ID
	key.Author = legacyKey.ID
	for name, d := range map[string]MUDecision{"record": record, "key": key} {
		if err := r.revocations(s, d); !errors.Is(err, ErrMURevoked) {
			t.Fatal("historical revocation did not refuse request", name, err)
		}
	}
	if len(s.highWater) != 0 || len(s.unions) != 0 {
		t.Fatal("refused requests raised a mark or union", s.highWater, s.unions)
	}
	own := MURevocation{"record", "synthetic-publisher-entry"}
	ok.Revocations = []MURevocation{own}
	if err := r.revocations(s, ok); err != nil {
		t.Fatal("publisher snapshot omitting historical entries refused", err)
	}
	if !s.unions[ok.PublisherKey][own] || len(s.highWater) != 1 || !s.highWater[ok.PublisherKey].Equal(at) {
		t.Fatal("accepted publisher snapshot did not record its own union and mark", s.unions, s.highWater)
	}
	assertLegacy()
	s.close()
	s = muOpen(t, c, b)
	assertLegacy()
	if err := r.revocations(s, ok); err != nil {
		t.Fatal("publisher snapshot omitting historical entries refused after reopen", err)
	}
}

func TestMULegacyC0146D26FixtureCorruption(t *testing.T) {
	c, b := muLegacyFixture(t, true)
	s, err := openMUState(context.Background(), c, b)
	if s != nil {
		s.close()
	}
	if !errors.Is(err, ErrMUState) {
		t.Fatal("fixture with one flipped byte opened", err)
	}
}
