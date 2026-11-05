package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func muFixture(t *testing.T) (MUStateConfig, MUBinding) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mu")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("mu-test-epoch"))}
	b := MUBinding{Audience: "swarma-keyvault-receiver", GrantRoot: "p256:root"}
	if err := InitializeMUState(c, b); err != nil {
		t.Fatal(err)
	}
	return c, b
}

func muUse(once bool, grant, nonce string) MUUse {
	return MUUse{Once: once, GrantRoot: "p256:root", GrantID: grant, Action: "work.assign", TargetKind: "product", TargetID: "swarma-platform",
		Requester: "p256:meta", Nonce: nonce, Audience: "swarma-keyvault-receiver", RequestHash: sha256.Sum256([]byte(grant + nonce))}
}

func muOpen(t *testing.T, c MUStateConfig, b MUBinding) *muState {
	t.Helper()
	s, err := openMUState(context.Background(), c, b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Claim: until_expiry accepts distinct nonces and refuses a repeated nonce,
// including after the journal is reopened (durable, not in-memory only).
func TestMUUntilExpiryNonces(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	for _, n := range []string{"n1", "n2", "n3"} {
		if _, err := s.reserve(muUse(false, "grant-A", n)); err != nil {
			t.Fatal("distinct nonce refused", n, err)
		}
	}
	if _, err := s.reserve(muUse(false, "grant-A", "n2")); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("replayed nonce accepted", err)
	}
	s.close()
	s = muOpen(t, c, b)
	defer s.close()
	if _, err := s.reserve(muUse(false, "grant-A", "n1")); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("replay after reopen accepted", err)
	}
	if _, err := s.reserve(muUse(false, "grant-A", "n4")); err != nil {
		t.Fatal("fresh nonce after reopen refused", err)
	}
}

// Claim: once consumes the right on the first use; a fresh nonce or a new
// request hash does not refill it; a new owner-signed grant id is a new right.
// The held allowance survives an UNKNOWN outcome (intent without outcome) and
// a reopen.
func TestMUOnceNoRefill(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	seq, err := s.reserve(muUse(true, "grant-O", "a1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.markIntent(seq); err != nil {
		t.Fatal(err)
	}
	refill := muUse(true, "grant-O", "a2")
	refill.RequestHash = sha256.Sum256([]byte("different request id"))
	if _, err := s.reserve(refill); !errors.Is(err, ErrMUUseHeld) {
		t.Fatal("once refilled by fresh nonce/request", err)
	}
	s.close()
	s = muOpen(t, c, b)
	defer s.close()
	if _, err := s.reserve(muUse(true, "grant-O", "a3")); !errors.Is(err, ErrMUUseHeld) {
		t.Fatal("unknown outcome released the once right", err)
	}
	if _, err := s.reserve(muUse(true, "grant-O2", "a4")); err != nil {
		t.Fatal("new grant id refused", err)
	}
	other := muUse(true, "grant-O", "a5")
	other.TargetID = "other-platform"
	if _, err := s.reserve(other); err != nil {
		t.Fatal("different target of the same once grant refused", err)
	}
}

// Claim: a nonce is single-use across policies and grants for one requester
// and audience, but the same nonce from another requester is a different key.
func TestMUNonceScope(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	defer s.close()
	if _, err := s.reserve(muUse(false, "grant-A", "shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserve(muUse(true, "grant-B", "shared")); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("nonce reused across policy/grant", err)
	}
	foreign := muUse(false, "grant-A", "shared")
	foreign.Requester = "p256:other"
	if _, err := s.reserve(foreign); err != nil {
		t.Fatal("other requester's nonce refused", err)
	}
}

// Claim: reservations bind the activated audience and grant root; outcome and
// intent order is enforced; a completed outcome replays.
func TestMUStateBindingAndOrder(t *testing.T) {
	c, b := muFixture(t)
	s := muOpen(t, c, b)
	wrongAud := muUse(false, "grant-A", "x1")
	wrongAud.Audience = "other-receiver"
	wrongRoot := muUse(false, "grant-A", "x2")
	wrongRoot.GrantRoot = "p256:other-root"
	for name, u := range map[string]MUUse{"audience": wrongAud, "root": wrongRoot} {
		if _, err := s.reserve(u); !errors.Is(err, ErrMUState) {
			t.Fatal("foreign binding reserved", name, err)
		}
	}
	seq, err := s.reserve(muUse(false, "grant-A", "x3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordOutcome(seq, []byte("receipt")); !errors.Is(err, ErrMUState) {
		t.Fatal("outcome without intent accepted", err)
	}
	if err := s.markIntent(seq); err != nil {
		t.Fatal(err)
	}
	if err := s.recordOutcome(seq, []byte("receipt")); err != nil {
		t.Fatal(err)
	}
	if err := s.recordOutcome(seq, []byte("again")); !errors.Is(err, ErrMUState) {
		t.Fatal("second outcome accepted", err)
	}
	s.close()
	s = muOpen(t, c, b)
	defer s.close()
	if r := s.reservations[seq]; r == nil || !r.intent || !r.complete {
		t.Fatal("completed reservation not replayed")
	}
}

// Claim: opening refuses a journal activated for another binding, a truncated
// journal, an absent journal and an uninitialized directory; initialization
// refuses a non-empty directory.
func TestMUStateOpenRefusals(t *testing.T) {
	c, b := muFixture(t)
	other := b
	other.Audience = "other-receiver"
	if _, err := openMUState(context.Background(), c, other); !errors.Is(err, ErrMUState) {
		t.Fatal("foreign activation opened", err)
	}
	if err := InitializeMUState(c, b); !errors.Is(err, ErrMUState) {
		t.Fatal("re-initialization accepted", err)
	}
	s := muOpen(t, c, b)
	if _, err := s.reserve(muUse(false, "grant-A", "t1")); err != nil {
		t.Fatal(err)
	}
	s.close()
	journal := filepath.Join(c.Directory, "mu.journal")
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openMUState(context.Background(), c, b); !errors.Is(err, ErrMUState) {
		t.Fatal("truncated journal opened", err)
	}
	if err := os.WriteFile(journal, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := openMUState(context.Background(), c, b); err != nil {
		t.Fatal("restored journal refused", err)
	} else {
		s.close()
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := openMUState(context.Background(), MUStateConfig{Directory: empty, Epoch: c.Epoch}, b); !errors.Is(err, ErrMUState) {
		t.Fatal("uninitialized directory opened", err)
	}
	if !bytes.HasPrefix(muActivation(b), []byte("MUA1")) {
		t.Fatal("activation tag")
	}
}
