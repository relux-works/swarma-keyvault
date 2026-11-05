package grants

import (
	"bytes"
	"errors"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

func muGrantRecord(t *testing.T, subject string, actions []any, targets []any, nonce string) []byte {
	t.Helper()
	raw, err := record.Canonical(map[string]any{"version": "swarm-envelope/2", "id": "sha256:" + nonce,
		"body":       map[string]any{"type": "grant/1", "subject": subject, "actions": actions, "targets": targets, "nonce": nonce},
		"signatures": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var muProductTarget = map[string]any{"kind": "product", "id": "swarma-platform"}

// Claim: the interim selection (subject == author plus exact action and target
// coverage) returns the single matching grant; two covering grants for the
// same author refuse as ambiguous instead of picking one; no covering grant
// refuses; a covering grant for another subject is never selected; and a
// malformed registry entry refuses instead of being skipped.
func TestMUSelectGrant(t *testing.T) {
	meta := muGrantRecord(t, "p256:meta", []any{"work.assign"}, []any{muProductTarget}, "a")
	other := muGrantRecord(t, "p256:other", []any{"work.assign"}, []any{muProductTarget}, "b")
	rooms := muGrantRecord(t, "p256:meta", []any{"room.membership"}, []any{map[string]any{"kind": "room-scope", "id": "swarma-space"}}, "c")
	got, err := muSelectGrant([][]byte{other, meta, rooms}, "p256:meta", "work.assign", "product", "swarma-platform")
	if err != nil || !bytes.Equal(got, meta) {
		t.Fatal("single covering grant not selected", err)
	}
	second := muGrantRecord(t, "p256:meta", []any{"work.accept", "work.assign"}, []any{muProductTarget}, "d")
	if _, err := muSelectGrant([][]byte{meta, second}, "p256:meta", "work.assign", "product", "swarma-platform"); !errors.Is(err, ErrMUAmbiguous) {
		t.Fatal("ambiguous selection not refused", err)
	}
	if _, err := muSelectGrant([][]byte{meta, second}, "p256:meta", "work.accept", "product", "swarma-platform"); err != nil {
		t.Fatal("unambiguous neighbour refused", err)
	}
	if _, err := muSelectGrant([][]byte{other, rooms}, "p256:meta", "work.assign", "product", "swarma-platform"); !errors.Is(err, ErrMUNoGrant) {
		t.Fatal("foreign subject grant selected", err)
	}
	if _, err := muSelectGrant([][]byte{meta}, "p256:meta", "work.assign", "product", "other-platform"); !errors.Is(err, ErrMUNoGrant) {
		t.Fatal("uncovered target selected", err)
	}
	if _, err := muSelectGrant([][]byte{meta, []byte("{not json")}, "p256:meta", "work.assign", "product", "swarma-platform"); !errors.Is(err, ErrMUState) {
		t.Fatal("malformed registry entry skipped", err)
	}
}
