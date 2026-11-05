package grants

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// signedSnapshotBody signs an arbitrary revocation/1 body with k, so a test
// can present a snapshot whose signature is valid but whose shape is not.
func signedSnapshotBody(t *testing.T, k muKey, body map[string]any) []byte {
	t.Helper()
	raw, err := record.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := mugrant.PrepareFor("revocation/1", k.id, raw)
	if err != nil {
		t.Fatal(err)
	}
	return k.sign(t, p)
}

// Claim: pre-absorption admits a pinned signer's snapshot only when its body
// has the static shape the platform verifier enforces. A well-formed
// snapshot with a key entry and a record entry is admitted with both
// entries (positive control). Each listed defect in the body or in one
// entry, under a valid signature by the pinned key, makes the snapshot
// unverified, so it contributes neither entries nor a mark. Limit: this
// checks the shape gate in muVerifiedSnapshot; the receiver-level effect is
// witnessed by the interop vector M-P-incomplete-then-older.
func TestMUVerifiedSnapshotShape(t *testing.T) {
	pub, other := newMUKey(t), newMUKey(t)
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	recordID, err := record.ContentID("revocation/1", map[string]any{"type": "revocation/1"})
	if err != nil {
		t.Fatal(err)
	}
	from := "2026-11-05T11:00:00Z"
	p, err := mugrant.BuildSnapshot(pub.id, at, []mugrant.SnapshotEntry{{Kind: "key", ID: other.id, From: from}, {Kind: "record", ID: recordID, From: from}})
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(p.Body(), &base); err != nil {
		t.Fatal(err)
	}
	sn, err := muVerifiedSnapshot(pub.sign(t, p), pub.id)
	if err != nil || len(sn.Entries) != 2 || !sn.IssuedAt.Equal(at) {
		t.Fatal("well-formed snapshot refused", sn, err)
	}
	if _, err := muVerifiedSnapshot(signedSnapshotBody(t, pub, base), pub.id); err != nil {
		t.Fatal("re-signed copy of the well-formed body refused", err)
	}
	entry := func(m map[string]any, f func(map[string]any)) {
		list := m["entries"].([]any)
		e := list[0].(map[string]any)
		f(e)
	}
	mutations := map[string]func(map[string]any){
		"complete-false":   func(m map[string]any) { m["complete"] = false },
		"complete-string":  func(m map[string]any) { m["complete"] = "true" },
		"complete-missing": func(m map[string]any) { delete(m, "complete") },
		"extra-member":     func(m map[string]any) { m["note"] = "x" },
		"entries-object":   func(m map[string]any) { m["entries"] = map[string]any{} },
		"issued-at-offset": func(m map[string]any) { m["issued_at"] = "2026-11-05T12:00:00+00:00" },
		"issued-at-short":  func(m map[string]any) { m["issued_at"] = "2026-11-05T12:00Z" },
		"entry-extra":      func(m map[string]any) { entry(m, func(e map[string]any) { e["why"] = "x" }) },
		"entry-no-from":    func(m map[string]any) { entry(m, func(e map[string]any) { delete(e, "from") }) },
		"entry-bad-from":   func(m map[string]any) { entry(m, func(e map[string]any) { e["from"] = "2026-11-05 11:00:00Z" }) },
		"entry-bad-kind":   func(m map[string]any) { entry(m, func(e map[string]any) { e["kind"] = "grant" }) },
		"entry-bad-key-id": func(m map[string]any) { entry(m, func(e map[string]any) { e["id"] = "p256:not-a-key" }) },
		"entry-record-name": func(m map[string]any) {
			entry(m, func(e map[string]any) { e["kind"] = "record"; e["id"] = "grant-name" })
		},
		"entry-not-object": func(m map[string]any) { m["entries"] = []any{"x"} },
	}
	for name, mutate := range mutations {
		var body map[string]any
		if err := json.Unmarshal(p.Body(), &body); err != nil {
			t.Fatal(err)
		}
		mutate(body)
		if sn, err := muVerifiedSnapshot(signedSnapshotBody(t, pub, body), pub.id); err == nil {
			t.Error("malformed snapshot admitted", name, sn)
		}
	}
}
