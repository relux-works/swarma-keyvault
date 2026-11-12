package namecoinpsbt

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Native review source carries all parsed graph inputs/outputs, complete scripts,
// fees and exact semantic bytes alongside the same frozen commitment. This is
// public fact construction; actual window rendering/biometry is a separate lane.
func TestReviewDocumentMatchesOwnedCandidate(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			a := preparedFixture(t, mode, slot)
			raw, err := a.ReviewDocument()
			if err != nil {
				t.Fatal(err)
			}
			var doc ReviewDocument
			if json.Unmarshal(raw, &doc) != nil || !bytes.Equal(doc.ReviewFrame, a.ReviewFrame()) || doc.FeeAtoms != a.candidate.view.Fee || doc.Account != a.selected.Account {
				t.Fatal("review binding")
			}
			names, values, scripts := 0, 0, 0
			labels := map[string]bool{}
			for _, fact := range doc.Facts {
				if labels[fact.Label] {
					t.Fatal("duplicate labels")
				}
				labels[fact.Label] = true
				if fact.Kind == "semanticName" {
					names++
				}
				if fact.Kind == "semanticValue" {
					values++
				}
				if bytes.Contains([]byte(fact.Label), []byte("complete script")) {
					scripts++
				}
			}
			expectedValues := 1
			if slot == "C" || slot == "D" {
				expectedValues = 2
			}
			expectedScripts := 6
			if slot == "C" || slot == "D" {
				expectedScripts = 8
			}
			if names != 2 || values != expectedValues || scripts != expectedScripts {
				t.Fatal("incomplete semantic/transaction facts", names, values, scripts)
			}
		}
	}
}

// The exact semantic display helper admits empty/printable ASCII and rejects
// controls, DEL, high/bidi UTF-8 and malformed hex. This isolates display policy;
// the full Core fixture test above checks integration with immutable candidates.
func TestSemanticReviewByteBoundary(t *testing.T) {
	for _, encoded := range []string{"", "20", "7e", "692f66697874757265"} {
		if _, ok := semanticReviewBytes(encoded); !ok {
			t.Fatal("valid semantic text refused")
		}
	}
	for _, encoded := range []string{"0a", "e280ae", "7f", "00", "c3a9", "0", "gg"} {
		if raw, ok := semanticReviewBytes(encoded); ok || raw != nil {
			t.Fatal("forbidden semantic text admitted")
		}
	}
}
