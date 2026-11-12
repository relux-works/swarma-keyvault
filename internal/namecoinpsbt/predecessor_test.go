package namecoinpsbt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func preparedFixture(t *testing.T, mode, slot string) PublicAttempt {
	t.Helper()
	c := candidate(t, mode, slot)
	s := fixtureSelection(t, c)
	raw, _ := json.Marshal(c.snapshot.Request())
	a, err := PrepareAttempt(raw, fixture(t, mode, "account-pin.json"), s, time.Unix(int64(s.Policy.CreatedAt)+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func fixtureHistory(t *testing.T, mode string, count int) (*namecoinjournal.Anchor, [][]byte, []HistoryEntry) {
	t.Helper()
	first := preparedFixture(t, mode, "A")
	s := first.Selection()
	var pin [32]byte
	_, _ = hex.Decode(pin[:], []byte(s.AccountPinSHA256))
	material := publishedAccountMaterial(t)
	defer clear(material)
	anchor, err := namecoinjournal.NewInitialization(namecoinjournal.Binding{Group: s.Group, Account: s.Account, PublicPin: pin, Policy: s.Policy.Revision}, material)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(anchor.Clear)
	var records [][]byte
	var entries []HistoryEntry
	for i := 0; i < count; i++ {
		slot := string(byte('A' + i))
		a := preparedFixture(t, mode, slot)
		ledger, err := anchor.RestoreLedger(records)
		if err != nil {
			t.Fatal(err)
		}
		tr, err := ledger.DispatchBound(a.ID(), a.Outpoints(), a.Commitment())
		if err != nil {
			t.Fatal(err)
		}
		d, err := anchor.Append(tr.Body)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, d)
		seq, head, err := anchor.Head()
		if err != nil {
			t.Fatal(err)
		}

		frozen, err := os.ReadFile(filepath.Join("..", "namecoinwire", "testdata", mode, slot+"-result.json"))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := namecoinwire.DecodeResult(frozen)
		if err != nil {
			t.Fatal(err)
		}
		// Preserve the exact Core PSBT bytes claimed by the frozen reveal
		// manifest. A different valid map ordering has a different public hash.
		parsed.Receipt.JournalSequence = seq
		parsed.Receipt.JournalHeadSHA256 = hex.EncodeToString(head[:])
		review := a.ReviewDigest()
		parsed.Receipt.ReviewSHA256 = hex.EncodeToString(review[:])
		result, err := namecoinwire.EncodeResult(parsed)
		if err != nil {
			t.Fatal(err)
		}

		tr, err = tr.Ledger.Complete(a.ID(), result)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := anchor.Append(tr.Body)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, signed)
		entries = append(entries, HistoryEntry{Descriptor: a.Descriptor(), Result: result})
	}
	return anchor, records, entries
}

// Public Core A/B/C signatures plus the account-derived in-memory anchor admit
// each next phase for both release modes. This proves graph/history checks; it
// does not prove native persistence, fresh biometric presence or actual dispatch.
func TestProtectedPredecessorGraph(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for n, slot := range []string{"A", "B", "C", "D"} {
			a := preparedFixture(t, mode, slot)
			anchor, records, entries := fixtureHistory(t, mode, n)
			if err := a.VerifyPredecessors(anchor, records, entries); err != nil {
				t.Fatal(mode, slot, err)
			}
		}
	}
}

// The same valid D control rejects missing/extra/reordered cached predecessors,
// result-only promotion, modified descriptors/results, and an internally valid
// loaded anchor before actual account correspondence has been re-established.
func TestProtectedPredecessorRefusals(t *testing.T) {
	mode := "all-four-before-release"
	a := preparedFixture(t, mode, "D")
	anchor, records, entries := fixtureHistory(t, mode, 3)
	if err := a.VerifyPredecessors(anchor, records, entries); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func([]HistoryEntry) []HistoryEntry{
		func(e []HistoryEntry) []HistoryEntry { return e[:2] },
		func(e []HistoryEntry) []HistoryEntry { return append(e, e[0]) },
		func(e []HistoryEntry) []HistoryEntry { e[0], e[1] = e[1], e[0]; return e },
		func(e []HistoryEntry) []HistoryEntry { e[0].Descriptor[len(e[0].Descriptor)-1] ^= 1; return e },
		func(e []HistoryEntry) []HistoryEntry { e[1].Result = append(e[1].Result, ' '); return e },
	} {
		cloned := make([]HistoryEntry, len(entries))
		for i, e := range entries {
			cloned[i] = HistoryEntry{Descriptor: bytes.Clone(e.Descriptor), Result: bytes.Clone(e.Result)}
		}
		if err := a.VerifyPredecessors(anchor, records, edit(cloned)); err == nil {
			t.Fatal("bad predecessor admitted")
		}
	}
	requireCode(t, a.VerifyPredecessors(anchor, records[:len(records)-1], entries), namecoinwire.OutcomeUnknown)
	requireCode(t, a.VerifyPredecessors(nil, records, entries), namecoinwire.OutcomeUnknown)
	protected, err := anchor.EncodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	s := a.Selection()
	var pin [32]byte
	_, _ = hex.Decode(pin[:], []byte(s.AccountPinSHA256))
	loaded, err := namecoinjournal.DecodeProtected(protected, namecoinjournal.Binding{Group: s.Group, Account: s.Account, PublicPin: pin, Policy: s.Policy.Revision})
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	requireCode(t, a.VerifyPredecessors(loaded, records, entries), namecoinwire.OutcomeUnknown)
	material := publishedAccountMaterial(t)
	defer clear(material)
	if loaded.VerifyAccount(material) != nil || a.VerifyPredecessors(loaded, records, entries) != nil {
		t.Fatal("actual account correspondence positive control")
	}
}
