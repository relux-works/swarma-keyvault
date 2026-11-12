package namecoinpsbt

import (
	"bytes"
	"encoding/hex"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// HistoryEntry contains only public cached bytes. Neither a result nor its
// descriptor is trusted until verified against the current account-rederived
// protected anchor and exact complete physical/typed history below.
type HistoryEntry struct{ Descriptor, Result []byte }

// VerifyPredecessors requires exactly the completed predecessors for this slot,
// checks both public signatures and protected D/S membership, and binds their
// actual graph/policy to this candidate. Hold the same storage gate throughout
// collection, verification and private dispatch. No cache scan or caller-supplied
// "approved" flag establishes predecessor authority.
func (a PublicAttempt) VerifyPredecessors(anchor *namecoinjournal.Anchor, records [][]byte, entries []HistoryEntry) error {
	r, p := a.candidate.snapshot.Request(), a.candidate.snapshot.Plan()
	needed := 0
	switch r.Slot {
	case "A":
		needed = 0
	case "B":
		needed = 1
	case "C":
		needed = 2
	case "D":
		needed = 3
	default:
		return failure(namecoinwire.InvalidRequest)
	}
	if len(entries) != needed {
		return failure(namecoinwire.IntentMismatch)
	}
	if needed == 0 {
		return nil
	} // Initial dispatch still requires private-engine account/journal admission.
	reservationHash := r.ReservationPlanSHA256
	parents := make(map[string]PublicAttempt, needed)
	receipts := make(map[string]namecoinwire.Receipt, needed)
	for i, entry := range entries {
		parent, err := DecodeAttempt(entry.Descriptor)
		if err != nil {
			return failure(namecoinwire.OutcomeUnknown)
		}
		pr, pp := parent.candidate.snapshot.Request(), parent.candidate.snapshot.Plan()
		expectedSlot := string(byte('A' + i))
		expectedPlan := reservationHash
		if expectedSlot == "C" {
			expectedPlan = r.PlanSHA256
		}
		if pr.Slot != expectedSlot || pr.PlanSHA256 != expectedPlan || parent.id != attemptIdentity(expectedPlan, expectedSlot) {
			return failure(namecoinwire.IntentMismatch)
		}
		if pp.Group != p.Group || pp.Account != p.Account || pp.AccountPinSHA256 != p.AccountPinSHA256 || pp.Network != p.Network || pp.Genesis != p.Genesis || pp.Policy != p.Policy {
			return failure(namecoinwire.IntentMismatch)
		}
		if len(pp.Registrations) != len(p.Registrations) {
			return failure(namecoinwire.IntentMismatch)
		}
		for j, registration := range p.Registrations {
			previous := pp.Registrations[j]
			if j == 1 && (registration.ValueHex != previous.ValueHex || registration.ValueSHA256 != previous.ValueSHA256) {
				return failure(namecoinwire.IntentMismatch)
			}
			if registration.NameHex != previous.NameHex || registration.RandHex != previous.RandHex || registration.NameOutputPath != previous.NameOutputPath || registration.ReservationSlot != previous.ReservationSlot || registration.RevealSlot != previous.RevealSlot {
				return failure(namecoinwire.IntentMismatch)
			}
		}
		receipt, err := parent.candidate.VerifyResult(entry.Result, parent.ReviewDigest())
		if err != nil {
			return failure(namecoinwire.OutcomeUnknown)
		}
		var head [32]byte
		if _, err = hex.Decode(head[:], []byte(receipt.JournalHeadSHA256)); err != nil || anchor == nil {
			return failure(namecoinwire.OutcomeUnknown)
		}
		if anchor.VerifyCompleted(parent.id, parent.Commitment(), entry.Result, receipt.JournalSequence, head, records) != nil {
			return failure(namecoinwire.OutcomeUnknown)
		}
		parents[expectedSlot], receipts[expectedSlot] = parent, receipt
	}
	if r.Slot == "B" {
		return nil
	} // Same exact reservation plan hash binds A's entire transaction template.
	if len(p.ParentResults) != 2 {
		return failure(namecoinwire.IntentMismatch)
	}
	for _, claimed := range p.ParentResults {
		actual, ok := receipts[claimed.Slot]
		if !ok || (claimed.Slot != "A" && claimed.Slot != "B") || claimed.RequestID != actual.RequestID || claimed.SittingID != actual.SittingID || claimed.UnsignedTxID != actual.UnsignedTxID || claimed.SignedPSBTSHA256 != actual.SignedPSBTSHA256 {
			return failure(namecoinwire.IntentMismatch)
		}
	}
	// Inspect already enforces the graph shape; now compare full actual historical
	// predecessor bodies, including when the supplied parents carry witness data.
	var cMeta, dMeta namecoinwire.Transaction
	for _, tx := range p.Transactions {
		if tx.Slot == "C" {
			cMeta = tx
		}
		if tx.Slot == "D" {
			dMeta = tx
		}
	}
	if len(cMeta.Inputs) != 2 || len(dMeta.Inputs) != 2 {
		return failure(namecoinwire.IntentMismatch)
	}
	if !historicalParent(cMeta.Inputs[0], parents["A"].candidate.packet.tx) || !historicalParent(cMeta.Inputs[1], parents["B"].candidate.packet.tx) || !historicalParent(dMeta.Inputs[0], parents["B"].candidate.packet.tx) {
		return failure(namecoinwire.IntentMismatch)
	}
	if r.Slot == "D" && !historicalParent(dMeta.Inputs[1], parents["C"].candidate.packet.tx) {
		return failure(namecoinwire.IntentMismatch)
	}
	return nil
}
func historicalParent(input namecoinwire.Input, actual transaction) bool {
	supplied, err := parseTransaction(decodeHex(input.PreviousTransactionHex), true)
	return err == nil && bytes.Equal(supplied.serialize(false), actual.serialize(false)) && input.TxID == rpcHash(actual.hash())
}
