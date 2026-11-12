package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
)

// VerifyCompleted checks the exact result against this account-rederived
// protected anchor and complete checked history. The receipt references its
// DISPATCHED record; the immediately following SIGNED record commits the result.
// Later legitimate history may advance the current head. Public JSON/hash
// consistency alone, an unfinished dispatch or a result file alone never passes.
// Retain the owning Storage/gate and immutable inputs through this check and ack.
func (a *Anchor) VerifyCompleted(id AttemptID, commitment [32]byte, exactResult []byte, dispatchSequence uint64, dispatchHead [32]byte, records [][]byte) error {
	if len(exactResult) == 0 || len(exactResult) > 8<<20 || dispatchSequence == 0 || dispatchSequence >= uint64(len(records)) {
		return ErrUnknown
	}
	ledger, err := a.RestoreLedger(records)
	if err != nil {
		return ErrUnknown
	}
	outcome, hash, err := ledger.Outcome(id)
	if err != nil || outcome != Signed || hash != sha256.Sum256(exactResult) {
		return ErrUnknown
	}
	bound, err := ledger.Commitment(id)
	if err != nil || bound != commitment {
		return ErrUnknown
	}
	dispatchRaw := records[dispatchSequence-1]
	dispatch, err := DecodeFrame(dispatchRaw)
	if err != nil || dispatch.Sequence != dispatchSequence || sha256.Sum256(dispatchRaw) != dispatchHead {
		return ErrUnknown
	}
	// The complete ledger was already replayed. These exact tag/id/commitment
	// predicates ensure the selected sequence belongs to THIS bound attempt.
	prefix := append([]byte("KVNT2\x00"), byte(Dispatched))
	prefix = append(prefix, id[:]...)
	prefix = append(prefix, commitment[:]...)
	if !bytes.HasPrefix(dispatch.Body, prefix) {
		return ErrUnknown
	}
	signed, err := DecodeFrame(records[dispatchSequence])
	if err != nil || signed.Sequence != dispatchSequence+1 || signed.Previous != dispatchHead {
		return ErrUnknown
	}
	expected := append([]byte("KVNT1\x00"), byte(Signed))
	expected = append(expected, id[:]...)
	expected = append(expected, hash[:]...)
	if !bytes.Equal(signed.Body, expected) {
		return ErrUnknown
	}
	return nil
}
