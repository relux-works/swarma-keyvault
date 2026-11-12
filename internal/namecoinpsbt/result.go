package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// ResultBytes uses the attempt's durable DISPATCHED sequence/head. The later
// SIGNED record commits these exact complete bytes; that later head is never
// inserted into the result it hashes. This method handles public data only;
// its caller must prove actual durable/protected completion before any ack.
func (c Candidate) ResultBytes(signatures [][]byte, review [32]byte, dispatchSequence uint64, dispatchHead [32]byte) ([]byte, error) {
	signed, _, err := c.Assemble(signatures)
	if err != nil {
		return nil, err
	}
	r, p := c.snapshot.Request(), c.snapshot.Plan()
	hash := sha256.Sum256(signed)
	receipt := namecoinwire.Receipt{Schema: "keyvault-namecoin-psbt-receipt/2", Status: "SIGNED", RequestID: r.RequestID, SittingID: r.SittingID, Slot: r.Slot, PlanSHA256: r.PlanSHA256, ReservationPlanSHA256: r.ReservationPlanSHA256, ReviewSHA256: hex.EncodeToString(review[:]), Network: r.Network, Group: p.Group, Account: p.Account, AccountPinSHA256: p.AccountPinSHA256, UnsignedTxID: c.view.UnsignedTxID, SignedPSBTSHA256: hex.EncodeToString(hash[:]), JournalSequence: dispatchSequence, JournalHeadSHA256: hex.EncodeToString(dispatchHead[:])}
	for i, sig := range signatures {
		receipt.InputSignatures = append(receipt.InputSignatures, namecoinwire.InputSignature{Index: uint32(i), PublicKey: c.view.Inputs[i].PublicKeyHex, Algorithm: "secp256k1-ecdsa", Encoding: "strict-der-low-s", Sighash: "ALL", Signature: hex.EncodeToString(sig[:len(sig)-1])})
	}
	return namecoinwire.EncodeResult(namecoinwire.Result{Schema: "keyvault-namecoin-psbt-result/2", SignedPSBT: base64.StdEncoding.EncodeToString(signed), Receipt: receipt})
}

// VerifyResult proves public request/review/PSBT/signature correlation only.
// Independently authenticate its DISPATCHED reference and subsequent completed
// SIGNED record in protected history before treating the result as recoverable.
func (c Candidate) VerifyResult(raw []byte, expectedReview [32]byte) (namecoinwire.Receipt, error) {
	r, err := namecoinwire.DecodeResult(raw)
	if err != nil {
		return namecoinwire.Receipt{}, err
	}
	request, plan := c.snapshot.Request(), c.snapshot.Plan()
	p := r.Receipt
	if len(c.digests) == 0 || p.RequestID != request.RequestID || p.SittingID != request.SittingID || p.Slot != request.Slot || p.PlanSHA256 != request.PlanSHA256 || p.ReservationPlanSHA256 != request.ReservationPlanSHA256 || p.ReviewSHA256 != hex.EncodeToString(expectedReview[:]) || p.Network != request.Network || p.Group != plan.Group || p.Account != plan.Account || p.AccountPinSHA256 != plan.AccountPinSHA256 || p.UnsignedTxID != c.view.UnsignedTxID {
		return namecoinwire.Receipt{}, failure(namecoinwire.IntentMismatch)
	}
	signed, _ := base64.StdEncoding.Strict().DecodeString(r.SignedPSBT)
	sigs, err := c.VerifySignedPSBT(signed)
	if err != nil {
		return namecoinwire.Receipt{}, err
	}
	if len(sigs) != len(p.InputSignatures) {
		return namecoinwire.Receipt{}, failure(namecoinwire.SighashRefused)
	}
	for i, sig := range sigs {
		s := p.InputSignatures[i]
		if s.PublicKey != c.view.Inputs[i].PublicKeyHex || !bytes.Equal(decodeHex(s.Signature), sig[:len(sig)-1]) {
			return namecoinwire.Receipt{}, failure(namecoinwire.SighashRefused)
		}
	}
	return p, nil
}
