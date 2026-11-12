package namecoinwire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

const (
	MaxSignedPSBTBytes = MaxPSBTBytes + MaxInputs*110
	MaxResultBytes     = 8 << 20
)

type InputSignature struct {
	Index     uint32 `json:"index"`
	PublicKey string `json:"pubkey"`
	Algorithm string `json:"algorithm"`
	Encoding  string `json:"encoding"`
	Sighash   string `json:"sighash"`
	Signature string `json:"signature"`
}
type Receipt struct {
	Schema                string           `json:"schema"`
	Status                string           `json:"status"`
	RequestID             string           `json:"request_id"`
	SittingID             string           `json:"sitting_id"`
	Slot                  string           `json:"slot"`
	PlanSHA256            string           `json:"plan_sha256"`
	ReservationPlanSHA256 string           `json:"reservation_plan_sha256"`
	ReviewSHA256          string           `json:"review_sha256"`
	Network               string           `json:"network"`
	Group                 string           `json:"group"`
	Account               string           `json:"account"`
	AccountPinSHA256      string           `json:"account_pin_sha256"`
	UnsignedTxID          string           `json:"unsigned_txid"`
	SignedPSBTSHA256      string           `json:"signed_psbt_sha256"`
	InputSignatures       []InputSignature `json:"input_signatures"`
	JournalSequence       uint64           `json:"journal_sequence"`
	JournalHeadSHA256     string           `json:"journal_head_sha256"`
}
type Result struct {
	Schema     string  `json:"schema"`
	SignedPSBT string  `json:"signed_psbt"`
	Receipt    Receipt `json:"receipt"`
}

// DecodeResult validates public syntax/correlation only. SIGNED/sequence/head
// claims are not authenticated by JSON, transaction signatures or a public
// hash. Admitted endpoint and protected completed history remain required.
func DecodeResult(raw []byte) (Result, error) {
	var r Result
	if decodeClosed(raw, &r, MaxResultBytes) != nil || r.Schema != "keyvault-namecoin-psbt-result/2" {
		return Result{}, ErrInvalidRequest
	}
	p := r.Receipt
	if p.Schema != "keyvault-namecoin-psbt-receipt/2" || p.Status != "SIGNED" || !hashString(p.RequestID) || !hashString(p.SittingID) || !hashString(p.PlanSHA256) || !hashString(p.ReservationPlanSHA256) || !hashString(p.ReviewSHA256) || !network(p.Network) || !identity(p.Group, "recovery") || !identity(p.Account, "namecoin") || !hashString(p.AccountPinSHA256) || !hashString(p.UnsignedTxID) || !hashString(p.SignedPSBTSHA256) || p.JournalSequence == 0 || !hashString(p.JournalHeadSHA256) || len(p.Slot) != 1 || p.Slot[0] < 'A' || p.Slot[0] > 'D' || len(p.InputSignatures) == 0 || len(p.InputSignatures) > MaxInputs {
		return Result{}, ErrInvalidRequest
	}
	psbt, err := base64.StdEncoding.Strict().DecodeString(r.SignedPSBT)
	if err != nil || len(psbt) == 0 || len(psbt) > MaxSignedPSBTBytes || base64.StdEncoding.EncodeToString(psbt) != r.SignedPSBT {
		return Result{}, ErrInvalidRequest
	}
	hash := sha256.Sum256(psbt)
	if hex.EncodeToString(hash[:]) != p.SignedPSBTSHA256 {
		return Result{}, ErrInvalidRequest
	}
	for i, sig := range p.InputSignatures {
		if sig.Index != uint32(i) || !hexString(sig.PublicKey, 33, 33) || (sig.PublicKey[:2] != "02" && sig.PublicKey[:2] != "03") || sig.Algorithm != "secp256k1-ecdsa" || sig.Encoding != "strict-der-low-s" || sig.Sighash != "ALL" || !hexString(sig.Signature, 8, 71) {
			return Result{}, ErrInvalidRequest
		}
	}
	return r, nil
}

// EncodeResult emits a complete public bundle with one final LF. Calling this
// formatter does not authenticate a SIGNED outcome or permit acknowledgement.
func EncodeResult(r Result) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	raw = append(raw, '\n')
	if _, err = DecodeResult(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
