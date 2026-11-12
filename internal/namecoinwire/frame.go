package namecoinwire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// ReviewContext is independently selected trusted configuration, not a request
// authority field. The engine must supply its actual retained pin/policy and
// validate admission/time/transaction facts before treating a frame as approved.
type ReviewContext struct {
	Group, Account, Network, Genesis, PolicyRevision string
	AccountPinSHA256                                 [32]byte
	PerTxFeeCap                                      uint64
}

// ReviewFrame rejects a context/plan mismatch and uses only this snapshot's
// owned bytes. Producing this public commitment performs no private operation.
func (s Snapshot) ReviewFrame(c ReviewContext) ([]byte, error) {
	p, r := s.plan, s.request
	cap, ok := Decimal(p.Policy.PerTxFeeCap)
	if !ok || len(s.psbt) == 0 || c.Group != p.Group || c.Account != p.Account || c.Network != p.Network || c.Genesis != p.Genesis ||
		c.PolicyRevision != p.Policy.Revision || c.PerTxFeeCap != cap || hex.EncodeToString(c.AccountPinSHA256[:]) != p.AccountPinSHA256 {
		return nil, NewFailure(PolicyRefused, false)
	}
	frame := []byte("keyvault/namecoin-psbt-review/2\x00")
	frame = append(frame, lp(s.psbt)...)
	frame = append(frame, lp([]byte(s.operation))...)
	for _, v := range []string{s.nameHex, s.valueHex, s.randHex} {
		b, _ := hex.DecodeString(v)
		frame = append(frame, lp(b)...)
	}
	if s.reservation == nil {
		frame = append(frame, 0)
	} else {
		frame = append(frame, 1)
		frame = append(frame, reverseHash(s.reservation.TxID)...)
		frame = binary.BigEndian.AppendUint32(frame, s.reservation.Vout)
	}
	phase := byte(0)
	if p.Kind == "reveal" {
		phase = 1
	}
	frame = append(frame, phase)
	for _, v := range []string{r.ReservationPlanSHA256, r.PlanSHA256, r.SittingID} {
		b, _ := hex.DecodeString(v)
		frame = append(frame, b...)
	}
	frame = append(frame, r.Slot[0])
	frame = append(frame, lp([]byte(c.Group))...)
	frame = append(frame, lp([]byte(c.Account))...)
	frame = append(frame, c.AccountPinSHA256[:]...)
	frame = append(frame, lp([]byte(c.Network))...)
	frame = append(frame, reverseHash(c.Genesis)...)
	frame = append(frame, lp([]byte(c.PolicyRevision))...)
	frame = binary.BigEndian.AppendUint64(frame, c.PerTxFeeCap)
	requestID, _ := hex.DecodeString(r.RequestID)
	frame = append(frame, requestID...)
	frame = binary.BigEndian.AppendUint64(frame, r.ExpiresAt)
	return frame, nil
}
func (s Snapshot) ReviewDigest(c ReviewContext) ([32]byte, error) {
	frame, err := s.ReviewFrame(c)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(frame), nil
}
func reverseHash(s string) []byte {
	b, _ := hex.DecodeString(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
