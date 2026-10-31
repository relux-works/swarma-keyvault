package grants

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

var errSignatureInvalid = errors.New("signature-invalid")

// parseLowSSignatureDER accepts the new envelope's fixed P256 representation
// only. It does not verify ECDSA, derive/enroll any key, read custody, normalize
// high-S, or confer authority. Received bytes are never changed or repaired.
func parseLowSSignatureDER(raw []byte) (*big.Int, *big.Int, error) {
	if len(raw) > 72 {
		return nil, nil, errInputLimit
	}
	if len(raw) < 8 || raw[0] != 0x30 || int(raw[1]) != len(raw)-2 {
		return nil, nil, errSignatureInvalid
	}
	position := 2
	integer := func() (*big.Int, bool) {
		if position+2 > len(raw) || raw[position] != 2 {
			return nil, false
		}
		length := int(raw[position+1])
		position += 2
		if length < 1 || length > 33 || length > len(raw)-position {
			return nil, false
		}
		value := raw[position : position+length]
		position += length
		// DER INTEGER is signed: positive top-bit values need exactly one
		// leading zero; no redundant zero or negative representation passes.
		if value[0]&0x80 != 0 || len(value) > 1 && value[0] == 0 && value[1]&0x80 == 0 {
			return nil, false
		}
		return new(big.Int).SetBytes(value), true
	}
	r, ok := integer()
	if !ok {
		return nil, nil, errSignatureInvalid
	}
	s, ok := integer()
	if !ok || position != len(raw) {
		return nil, nil, errSignatureInvalid
	}
	order := elliptic.P256().Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 || s.Cmp(half) > 0 {
		return nil, nil, errSignatureInvalid
	}
	return r, s, nil
}
