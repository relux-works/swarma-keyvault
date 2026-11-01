package grants

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
)

// verifyP256Signature checks only the fixed P-256 ECDSA mathematical relation
// for an explicit public key, exact SHA-256 digest and strict low-S DER.
// A successful check does not enroll/trust the key or authenticate an issuer,
// validate a grant payload/interval, read a clock or authorize any operation.
// Callers must separately establish the exact domain digest, complete schema,
// enrolled SPKI/owner/purpose binding and all current state/authority gates.
// No input is normalized, retained or changed; no private-key operation occurs.
func verifyP256Signature(public *ecdsa.PublicKey, digest [sha256.Size]byte, raw []byte) error {
	r, s, err := parseLowSSignatureDER(raw)
	if err != nil {
		return err
	}
	// Admit the standard P-256 implementation before calling any curve method.
	// Nil/negative/oversized coordinates refuse before curve arithmetic.
	curve := elliptic.P256()
	if public == nil || public.Curve != curve || public.X == nil || public.Y == nil ||
		public.X.Sign() < 0 || public.Y.Sign() < 0 || public.X.BitLen() > 256 || public.Y.BitLen() > 256 {
		return errSignatureInvalid
	}
	if !curve.IsOnCurve(public.X, public.Y) || !ecdsa.Verify(public, digest[:], r, s) {
		return errSignatureInvalid
	}
	return nil
}
