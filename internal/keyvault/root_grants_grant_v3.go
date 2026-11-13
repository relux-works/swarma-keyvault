package keyvault

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const rootGrantsGrantV3Operation = "review-sign-grant-v3"
const rootGrantsGrantV3Domain = "swarma-grant-v3"
const rootGrantsGrantV3Limit = 65536

// rootGrantsGrantV3Digest is the grant-v3 BYTE primitive, not a grant parser or
// authority check. Its input must already be the exact, complete, independently
// validated canonical grant. It never normalizes JSON or accepts a caller hash.
// Keep this private until the typed grant/contract/consent and enrollment/source
// gates can construct that input. A digest by itself cannot authorize signing.
func rootGrantsGrantV3Digest(canonical []byte) ([32]byte, error) {
	if len(canonical) == 0 {
		return [32]byte{}, recoveryRefuse("invalid_arguments")
	}
	if len(canonical) > rootGrantsGrantV3Limit {
		return [32]byte{}, recoveryRefuse("limit_exceeded")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(rootGrantsGrantV3Domain))
	_, _ = h.Write(canonical)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// rootGrantsVerifyGrantV3 re-computes the exact protocol message rather than
// trusting a helper-supplied digest. expectedK must come from the independently
// admitted root record AND authority, not the requested issuer field. This is
// offline public math only: successful verification proves neither canonical
// grant semantics, authority, consent, observation, review nor fresh presence.
// No scalar, arbitrary-hash signer, Keychain or helper call is exposed here.
func rootGrantsVerifyGrantV3(canonical []byte, expectedK string, signature []byte) error {
	digest, err := rootGrantsGrantV3Digest(canonical)
	if err != nil {
		return err
	}
	if !lowerHex(expectedK, 32) {
		return recoveryRefuse("public_pin_mismatch")
	}
	public, _ := hex.DecodeString(expectedK)
	key, err := schnorr.ParsePubKey(public)
	if err != nil {
		return recoveryRefuse("public_pin_mismatch")
	}
	// ParseSignature admits exactly 64 raw BIP-340 bytes, never DER, an appended
	// sighash byte or a hex-text signature disguised as a byte buffer.
	sig, err := schnorr.ParseSignature(signature)
	if err != nil || !sig.Verify(digest[:], key) {
		return recoveryRefuse("signature_verification_failed")
	}
	return nil
}
