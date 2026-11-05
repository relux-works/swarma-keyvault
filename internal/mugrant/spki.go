package mugrant

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
)

var errSPKI = errors.New("mugrant-spki-invalid")

// parseP256SPKI admits only a P-256 ECDSA public key in PKIX form whose
// re-encoding is byte-identical to the input.
func parseP256SPKI(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 || len(spki) > 256 {
		return nil, errSPKI
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errSPKI
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errSPKI
	}
	again, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || string(again) != string(spki) {
		return nil, errSPKI
	}
	return pub, nil
}

// parseEd25519SPKI admits only the canonical PKIX DER of an Ed25519 key.
func parseEd25519SPKI(spki []byte) (ed25519.PublicKey, error) {
	if len(spki) == 0 || len(spki) > 256 {
		return nil, errSPKI
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errSPKI
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errSPKI
	}
	again, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || string(again) != string(spki) {
		return nil, errSPKI
	}
	return pub, nil
}
