package reviewedsession

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
)

type subjectFingerprint struct {
	kind, encoding, full, tail string
}

// This function compares full independently supplied bytes. It does not
// establish the provenance of that pin or authenticate a Matrix account.
func fingerprint(p profile, public, admitted []byte) (subjectFingerprint, error) {
	var result subjectFingerprint
	if !p.included() || len(public) == 0 || !bytes.Equal(public, admitted) {
		return result, errBinding
	}
	switch p {
	case repository:
		if len(public) != 32 {
			return result, errBinding
		}
		result.kind = "raw-ed25519-device"
	default:
		if _, err := p256DER(public); err != nil {
			return result, err
		}
		switch p {
		case localRepository:
			result.kind = "requester-p256-spki"
		case a2aCertificate:
			result.kind = "application-p256-spki"
		case muGrantMac:
			result.kind = "mac-p256-spki"
		}
	}
	h := sha256.Sum256(public)
	result.encoding, result.full = "lowercase-hex", hex.EncodeToString(h[:])
	if p == muGrantMac {
		result.encoding, result.full = "unpadded-base64url", base64.RawURLEncoding.EncodeToString(h[:])
	}
	result.tail = result.full[len(result.full)-8:]
	return result, nil
}

func p256DER(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 || len(der) > 1024 {
		return nil, errBinding
	}
	p, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errBinding
	}
	key, ok := p.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errBinding
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonical, der) {
		return nil, errBinding
	}
	return key, nil
}

// MU key IDs encode compressed points. Hash canonical SPKI DER, never this
// textual ID or its 33 point bytes. Account/generation remain attested context.
func muSubjectFingerprint(keyID string, admittedDER []byte) (subjectFingerprint, error) {
	const prefix = "p256:"
	if len(keyID) <= len(prefix) || keyID[:len(prefix)] != prefix {
		return subjectFingerprint{}, errBinding
	}
	point, err := byteString(keyID[len(prefix):], 33)
	if err != nil || len(point) != 33 {
		return subjectFingerprint{}, errBinding
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), point)
	if x == nil {
		return subjectFingerprint{}, errBinding
	}
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		return subjectFingerprint{}, errBinding
	}
	return fingerprint(muGrantMac, der, admittedDER)
}
