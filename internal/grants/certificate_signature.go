package grants

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

var errIssuerUntrusted = errors.New("issuer-untrusted")

// publicIssuerPin carries explicit caller-supplied expected public values.
// This struct is not an enrolled principal or evidence of protected custody.
type publicIssuerPin struct {
	ownerMXID string
	spkiDER   []byte
}

// checkCertificateSignatureWithPin composes the bounded certificate envelope,
// complete typed payload and fixed-domain P-256 signature checks. The expected
// owner and exact public SPKI DER must come from a separately admitted enrollment
// boundary; supplying these arguments does not enroll a key or prove custody.
// A nil result establishes only that this certificate is signed by that explicit
// pin with matching owner/purpose. It does not check current time, revocation,
// supersession, receiver identity, durable state/audit/use or provider authority.
// It returns no dispatch capability and accesses no key store or private key.
func checkCertificateSignatureWithPin(raw []byte, ownerMXID string, issuerSPKIDER []byte) error {
	_, err := checkSignedRecordWithPin(raw, certificateEnvelopeWire, publicIssuerPin{ownerMXID: ownerMXID, spkiDER: issuerSPKIDER})
	return err
}

// checkSignedRecordWithPin checks complete certificate/revocation public
// representations only. The returned projection is not a lifecycle command,
// protected enrollment, current-state witness or dispatch capability.
func checkSignedRecordWithPin(raw []byte, profile wireProfile, pin publicIssuerPin) (*envelopeProjection, error) {
	envelope, err := parseEnvelopeProjection(raw, profile)
	if err != nil {
		return nil, err
	}
	var issuer *issuerProjection
	switch profile {
	case certificateEnvelopeWire:
		certificate, err := parseCertificateProjection(envelope.payload)
		if err != nil {
			return nil, err
		}
		issuer = certificate.issuer
	case revocationEnvelopeWire:
		revocation, err := parseRevocationProjection(envelope.payload)
		if err != nil {
			return nil, err
		}
		issuer = revocation.issuer
	default:
		return nil, errBadSchema
	}
	// Bound the public-key parser before calling it. The supported P-256 SPKI
	// export is 91 bytes; this finite cap is not a fallback algorithm selector.
	if len(pin.spkiDER) == 0 || len(pin.spkiDER) > 1024 {
		return nil, errIssuerUntrusted
	}
	if _, err := parseMatrixAccountRepresentation(pin.ownerMXID); err != nil {
		return nil, errIssuerUntrusted
	}
	keyID := sha256.Sum256(pin.spkiDER)
	if issuer.ownerMXID != pin.ownerMXID ||
		issuer.keyID != "sha256:"+hex.EncodeToString(keyID[:]) ||
		issuer.purpose != "grants-owner-v1" {
		return nil, errIssuerUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(pin.spkiDER)
	if err != nil {
		return nil, errIssuerUntrusted
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errIssuerUntrusted
	}
	digest, err := domainDigest(envelope.domain, envelope.payload)
	if err != nil {
		return nil, err
	}
	if err := verifyP256Signature(public, digest, envelope.signature); err != nil {
		return nil, err
	}
	return envelope, nil
}
