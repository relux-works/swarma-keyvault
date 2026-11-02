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

// checkCertificateSignatureWithPin composes the bounded certificate envelope,
// complete typed payload and fixed-domain P-256 signature checks. The expected
// owner and exact public SPKI DER must come from a separately admitted enrollment
// boundary; supplying these arguments does not enroll a key or prove custody.
// A nil result establishes only that this certificate is signed by that explicit
// pin with matching owner/purpose. It does not check current time, revocation,
// supersession, receiver identity, durable state/audit/use or provider authority.
// It returns no dispatch capability and accesses no key store or private key.
func checkCertificateSignatureWithPin(raw []byte, ownerMXID string, issuerSPKIDER []byte) error {
	envelope, err := parseEnvelopeProjection(raw, certificateEnvelopeWire)
	if err != nil {
		return err
	}
	certificate, err := parseCertificateProjection(envelope.payload)
	if err != nil {
		return err
	}
	// Bound the public-key parser before calling it. The supported P-256 SPKI
	// export is 91 bytes; this finite cap is not a fallback algorithm selector.
	if len(issuerSPKIDER) == 0 || len(issuerSPKIDER) > 1024 {
		return errIssuerUntrusted
	}
	if _, err := parseMatrixAccountRepresentation(ownerMXID); err != nil {
		return errIssuerUntrusted
	}
	keyID := sha256.Sum256(issuerSPKIDER)
	if certificate.issuer.ownerMXID != ownerMXID ||
		certificate.issuer.keyID != "sha256:"+hex.EncodeToString(keyID[:]) ||
		certificate.issuer.purpose != "grants-owner-v1" {
		return errIssuerUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(issuerSPKIDER)
	if err != nil {
		return errIssuerUntrusted
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return errIssuerUntrusted
	}
	digest, err := domainDigest(certificateDomain, envelope.payload)
	if err != nil {
		return err
	}
	return verifyP256Signature(public, digest, envelope.signature)
}
