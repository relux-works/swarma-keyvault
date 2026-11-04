package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
)

const LocalOrganization = "relux-works"
const LocalRepository = "matrix-grants-poc-261031"
const LocalOwnerMXID = "@alexis:gr.relux.works"

// This domain authenticates only the explicitly enrolled local association;
// it is separate from the existing request correlation digest and Matrix.
func localRequestDigest(raw []byte) [32]byte {
	digest, _ := domainDigest(localAttestation2Domain, raw)
	return digest
}

func localPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	if len(der) == 0 || len(der) > 1024 {
		return nil, errIssuerUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errIssuerUntrusted
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errIssuerUntrusted
	}
	return key, nil
}

type localAttestation struct {
	raw, signature []byte
	request        *localOperationProjection
}

func parseLocalAttestation(raw []byte) (*localAttestation, error) {
	node, err := parseCanonical(raw, localRequest2EnvelopeWire)
	if err != nil {
		return nil, err
	}
	f, err := subobjectTexts(node, "type", "payload", "signature")
	if err != nil || f["type"] != "grants-local-request-2" {
		return nil, errBadSchema
	}
	payload, err := decodeEnvelopeField(f["payload"], localRequestPayloadField)
	if err != nil {
		return nil, err
	}
	signature, err := decodeEnvelopeField(f["signature"], signatureField)
	if err != nil {
		return nil, err
	}
	if _, _, err := parseLowSSignatureDER(signature); err != nil {
		return nil, err
	}
	request, err := parseLocalOperationProjection(payload)
	if err != nil {
		return nil, err
	}
	return &localAttestation{raw: bytes.Clone(raw), signature: signature, request: request}, nil
}

// LocalRequestSigning owns exact typed request bytes. It does not enroll a key,
// verify a certificate, reserve a use or authenticate a Matrix device.
type LocalRequestSigning struct {
	request *localOperationProjection
	public  *ecdsa.PublicKey
}

func PrepareLocalRequest(raw, publicDER []byte) (*LocalRequestSigning, error) {
	request, err := parseLocalOperationProjection(raw)
	if err != nil {
		return nil, err
	}
	if request.action != "repository.create" || request.createTarget.organization != LocalOrganization || request.createTarget.name != LocalRepository {
		return nil, errResourceMismatch
	}
	public, err := localPublicKey(publicDER)
	if err != nil {
		return nil, err
	}
	return &LocalRequestSigning{request: request, public: public}, nil
}

func (p *LocalRequestSigning) Digest() [32]byte { return localRequestDigest(p.request.raw) }

func (p *LocalRequestSigning) SignedEnvelope(signature []byte) ([]byte, error) {
	if p == nil || p.request == nil {
		return nil, errBadSchema
	}
	if err := verifyP256Signature(p.public, p.Digest(), signature); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"type": "grants-local-request-2", "payload": base64.RawURLEncoding.EncodeToString(p.request.raw), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}
