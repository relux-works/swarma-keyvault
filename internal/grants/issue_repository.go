package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RepositoryIssuance owns the complete exact first-slice payload and its public
// pin. It is signing preparation, never enrollment or active grant authority.
type RepositoryIssuance struct {
	payload, public []byte
	owner, review   string
	digest          [sha256.Size]byte
}

// NewRepositoryIssuance validates a one-cycle first-issue private CREATE and
// paired DELETE against the explicit intended scope. No key store is accessed.
// Received payload bytes are never normalized or replaced before signing.
func NewRepositoryIssuance(payload []byte, owner string, public []byte, organization, name string) (*RepositoryIssuance, error) {
	certificate, err := parseCertificateProjection(payload)
	if err != nil {
		return nil, err
	}
	if _, err := parseMatrixAccountRepresentation(owner); err != nil || len(public) == 0 || len(public) > 1024 {
		return nil, errIssuerUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(public)
	if err != nil {
		return nil, errIssuerUntrusted
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errIssuerUntrusted
	}
	id := sha256.Sum256(public)
	if certificate.issuer.ownerMXID != owner || certificate.issuer.keyID != "sha256:"+hex.EncodeToString(id[:]) || certificate.issuer.purpose != "grants-owner-v1" {
		return nil, errIssuerUntrusted
	}
	if organization == "" || name == "" || len(certificate.supersedes) != 0 || len(certificate.cycles) != 1 || len(certificate.entries) != 2 {
		return nil, errScheduleMismatch
	}
	var create, remove *entryProjection
	for _, entry := range certificate.entries {
		if entry.action == "repository.create" {
			create = entry
		} else {
			remove = entry
		}
	}
	if create == nil || remove == nil || len(create.uses) != 1 || len(remove.uses) != 1 {
		return nil, errScheduleMismatch
	}
	if create.createTarget.organization != organization || create.createTarget.name != name || create.createTarget.visibility != "private" ||
		remove.deleteTarget.organization != organization || remove.deleteTarget.name != name || remove.deleteTarget.pairedCreateEntry != create.entryID {
		return nil, errResourceMismatch
	}
	digest, err := domainDigest(certificateDomain, payload)
	if err != nil {
		return nil, err
	}
	var display bytes.Buffer
	if err := json.Indent(&display, payload, "", "  "); err != nil {
		return nil, errBadEncoding
	}
	review := fmt.Sprintf("Разрешается одно создание приватного репозитория %s/%s и парное удаление; в первом срезе удаление не выполняется.\nПодпись ещё не выполнена. Привязка requester к Matrix subject локальная и не подтверждает Matrix identity.\nDomain: swarma-grants/certificate/1\nSHA256(domain + LF + exact payload): %x\n%s\n", organization, name, digest, display.Bytes())
	return &RepositoryIssuance{payload: bytes.Clone(payload), public: bytes.Clone(public), owner: owner, review: review, digest: digest}, nil
}

func (p *RepositoryIssuance) Digest() [sha256.Size]byte { return p.digest }
func (p *RepositoryIssuance) Review() string            { return p.review }

// SignedEnvelope emits the existing certificate wire only after the returned
// signature verifies against this preparation's exact bytes and explicit pin.
// It neither activates nor stores the resulting certificate.
func (p *RepositoryIssuance) SignedEnvelope(signature []byte) ([]byte, error) {
	if p == nil || len(p.payload) == 0 {
		return nil, errBadSchema
	}
	if _, _, err := parseLowSSignatureDER(signature); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(map[string]string{
		"type": "grants-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(p.payload),
		"signature": base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, errBadSchema
	}
	if err := checkCertificateSignatureWithPin(raw, p.owner, p.public); err != nil {
		return nil, err
	}
	return raw, nil
}
