package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// A2ARepository belongs to the separate application-key test profile. It does
// not widen or reinterpret the existing local certificate/request profiles.
const A2ARepository = "matrix-grants-g2-261104"

var (
	ErrA2APromptOverflow    = errors.New("a2a-prompt-not-displayable")
	ErrA2ATerm              = errors.New("a2a-term-mismatch")
	ErrA2ARegistryPin       = errors.New("a2a-registry-pin-mismatch")
	ErrA2ASenderUnavailable = errors.New("a2a-full-sender-unavailable")
	ErrA2ANoGrant           = errors.New("a2a-no-applicable-grant")
	ErrA2AAmbiguousGrant    = errors.New("a2a-ambiguous-grant")
	ErrA2AContext           = errors.New("a2a-context-mismatch")
)

type a2aCertificate struct {
	raw                            []byte
	id, audience, account, entryID string
	issuer                         *issuerProjection
	subjectHash, keyRegistryHash   [32]byte
	notBefore, expiresAt           time.Time
}

func a2aTarget(node *wireValue) error {
	f, err := subobjectTexts(node, "name", "organization", "visibility")
	if err != nil {
		return err
	}
	if f["name"] != A2ARepository || f["organization"] != LocalOrganization || f["visibility"] != "private" {
		return errResourceMismatch
	}
	return nil
}

func parseA2ACertificate(raw []byte) (*a2aCertificate, error) {
	n, err := parseCanonical(raw, a2aCertificateWire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(n, "audience", "certificate_id", "entries", "expires_at", "issuer", "key_registry_sha256", "not_before", "subject", "supersedes", "type")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"audience", "certificate_id", "expires_at", "key_registry_sha256", "not_before", "type"} {
		if f[name].kind != stringValue {
			return nil, errBadSchema
		}
	}
	if f["type"].text != "grants-a2a-certificate-1" || f["supersedes"].kind != arrayValue || len(f["supersedes"].elements) != 0 {
		return nil, errBadSchema
	}
	c := &a2aCertificate{raw: bytes.Clone(raw)}
	if c.audience, err = parseMatrixAccountRepresentation(f["audience"].text); err != nil {
		return nil, err
	}
	if c.id, err = parseOpaqueID(f["certificate_id"].text); err != nil {
		return nil, err
	}
	if c.issuer, err = parseIssuerNode(f["issuer"]); err != nil {
		return nil, err
	}
	if c.keyRegistryHash, err = parseWireDigest(f["key_registry_sha256"].text); err != nil {
		return nil, err
	}
	sub, err := subobjectTexts(f["subject"], "account_mxid", "spki_sha256")
	if err != nil {
		return nil, err
	}
	if c.account, err = parseMatrixAccountRepresentation(sub["account_mxid"]); err != nil {
		return nil, err
	}
	if c.subjectHash, err = parseWireDigest(sub["spki_sha256"]); err != nil {
		return nil, err
	}
	if c.notBefore, err = parseWireTime(f["not_before"].text); err != nil {
		return nil, err
	}
	if c.expiresAt, err = parseWireTime(f["expires_at"].text); err != nil {
		return nil, err
	}
	if !c.expiresAt.After(c.notBefore) || c.expiresAt.Sub(c.notBefore) > 30*time.Minute {
		return nil, ErrA2ATerm
	}
	if f["entries"].kind != arrayValue || len(f["entries"].elements) != 1 {
		return nil, errResourceMismatch
	}
	e, err := closedObject(f["entries"].elements[0], "action", "entry_id", "target", "use_count")
	if err != nil {
		return nil, err
	}
	if e["action"].kind != stringValue || e["action"].text != "repository.create" || e["use_count"].kind != stringValue || e["use_count"].text != "1" {
		return nil, errResourceMismatch
	}
	if e["entry_id"].kind != stringValue {
		return nil, errBadSchema
	}
	if c.entryID, err = parseOpaqueID(e["entry_id"].text); err != nil {
		return nil, err
	}
	if err := a2aTarget(e["target"]); err != nil {
		return nil, err
	}
	return c, nil
}

func a2aCheckedReason(reason string) (string, error) {
	if reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 200 {
		return "", ErrA2APromptOverflow
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", ErrA2APromptOverflow
		}
	}
	return reason, nil
}

func (c *a2aCertificate) reason(digest [32]byte) (string, error) {
	// Fixed MSK UTC+03 avoids inheriting the process locale/timezone. Spell
	// both dates if the interval crosses midnight; never omit the latter.
	msk := time.FixedZone("MSK", 3*60*60)
	start, end := c.notBefore.In(msk), c.expiresAt.In(msk)
	clock := "15:04"
	if start.Second() != 0 || end.Second() != 0 {
		clock = "15:04:05"
	}
	interval := start.Format("02.01.2006 "+clock) + "–" + end.Format(clock) + " MSK"
	if start.Format("2006-01-02") != end.Format("2006-01-02") {
		interval = start.Format("02.01.2006 "+clock) + "–" + end.Format("02.01.2006 "+clock) + " MSK"
	}
	reason := fmt.Sprintf("1× CREATE private %s/%s → %s key %x; %s; SHA256 %x", LocalOrganization, A2ARepository, c.account, c.subjectHash[:8], interval, digest[26:])
	return a2aCheckedReason(reason)
}

// A2ACertificateIssuance holds exact checked unsigned bytes and public pins.
// It neither opens a vault nor issues authority, enrolls a key or changes state.
type A2ACertificateIssuance struct {
	certificate *a2aCertificate
	public      *ecdsa.PublicKey
	digest      [32]byte
	reason      string
}

func PrepareA2ACertificate(raw []byte, ownerMXID string, ownerDER, granteeDER []byte) (*A2ACertificateIssuance, error) {
	c, err := parseA2ACertificate(raw)
	if err != nil {
		return nil, err
	}
	public, err := localPublicKey(ownerDER)
	if err != nil {
		return nil, err
	}
	if _, err := parseMatrixAccountRepresentation(ownerMXID); err != nil {
		return nil, errIssuerUntrusted
	}
	if c.issuer.ownerMXID != ownerMXID || c.issuer.keyID != "sha256:"+hex.EncodeToString(sha256Sum(ownerDER)) {
		return nil, errIssuerUntrusted
	}
	if _, err := localPublicKey(granteeDER); err != nil {
		return nil, err
	}
	if bytes.Equal(ownerDER, granteeDER) || sha256.Sum256(granteeDER) != c.subjectHash {
		return nil, errRequesterMismatch
	}
	digest, _ := domainDigest(a2aCertificateDomain, raw)
	reason, err := c.reason(digest)
	if err != nil {
		return nil, err
	}
	return &A2ACertificateIssuance{certificate: c, public: public, digest: digest, reason: reason}, nil
}

func sha256Sum(raw []byte) []byte { sum := sha256.Sum256(raw); return sum[:] }

func (p *A2ACertificateIssuance) Payload() []byte         { return bytes.Clone(p.certificate.raw) }
func (p *A2ACertificateIssuance) Digest() [32]byte        { return p.digest }
func (p *A2ACertificateIssuance) Prompt() (string, error) { return a2aCheckedReason(p.reason) }
func (p *A2ACertificateIssuance) Review() string {
	return fmt.Sprintf("UNSIGNED: no grant is active.\nPresence reason: %s\nExactly one private CREATE; no DELETE, retry or other action.\nSubject key SHA256: %x\nValidity UTC: [%s,%s)\nDomain: swarma-grants/a2a-certificate/1\nDigest SHA256: %x\nSame OS user and shared provider login do not isolate sessions or GitHub authority. Application signatures do not establish Matrix E2EE/device authentication.\nExact canonical certificate:\n%s\n", p.reason, p.certificate.subjectHash, p.certificate.notBefore.Format(time.RFC3339), p.certificate.expiresAt.Format(time.RFC3339), p.digest, p.certificate.raw)
}
func (p *A2ACertificateIssuance) SignedEnvelope(signature []byte) ([]byte, error) {
	if p == nil || p.certificate == nil {
		return nil, errBadSchema
	}
	if err := verifyP256Signature(p.public, p.digest, signature); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"type": "grants-a2a-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(p.certificate.raw), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}
