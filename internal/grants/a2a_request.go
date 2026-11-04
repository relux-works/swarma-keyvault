package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

type a2aRequest struct {
	raw, actionPayload                   []byte
	sender, audience, room, topic, nonce string
	registryHash                         [32]byte
	issuedAt, expiresAt                  time.Time
}

func a2aContextText(value string, prefix byte) bool {
	if len(value) < 2 || len(value) > 255 || value[0] != prefix {
		return false
	}
	for i := range value {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func parseA2ARequest(raw, action []byte) (*a2aRequest, error) {
	n, err := parseCanonical(raw, a2aRequestWire)
	if err != nil {
		return nil, err
	}
	f, err := subobjectTexts(n, "action", "audience", "expires_at", "grant_registry_sha256", "issued_at", "nonce", "request_sha256", "resource", "room_id", "sender_mxid", "topic", "version")
	if err != nil {
		return nil, err
	}
	if f["version"] != "grants-a2a-request-1" {
		return nil, errBadSchema
	}
	if f["action"] != "repository.create" || f["resource"] != "github:"+LocalOrganization+"/"+A2ARepository {
		return nil, errResourceMismatch
	}
	actionNode, err := parseCanonical(action, a2aActionWire)
	if err != nil {
		return nil, err
	}
	if err := a2aTarget(actionNode); err != nil {
		return nil, err
	}
	payloadHash, err := parseWireDigest(f["request_sha256"])
	if err != nil {
		return nil, err
	}
	if payloadHash != sha256.Sum256(action) {
		return nil, ErrA2AContext
	}
	q := &a2aRequest{raw: bytes.Clone(raw), actionPayload: bytes.Clone(action), nonce: f["nonce"], room: f["room_id"], topic: f["topic"]}
	if q.sender, err = parseA2AAccount(f["sender_mxid"]); err != nil {
		return nil, err
	}
	if q.audience, err = parseA2AAccount(f["audience"]); err != nil {
		return nil, err
	}
	if !a2aContextText(q.room, '!') {
		return nil, errBadSchema
	}
	if _, err := parseOpaqueID(q.topic); err != nil {
		return nil, err
	}
	if _, err := parseWireDigest(q.nonce); err != nil {
		return nil, err
	}
	if q.registryHash, err = parseWireDigest(f["grant_registry_sha256"]); err != nil {
		return nil, err
	}
	if q.issuedAt, err = parseWireTime(f["issued_at"]); err != nil {
		return nil, err
	}
	if q.expiresAt, err = parseWireTime(f["expires_at"]); err != nil {
		return nil, err
	}
	if !q.expiresAt.After(q.issuedAt) || q.expiresAt.Sub(q.issuedAt) > 5*time.Minute {
		return nil, ErrA2ATerm
	}
	return q, nil
}

// A2ARequestSigning prepares only exact public bytes and a domain digest. It
// does not authenticate an event, select a grant, sign or open execution state.
type A2ARequestSigning struct{ request *a2aRequest }

func PrepareA2ARequest(raw, action []byte) (*A2ARequestSigning, error) {
	q, err := parseA2ARequest(raw, action)
	if err != nil {
		return nil, err
	}
	return &A2ARequestSigning{request: q}, nil
}
func (p *A2ARequestSigning) Digest() [32]byte {
	d, _ := domainDigest(a2aRequestDomain, p.request.raw)
	return d
}
func (p *A2ARequestSigning) Payload() []byte { return bytes.Clone(p.request.raw) }
func (p *A2ARequestSigning) SignedEnvelope(signature, publicDER []byte) ([]byte, error) {
	if p == nil || p.request == nil {
		return nil, errBadSchema
	}
	public, err := localPublicKey(publicDER)
	if err != nil {
		return nil, err
	}
	if err := verifyP256Signature(public, p.Digest(), signature); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"type": "grants-a2a-envelope-1", "payload": base64.RawURLEncoding.EncodeToString(p.request.raw), "request": base64.RawURLEncoding.EncodeToString(p.request.actionPayload), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}

func a2aBase64(value string, maximum int) ([]byte, error) {
	if len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errInputLimit
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errBadEncoding
	}
	return raw, nil
}

func parseA2AEnvelope(raw []byte) (*a2aRequest, []byte, error) {
	n, err := parseCanonical(raw, a2aRequestEnvelopeWire)
	if err != nil {
		return nil, nil, err
	}
	f, err := subobjectTexts(n, "payload", "request", "signature", "type")
	if err != nil {
		return nil, nil, err
	}
	if f["type"] != "grants-a2a-envelope-1" {
		return nil, nil, errBadSchema
	}
	payload, err := a2aBase64(f["payload"], 4096)
	if err != nil {
		return nil, nil, err
	}
	action, err := a2aBase64(f["request"], 1024)
	if err != nil {
		return nil, nil, err
	}
	sig, err := a2aBase64(f["signature"], 72)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := parseLowSSignatureDER(sig); err != nil {
		return nil, nil, err
	}
	q, err := parseA2ARequest(payload, action)
	if err != nil {
		return nil, nil, err
	}
	return q, sig, nil
}
