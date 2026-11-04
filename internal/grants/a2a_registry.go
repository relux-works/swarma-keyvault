package grants

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// A2AReceiverConfig is a separately admitted caller's public configuration,
// never trust selected by message fields. File admission/custody and authentic
// Matrix projections remain the caller's obligations. Same-UID tampering is not
// prevented by these public pins. This component does not open files or a vault.
type A2AReceiverConfig struct {
	OwnerMXID, Audience, RoomID, Topic       string
	OwnerSPKIDER, KeyRegistry, GrantRegistry []byte
	KeyRegistrySHA256, GrantRegistrySHA256   string
}

type a2aRegistryKey struct {
	public *ecdsa.PublicKey
	hash   [32]byte
	active bool
}

// A2AReceiver performs only public cryptographic/context verification. It does
// not check/reserve nonces or uses, observe the network, authorize dispatch or
// call a provider. Execution must recheck this result inside its own durable
// state transaction; a successful Verify is not a reusable dispatch capability.
type A2AReceiver struct {
	audience, room, topic string
	keyHash, registryHash [32]byte
	keys                  map[string]a2aRegistryKey
	grants                map[string][]*a2aCertificate
	revoked               map[string]bool
}

func NewA2AReceiver(config A2AReceiverConfig) (*A2AReceiver, error) {
	owner, err := localPublicKey(config.OwnerSPKIDER)
	if err != nil {
		return nil, err
	}
	if _, err := parseMatrixAccountRepresentation(config.OwnerMXID); err != nil {
		return nil, errIssuerUntrusted
	}
	if _, err := parseMatrixAccountRepresentation(config.Audience); err != nil {
		return nil, ErrA2AContext
	}
	if !a2aContextText(config.RoomID, '!') {
		return nil, ErrA2AContext
	}
	if _, err := parseOpaqueID(config.Topic); err != nil {
		return nil, ErrA2AContext
	}
	keyHash, err := parseWireDigest(config.KeyRegistrySHA256)
	if err != nil {
		return nil, ErrA2ARegistryPin
	}
	grantHash, err := parseWireDigest(config.GrantRegistrySHA256)
	if err != nil {
		return nil, ErrA2ARegistryPin
	}
	if len(config.KeyRegistry) > 16384 || len(config.GrantRegistry) > 98304 {
		return nil, errInputLimit
	}
	if sha256.Sum256(config.KeyRegistry) != keyHash || sha256.Sum256(config.GrantRegistry) != grantHash {
		return nil, ErrA2ARegistryPin
	}
	r := &A2AReceiver{audience: config.Audience, room: config.RoomID, topic: config.Topic, keyHash: keyHash, registryHash: grantHash,
		keys: map[string]a2aRegistryKey{}, grants: map[string][]*a2aCertificate{}, revoked: map[string]bool{}}
	if err := r.parseKeys(config.KeyRegistry); err != nil {
		return nil, err
	}
	if err := r.parseGrants(config.GrantRegistry, owner, config.OwnerMXID, config.OwnerSPKIDER); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *A2AReceiver) parseKeys(raw []byte) error {
	n, err := parseCanonical(raw, a2aKeyRegistryWire)
	if err != nil {
		return err
	}
	f, err := closedObject(n, "keys", "type")
	if err != nil {
		return err
	}
	if f["type"].kind != stringValue || f["type"].text != "grants-a2a-key-registry-1" || f["keys"].kind != objectValue {
		return errBadSchema
	}
	for _, m := range f["keys"].members {
		if _, err := parseMatrixAccountRepresentation(m.name); err != nil {
			return err
		}
		v, err := subobjectTexts(m.value, "generation", "spki", "spki_sha256", "status")
		if err != nil {
			return err
		}
		if _, err := parsePositiveDecimal(v["generation"]); err != nil {
			return err
		}
		if v["status"] != "active" && v["status"] != "revoked" {
			return errBadSchema
		}
		der, err := a2aBase64(v["spki"], 1024)
		if err != nil {
			return err
		}
		key, err := localPublicKey(der)
		if err != nil {
			return err
		}
		hash, err := parseWireDigest(v["spki_sha256"])
		if err != nil {
			return err
		}
		if hash != sha256.Sum256(der) {
			return ErrA2ARegistryPin
		}
		r.keys[m.name] = a2aRegistryKey{public: key, hash: hash, active: v["status"] == "active"}
	}
	return nil
}

func parseA2ASignedCertificate(raw []byte, owner *ecdsa.PublicKey, ownerMXID string, ownerDER []byte) (*a2aCertificate, error) {
	n, err := parseCanonical(raw, a2aCertificateEnvelopeWire)
	if err != nil {
		return nil, err
	}
	f, err := subobjectTexts(n, "payload", "signature", "type")
	if err != nil {
		return nil, err
	}
	if f["type"] != "grants-a2a-signed-certificate-1" {
		return nil, errBadSchema
	}
	payload, err := a2aBase64(f["payload"], 4096)
	if err != nil {
		return nil, err
	}
	sig, err := a2aBase64(f["signature"], 72)
	if err != nil {
		return nil, err
	}
	c, err := parseA2ACertificate(payload)
	if err != nil {
		return nil, err
	}
	if c.issuer.ownerMXID != ownerMXID || c.issuer.keyID != "sha256:"+hex.EncodeToString(sha256Sum(ownerDER)) {
		return nil, errIssuerUntrusted
	}
	digest, _ := domainDigest(a2aCertificateDomain, payload)
	if err := verifyP256Signature(owner, digest, sig); err != nil {
		return nil, err
	}
	return c, nil
}

func (r *A2AReceiver) parseGrants(raw []byte, owner *ecdsa.PublicKey, ownerMXID string, ownerDER []byte) error {
	n, err := parseCanonical(raw, a2aGrantRegistryWire)
	if err != nil {
		return err
	}
	f, err := closedObject(n, "grants", "key_registry_sha256", "revoked", "type")
	if err != nil {
		return err
	}
	if f["type"].kind != stringValue || f["type"].text != "grants-a2a-grants-registry-1" || f["key_registry_sha256"].kind != stringValue || f["grants"].kind != objectValue || f["revoked"].kind != arrayValue {
		return errBadSchema
	}
	keyHash, err := parseWireDigest(f["key_registry_sha256"].text)
	if err != nil || keyHash != r.keyHash {
		return ErrA2ARegistryPin
	}
	if len(f["revoked"].elements) > 64 {
		return errInputLimit
	}
	for _, v := range f["revoked"].elements {
		if v.kind != stringValue {
			return errBadSchema
		}
		id, err := parseOpaqueID(v.text)
		if err != nil {
			return err
		}
		if r.revoked[id] {
			return errBadSchema
		}
		r.revoked[id] = true
	}
	ids := map[string]bool{}
	for _, m := range f["grants"].members {
		if _, err := parseMatrixAccountRepresentation(m.name); err != nil {
			return err
		}
		key, ok := r.keys[m.name]
		if !ok {
			return errRequesterMismatch
		}
		if m.value.kind != arrayValue || len(m.value.elements) > 4 {
			return errBadSchema
		}
		for _, v := range m.value.elements {
			if v.kind != stringValue {
				return errBadSchema
			}
			envelope, err := a2aBase64(v.text, 8192)
			if err != nil {
				return err
			}
			c, err := parseA2ASignedCertificate(envelope, owner, ownerMXID, ownerDER)
			if err != nil {
				return err
			}
			if c.account != m.name || c.subjectHash != key.hash || c.keyRegistryHash != r.keyHash {
				return errRequesterMismatch
			}
			if c.audience != r.audience {
				return ErrA2AContext
			}
			if ids[c.id] {
				return errBadSchema
			}
			ids[c.id] = true
			r.grants[m.name] = append(r.grants[m.name], c)
		}
	}
	return nil
}

// A2AEvent must be supplied by an admitted authentic event projection, not
// unmarshaled from a requester-controlled body. It makes no E2EE/device claim.
// Until a supported projection supplies full sender/context, live intake must
// refuse. Neither a display alias nor @alias:<assumed server> is acceptable.
type A2AEvent struct {
	SenderMXID, RecipientMXID, RoomID, Topic, Kind, EventID string
	Body                                                    []byte
}

// A2AVerifiedEnvelope is public verification evidence, not a dispatch token or
// proof of unused authority. These exported strings are descriptive only.
type A2AVerifiedEnvelope struct {
	CertificateID, EntryID, SenderMXID, Nonce, EventID string
	OwnerKeySHA256, SubjectKeySHA256, RequestSHA256    string
}

func (r *A2AReceiver) Verify(event A2AEvent, now time.Time) (*A2AVerifiedEnvelope, error) {
	if r == nil {
		return nil, ErrA2AContext
	}
	if _, err := parseMatrixAccountRepresentation(event.SenderMXID); err != nil {
		return nil, ErrA2ASenderUnavailable
	}
	if event.RecipientMXID != r.audience || event.RoomID != r.room || event.Topic != r.topic || event.Kind != "request" || !a2aContextText(event.EventID, '$') {
		return nil, ErrA2AContext
	}
	key, ok := r.keys[event.SenderMXID]
	if !ok || !key.active || len(r.grants[event.SenderMXID]) == 0 {
		return nil, ErrA2ANoGrant
	}
	q, sig, err := parseA2AEnvelope(event.Body)
	if err != nil {
		return nil, err
	}
	if q.sender != event.SenderMXID || q.audience != r.audience || q.room != r.room || q.topic != r.topic {
		return nil, ErrA2AContext
	}
	if q.registryHash != r.registryHash {
		return nil, ErrA2ARegistryPin
	}
	if now.IsZero() || now.Before(q.issuedAt) || !now.Before(q.expiresAt) {
		return nil, ErrA2ATerm
	}
	digest, _ := domainDigest(a2aRequestDomain, q.raw)
	if err := verifyP256Signature(key.public, digest, sig); err != nil {
		return nil, err
	}
	var chosen *a2aCertificate
	for _, c := range r.grants[event.SenderMXID] {
		if r.revoked[c.id] {
			continue
		}
		if now.Before(c.notBefore) || !now.Before(c.expiresAt) || q.issuedAt.Before(c.notBefore) || q.expiresAt.After(c.expiresAt) {
			continue
		}
		if chosen != nil {
			return nil, ErrA2AAmbiguousGrant
		}
		chosen = c
	}
	if chosen == nil {
		return nil, ErrA2ANoGrant
	}
	return &A2AVerifiedEnvelope{CertificateID: chosen.id, EntryID: chosen.entryID, SenderMXID: event.SenderMXID, Nonce: q.nonce, EventID: event.EventID,
		OwnerKeySHA256: chosen.issuer.keyID[7:], SubjectKeySHA256: hex.EncodeToString(key.hash[:]), RequestSHA256: hex.EncodeToString(sha256Sum(q.raw))}, nil
}
