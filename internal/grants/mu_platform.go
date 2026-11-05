package grants

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// ErrMUPlatform carries a platform verifier refusal code.
type ErrMUPlatform struct{ Code string }

func (e *ErrMUPlatform) Error() string { return "mu-platform-refused: " + e.Code }

// MUMacAgent is one pinned Mac agent: its owner-root attestation and the
// current generation the owner registered for it.
type MUMacAgent struct {
	Key         string // p256 key id
	Attestation []byte // raw attestation/1 (profile mac-se-1)
	Generation  int64
}

// MUPlatformConfig is the receiver's pinned trust configuration for the
// platform verifier. Every field comes from protected local configuration,
// never from the event.
type MUPlatformConfig struct {
	GrantRoot     string
	Audience      string
	Grants        [][]byte              // pinned owner-signed grant/1 envelopes
	Agents        map[string]MUMacAgent // by full MXID (registry index only)
	Publisher     []byte                // raw publisher attestation (grant-revocation-1)
	PublisherKey  string
	Snapshot      func() ([]byte, error) // latest publisher snapshot bytes
	TimeAuthority time.Duration          // how long the local clock is asserted trusted
	// Linux agents (contract D1/D4): Ed25519 keys attested by the Keymaker
	// signing service; evidence comes from the registry, by id.
	Linux    map[string]MULinuxAgent // by full MXID (registry identity)
	Registry MURegistryEvidence
}

// MULinuxAgent is the registry identity of a Linux (Ed25519) agent.
type MULinuxAgent struct {
	Key                     string // ed25519 key id
	UID, RegistrationNumber int64
}

// MURegistryEvidence supplies the protected Keymaker evidence for Linux
// authors. Every source is consulted per request; an error refuses.
type MURegistryEvidence struct {
	ServiceRoot        string                                            // Keymaker signing-service root (purpose 5)
	AgentRevocationKey string                                            // registry revocation key for agent keys
	Attestation        func(contentID string) ([]byte, error)            // exact attestation bytes by id
	ActiveGeneration   func(key string) (mugrant.KeymakerBinding, error) // current active generation of the key
	AgentSnapshot      func() ([]byte, error)                            // latest agent revocation snapshot
}

// MUEnvelopeEvent is the a2a envelope projection of one authenticated event.
type MUEnvelopeEvent struct {
	Sender, Receiver, Room, EventID string
	Envelope, Text                  []byte
}

// MUPlatform adapts swarma-envelope's verifier to MUVerifier.
type MUPlatform struct {
	config MUPlatformConfig
	events func(eventID string) (MUEnvelopeEvent, error)
}

// NewMUPlatform builds the adapter. events resolves an event id to its
// authenticated projection (the pinned a2a read).
func NewMUPlatform(c MUPlatformConfig, events func(string) (MUEnvelopeEvent, error)) *MUPlatform {
	return &MUPlatform{config: c, events: events}
}

func muEvidence(v any) (verifier.Evidence, error) { return verifier.Present(v) }

// Verify checks the projected event with VerifyMessage, selects the single
// covering pinned grant by author, runs Authorize, and returns the decision
// with the verified publisher snapshot's entries.
func (p *MUPlatform) Verify(ev MUEvent, now time.Time) (MUDecision, error) {
	if p == nil || p.events == nil || p.config.Snapshot == nil {
		return MUDecision{}, ErrMUState
	}
	pe, err := p.events(ev.EventID)
	if err != nil || pe.Sender != ev.SenderMXID || pe.EventID != ev.EventID || pe.Room == "" {
		return MUDecision{}, ErrMUState
	}
	agent, mac := p.config.Agents[pe.Sender]
	linux, isLinux := p.config.Linux[pe.Sender]
	if !mac && !isLinux {
		return MUDecision{}, ErrMUSender
	}
	// The same text rule the requester enforces before signing, so both
	// sides admit exactly the same requests (interop contract §2.2).
	if !mugrant.RequestTextAdmissible(pe.Text) {
		return MUDecision{}, ErrMUText
	}
	snap, err := p.config.Snapshot()
	if err != nil {
		return MUDecision{}, &ErrMUPlatform{"revocation_unavailable"}
	}
	revocations := map[string]any{p.config.PublisherKey: map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": snap}}
	var linuxRoots map[string]any
	var agentSnapBytes []byte
	var (
		authorKey, attID string
		attestation      []byte
		active           map[string]any
	)
	if mac {
		authorKey, attestation = agent.Key, agent.Attestation
		if attID, err = muRecordID(attestation, "attestation/1"); err != nil {
			return MUDecision{}, ErrMUState
		}
		// The MXID is filled from the authenticated sender, never the request.
		active = map[string]any{"profile": "mac-se-1", "mxid": pe.Sender, "generation": agent.Generation, "active": true}
	} else {
		reg := p.config.Registry
		if reg.Attestation == nil || reg.ActiveGeneration == nil || reg.AgentSnapshot == nil || reg.ServiceRoot == "" || reg.AgentRevocationKey == "" {
			return MUDecision{}, ErrMUState
		}
		body, err := muMessageBody(pe.Envelope)
		if err != nil {
			return MUDecision{}, err
		}
		// The attestation is resolved by the signed content id, never as
		// "the current attestation for this key".
		attID, _ = body["author_attestation"].(string)
		authorKey = linux.Key
		if attestation, err = reg.Attestation(attID); err != nil {
			return MUDecision{}, &ErrMUPlatform{"key_binding_unavailable"}
		}
		gen, err := reg.ActiveGeneration(linux.Key)
		if err != nil || gen.UID != linux.UID || gen.RegistrationNumber != linux.RegistrationNumber {
			return MUDecision{}, &ErrMUPlatform{"key_binding_unavailable"}
		}
		active = gen.Map()
		active["active"] = true
		agentSnap, err := reg.AgentSnapshot()
		if err != nil {
			return MUDecision{}, &ErrMUPlatform{"revocation_unavailable"}
		}
		agentSnapBytes = agentSnap
		revocations[reg.AgentRevocationKey] = map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": agentSnap}
		linuxRoots = map[string]any{
			"service_root":          map[string]any{"key": reg.ServiceRoot, "purpose": int64(5)},
			"agent_revocation_root": map[string]any{"attestation_root": reg.ServiceRoot, "key": reg.AgentRevocationKey, "purpose": "registry-revocation"},
		}
	}
	nowText := now.UTC().Format("2006-01-02T15:04:05Z")
	facts := map[string]any{
		"audience": p.config.Audience, "required_roles": []any{"author"}, "known_keys": []any{authorKey},
		"root": p.config.GrantRoot, "attestations": map[string]any{attID: attestation},
		"agent_attestation_ids": map[string]any{authorKey: attID},
		"active_generations":    map[string]any{authorKey: active},
		"revocations":           revocations,
		"time":                  map[string]any{"trusted": true, "fresh": true, "authority_until": now.UTC().Add(p.config.TimeAuthority).Format("2006-01-02T15:04:05Z")},
		"now":                   nowText, "watermark_available": true, "watermark": nowText,
		"id_journal_available": true, "seen": map[string]any{}, "replay_available": true, "used_actions": []any{},
		"assurance": map[string]any{"level": "A2", "presence": false},
		// No operator devices take part: an explicit empty collection, never absence.
		"operator_attestations": map[string]any{},
		"delivery":              map[string]any{"room": pe.Room, "to": pe.Receiver, "text": pe.Text},
	}
	for k, v := range linuxRoots {
		facts[k] = v
	}
	c, err := muContext(facts, p.config.Publisher)
	if err != nil {
		return MUDecision{}, ErrMUState
	}
	v := verifier.New(c)
	if r := v.VerifyMessage(pe.Envelope); r.Code != "accept" {
		return MUDecision{}, &ErrMUPlatform{r.Code}
	}
	body, err := muMessageBody(pe.Envelope)
	if err != nil {
		return MUDecision{}, err
	}
	target, _ := body["target"].(map[string]any)
	action, _ := body["action"].(string)
	kind, _ := target["kind"].(string)
	id, _ := target["id"].(string)
	author, _ := body["author"].(string)
	if author != authorKey {
		return MUDecision{}, ErrMUSender
	}
	grant, err := muSelectGrant(p.config.Grants, author, action, kind, id)
	if err != nil {
		return MUDecision{}, err
	}
	req, err := muEvidence(map[string]any{"key": author, "action": action, "target": map[string]any{"kind": kind, "id": id}})
	if err != nil {
		return MUDecision{}, ErrMUState
	}
	r := v.Authorize([][]byte{grant}, req)
	if r.Code != "accept" {
		return MUDecision{}, &ErrMUPlatform{r.Code}
	}
	args := map[string]string{}
	if a, ok := body["arguments"].(map[string]any); ok {
		for k, x := range a {
			s, ok := x.(string)
			if !ok {
				return MUDecision{}, ErrMUState
			}
			args[k] = s
		}
	}
	exp, err := time.Parse("2006-01-02T15:04:05Z", strOr(body["exp"]))
	if err != nil {
		return MUDecision{}, ErrMUState
	}
	grantID, err := muRecordID(grant, "grant/1")
	if err != nil {
		return MUDecision{}, ErrMUState
	}
	entries, err := muSnapshotEntries(snap)
	if err != nil {
		return MUDecision{}, ErrMUState
	}
	var agentKey string
	var agentEntries []MURevocation
	if agentSnapBytes != nil {
		agentKey = p.config.Registry.AgentRevocationKey
		if agentEntries, err = muSnapshotEntries(agentSnapBytes); err != nil {
			return MUDecision{}, ErrMUState
		}
	}
	marks := map[string]time.Time{}
	if marks[p.config.PublisherKey], err = muSnapshotIssuedAt(snap); err != nil {
		return MUDecision{}, ErrMUState
	}
	if agentSnapBytes != nil {
		if marks[p.config.Registry.AgentRevocationKey], err = muSnapshotIssuedAt(agentSnapBytes); err != nil {
			return MUDecision{}, ErrMUState
		}
	}
	nonce, _ := body["nonce"].(string)
	aud, _ := body["aud"].(string)
	return MUDecision{GrantRoot: p.config.GrantRoot, GrantID: grantID, Use: r.Plan.Use, Author: author, Audience: aud, Nonce: nonce,
		Action: action, TargetKind: kind, TargetID: id, Arguments: args, AuthorAttestation: attID, Expires: exp,
		RequestHash: sha256.Sum256(pe.Envelope), PublisherKey: p.config.PublisherKey, Revocations: entries, SnapshotMarks: marks,
		AgentRevocationKey: agentKey, AgentRevocations: agentEntries}, nil
}

func strOr(v any) string { s, _ := v.(string); return s }

func muContext(f map[string]any, publisher []byte) (verifier.Context, error) {
	var c verifier.Context
	slots := map[string]*verifier.Evidence{"audience": &c.Audience, "required_roles": &c.RequiredRoles, "known_keys": &c.AdmittedKeys, "root": &c.GrantRoot,
		"attestations": &c.Attestations, "agent_attestation_ids": &c.AgentAttestationIDs, "active_generations": &c.CurrentGenerations, "revocations": &c.SignedSnapshots,
		"time": &c.Time, "now": &c.Now, "watermark_available": &c.WatermarkAvailable, "watermark": &c.Watermark, "id_journal_available": &c.IDJournalAvailable,
		"seen": &c.IDJournal, "replay_available": &c.ReplayAvailable, "used_actions": &c.UsedActions, "assurance": &c.Assurance, "delivery": &c.Delivery,
		"operator_attestations": &c.DeviceAttestations}
	for name, slot := range slots {
		e, err := verifier.Present(f[name])
		if err != nil {
			return c, err
		}
		*slot = e
	}
	for name, slot := range map[string]*verifier.Evidence{"service_root": &c.ServiceRoot, "agent_revocation_root": &c.AgentRevocationRoot} {
		if v, ok := f[name]; ok {
			e, err := verifier.Present(v)
			if err != nil {
				return c, err
			}
			*slot = e
		}
	}
	if publisher != nil {
		e, err := verifier.Present(publisher)
		if err != nil {
			return c, err
		}
		c.GrantRevocationPublisher = e
	}
	return c, nil
}

func muParseEnvelope(raw []byte) (map[string]any, error) {
	p, err := record.Parse(raw, 65536, 16)
	if err != nil {
		return nil, ErrMUState
	}
	e, ok := p.(map[string]any)
	if !ok {
		return nil, ErrMUState
	}
	return e, nil
}

func muMessageBody(raw []byte) (map[string]any, error) {
	e, err := muParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	b, ok := e["body"].(map[string]any)
	if !ok || b["type"] != "message/1" {
		return nil, ErrMUState
	}
	return b, nil
}

func muRecordID(raw []byte, kind string) (string, error) {
	e, err := muParseEnvelope(raw)
	if err != nil {
		return "", err
	}
	b, ok := e["body"].(map[string]any)
	if !ok || b["type"] != kind {
		return "", ErrMUState
	}
	id, err := record.ContentID(kind, b)
	if err != nil || id != e["id"] {
		return "", errors.New("content id mismatch")
	}
	return id, nil
}

// muSnapshotEntries returns the entries of a snapshot the verifier already
// accepted in the same call.
// MUPlatform hands the receiver its verified snapshots before verification.
var _ MUSnapshotSource = (*MUPlatform)(nil)

// VerifiedSnapshots returns the snapshots this event would be judged against,
// each verified as an exact revocation/1 signed by its pinned signer: the
// publisher snapshot, and for a Linux author the agent revocation snapshot.
// A snapshot that does not verify is left out; verification then refuses.
func (p *MUPlatform) VerifiedSnapshots(ev MUEvent) ([]MUSnapshot, error) {
	if p == nil || p.config.Snapshot == nil {
		return nil, ErrMUState
	}
	var out []MUSnapshot
	if raw, err := p.config.Snapshot(); err == nil {
		if sn, err := muVerifiedSnapshot(raw, p.config.PublisherKey); err == nil {
			out = append(out, sn)
		}
	}
	if _, linux := p.config.Linux[ev.SenderMXID]; linux && p.config.Registry.AgentSnapshot != nil && p.config.Registry.AgentRevocationKey != "" {
		if raw, err := p.config.Registry.AgentSnapshot(); err == nil {
			if sn, err := muVerifiedSnapshot(raw, p.config.Registry.AgentRevocationKey); err == nil {
				out = append(out, sn)
			}
		}
	}
	return out, nil
}

// muVerifiedSnapshot admits a swarm-envelope/2 revocation/1 only when its
// issuer and single author signature are key and the content id matches.
func muVerifiedSnapshot(raw []byte, key string) (MUSnapshot, error) {
	e, err := muParseEnvelope(raw)
	if err != nil || len(e) != 4 || e["version"] != "swarm-envelope/2" {
		return MUSnapshot{}, ErrMUState
	}
	b, ok := e["body"].(map[string]any)
	sigs, _ := e["signatures"].([]any)
	if !ok || b["type"] != "revocation/1" || b["issuer"] != key || len(sigs) != 1 {
		return MUSnapshot{}, ErrMUState
	}
	sig, _ := sigs[0].(map[string]any)
	text, _ := sig["sig"].(string)
	raw64, err := record.DecodeBase64(text, 64)
	if err != nil || len(sig) != 3 || sig["key"] != key || sig["role"] != "author" {
		return MUSnapshot{}, ErrMUState
	}
	if id, err := record.ContentID("revocation/1", b); err != nil || id != e["id"] {
		return MUSnapshot{}, ErrMUState
	}
	pre, err := record.SigningPreimage("revocation/1", key, "author", b)
	if err != nil || record.VerifySignature(key, raw64, pre) != nil {
		return MUSnapshot{}, ErrMUState
	}
	entries, err := muSnapshotEntries(raw)
	if err != nil {
		return MUSnapshot{}, err
	}
	at, err := muSnapshotIssuedAt(raw)
	if err != nil {
		return MUSnapshot{}, err
	}
	return MUSnapshot{Signer: key, IssuedAt: at, Entries: entries}, nil
}

// muSnapshotIssuedAt returns a verified snapshot's issued_at.
func muSnapshotIssuedAt(raw []byte) (time.Time, error) {
	e, err := muParseEnvelope(raw)
	if err != nil {
		return time.Time{}, err
	}
	b, _ := e["body"].(map[string]any)
	text, _ := b["issued_at"].(string)
	t, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return time.Time{}, ErrMUState
	}
	return t.UTC(), nil
}

func muSnapshotEntries(raw []byte) ([]MURevocation, error) {
	e, err := muParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	b, _ := e["body"].(map[string]any)
	list, _ := b["entries"].([]any)
	out := []MURevocation{}
	for _, x := range list {
		m, _ := x.(map[string]any)
		kind, _ := m["kind"].(string)
		id, _ := m["id"].(string)
		r := MURevocation{kind, id}
		if !validMURevocation(r) {
			return nil, ErrMUState
		}
		out = append(out, r)
	}
	return out, nil
}
