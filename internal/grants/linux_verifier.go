package grants

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// LinuxRegistryAgent is a current protected registry result, not event input.
// Keymaker generation and master epoch are strings; Mac generation is int64.
// MXID is the registry mapping of (UID, RegistrationNumber).
type LinuxRegistryAgent struct {
	Key, MXID                            string
	UID, RegistrationNumber              int64
	Generation, MasterEpoch, Owner, Path string
	Active                               bool
}

func (a LinuxRegistryAgent) binding() map[string]any {
	return map[string]any{"uid": a.UID, "registration_number": a.RegistrationNumber,
		"generation": a.Generation, "master_epoch": a.MasterEpoch, "owner": a.Owner, "path": a.Path, "active": a.Active}
}

// LinuxSnapshot comes from a protected snapshot source. RollbackSafe requires
// durable monotonic-union validation by that source; a valid signature alone
// never establishes continuity. The adapter fixes maximum age to 60 seconds.
type LinuxSnapshot struct {
	Wire                    []byte
	Available, RollbackSafe bool
}

// LinuxEvidenceSource is an in-process port for the existing registry by-ID
// evidence and snapshot sources. No transport or remote API is defined here.
// Implementations must authenticate/protect these results independently of an
// incoming request, and refresh CurrentAgent on every invocation.
type LinuxEvidenceSource interface {
	Attestation(contentID string) ([]byte, error)
	CurrentAgent(key string) (LinuxRegistryAgent, error)
	Snapshot(root string) (LinuxSnapshot, error)
}

// LinuxVerificationState must be sampled from a qualified trusted clock and
// durable state. No availability, continuity or trust is inferred from now.
// VerificationState must independently resolve assurance for the exact request
// hash (all zero for issuance-only identity checks); missing assurance refuses
// grants requiring A2. Attested agent identity alone establishes only A1.
type LinuxVerificationState struct {
	Now, AuthorityUntil, Watermark                         time.Time
	Trusted, Fresh, WatermarkAvailable, IDJournalAvailable bool
	IDJournal                                              map[string][]byte
	// Assurance is independent protected request-bound session evidence.
	// Keymaker author identity establishes only A1; it never implies A2.
	Assurance verifier.Evidence
}
type LinuxStateSource interface {
	VerificationState(requestHash [32]byte) (LinuxVerificationState, error)
}

// LinuxVerifierConfig is protected installation policy, never caller/event
// trust. RoomID is an exact !room ID; #swarma-grant-revocation is provisioning
// metadata only and does not occur in request verification.
type LinuxVerifierConfig struct {
	GrantRoot, ServiceRoot, AgentRevocationRoot string
	PublisherKey                                string
	Publisher                                   []byte
	Audience, RoomID, ReceiverMXID              string
	Grants                                      [][]byte
	MacAgents                                   map[string]MUMacAgent // protected current generation by MXID
	// LinuxAgents pins each sender's registry identity independently of current
	// generation evidence. A Linux sender requires this protected MXID mapping;
	// neither CurrentAgent nor the request may supply its own identity pin.
	LinuxAgents map[string]MULinuxAgent
}

// LinuxVerifier delegates all crypto, CCJ, profiles and grant authorization to
// the pinned ENV verifier. It returns a candidate for durable receiver admission.
type LinuxVerifier struct {
	config   LinuxVerifierConfig
	evidence LinuxEvidenceSource
	state    LinuxStateSource
	events   func(room, eventID string) (MUEnvelopeEvent, error)
}

var _ MUVerifier = (*LinuxVerifier)(nil)

// LinuxVerifiedDecision carries the exact snapshot sequence marks alongside a
// candidate. Every mark comes from a snapshot accepted by the pinned verifier
// in the same call, keyed by its protected signer. No mark is accepted durably
// here: the receiver must compare and persist them under its admission lock.
// VerifiedSnapshots is separate from candidate metadata: a request refusal
// returns no candidate or accepted marks, but retains authenticated observations.
type LinuxVerifiedDecision struct {
	Decision      MUDecision
	SnapshotMarks map[string]time.Time
	// SnapshotEntries retains each signer's entries from that same verified sample.
	SnapshotEntries map[string][]MURevocation
	// VerifiedSnapshots are independently signature-checked from the same source
	// reads, even when the request refuses. They never authorize an effect.
	VerifiedSnapshots []LinuxVerifiedSnapshot
}

// NewLinuxVerifier copies policy so a later caller mutation cannot replace pins.
// Source implementations remain protected dependencies, not received evidence.
func NewLinuxVerifier(c LinuxVerifierConfig, evidence LinuxEvidenceSource, state LinuxStateSource, events func(string, string) (MUEnvelopeEvent, error)) (*LinuxVerifier, error) {
	seen := map[string]bool{}
	for _, k := range []string{c.GrantRoot, c.ServiceRoot, c.AgentRevocationRoot, c.PublisherKey} {
		if record.ValidateKey(k) != nil || seen[k] {
			return nil, ErrMUState
		}
		seen[k] = true
	}
	if !strings.HasPrefix(c.GrantRoot, "p256:") || !linuxVerifierToken(c.Audience) || !linuxVerifierRoom(c.RoomID) || !linuxVerifierMXID(c.ReceiverMXID) || evidence == nil || state == nil {
		return nil, ErrMUState
	}
	pub, err := mugrant.VerifyPublisherAttestation(c.Publisher, c.GrantRoot)
	if err != nil || pub.Key != c.PublisherKey {
		return nil, ErrMUState
	}
	c.Publisher = bytes.Clone(c.Publisher)
	grants := make([][]byte, len(c.Grants))
	for i, g := range c.Grants {
		grants[i] = bytes.Clone(g)
	}
	c.Grants = grants
	agents := make(map[string]MUMacAgent, len(c.MacAgents))
	for mxid, a := range c.MacAgents {
		a.Attestation = bytes.Clone(a.Attestation)
		agents[mxid] = a
	}
	c.MacAgents = agents
	linuxAgents := make(map[string]MULinuxAgent, len(c.LinuxAgents))
	for mxid, a := range c.LinuxAgents {
		if _, overlap := c.MacAgents[mxid]; overlap {
			return nil, ErrMUState
		}
		linuxAgents[mxid] = a
	}
	c.LinuxAgents = linuxAgents
	return &LinuxVerifier{c, evidence, state, events}, nil
}

func linuxVerifierToken(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
func linuxVerifierRoom(s string) bool {
	return strings.HasPrefix(s, "!") && len(s) > 1 && linuxVerifierToken(s)
}
func linuxVerifierMXID(s string) bool {
	local, server, ok := strings.Cut(strings.TrimPrefix(s, "@"), ":")
	return strings.HasPrefix(s, "@") && ok && local != "" && server != "" && linuxVerifierToken(s)
}
func linuxVerifierRefuse(code string) error { return &ErrMUPlatform{Code: code} }

// Verify bridges the legacy receiver port with exact room/event/body custody.
// It omits r4 sequence metadata; new receiver integrations use VerifyWithSnapshots.
func (p *LinuxVerifier) Verify(ev MUEvent, now time.Time) (MUDecision, error) {
	result, err := p.VerifyWithSnapshots(ev, now)
	return result.Decision, err
}

// VerifyWithSnapshots is the exact-projection MUVerifier bridge with the r4
// snapshot metadata required for durable receiver admission.
func (p *LinuxVerifier) VerifyWithSnapshots(ev MUEvent, now time.Time) (LinuxVerifiedDecision, error) {
	if p == nil || p.events == nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	pe, err := p.events(ev.RoomID, ev.EventID)
	// Text refusal precedes every other request admission check (r2).
	if !mugrant.RequestTextAdmissible(pe.Text) {
		return LinuxVerifiedDecision{}, linuxVerifierRefuse("mu-request-text-refused")
	}
	if err != nil || pe.Sender != ev.SenderMXID || pe.Room != ev.RoomID || pe.EventID != ev.EventID || !bytes.Equal(pe.Envelope, ev.Envelope) {
		return LinuxVerifiedDecision{}, ErrMUProjection
	}
	return p.VerifyProjectedWithSnapshots(pe, now)
}

func (p *LinuxVerifier) context(now time.Time, requestHash [32]byte) (verifier.Context, error) {
	var c verifier.Context
	if p == nil || p.state == nil || p.evidence == nil {
		return c, ErrMUState
	}
	s, err := p.state.VerificationState(requestHash)
	if err != nil || s.Now.IsZero() || now.IsZero() || !s.Now.Equal(now) || !linuxVerificationJournalFits(s.IDJournal) {
		return c, linuxVerifierRefuse("time_unavailable")
	}
	// Preserve exact evidence: the pinned verifier refuses fractional wire
	// instants rather than accepting a value rounded into its time window.
	c.Assurance = s.Assurance
	journal := map[string]any{}
	for id, wire := range s.IDJournal {
		journal[id] = wire
	}
	// A nil journal is unavailable even if a provider accidentally sets the flag.
	values := []struct {
		dst *verifier.Evidence
		v   any
	}{
		{&c.Audience, p.config.Audience}, {&c.RequiredRoles, []any{"author"}},
		{&c.GrantRoot, p.config.GrantRoot},
		{&c.ServiceRoot, map[string]any{"key": p.config.ServiceRoot, "purpose": int64(5)}},
		{&c.AgentRevocationRoot, map[string]any{"key": p.config.AgentRevocationRoot, "purpose": "registry-revocation", "attestation_root": p.config.ServiceRoot}},
		{&c.GrantRevocationPublisher, p.config.Publisher},
		{&c.DeviceAttestations, map[string]any{}},
		{&c.Time, map[string]any{"trusted": s.Trusted, "fresh": s.Fresh, "authority_until": s.AuthorityUntil.UTC().Format(time.RFC3339Nano)}},
		{&c.Now, s.Now.UTC().Format(time.RFC3339Nano)}, {&c.WatermarkAvailable, s.WatermarkAvailable}, {&c.Watermark, s.Watermark.UTC().Format(time.RFC3339Nano)},
		{&c.IDJournalAvailable, s.IDJournalAvailable && s.IDJournal != nil}, {&c.IDJournal, journal},
	}
	for _, v := range values {
		e, err := verifier.Present(v.v)
		if err != nil {
			return verifier.Context{}, ErrMUState
		}
		*v.dst = e
	}
	return c, nil
}

// authorContext fetches the exact signed reference and current protected
// registry result independently. No fallback to another attestation is allowed.
func (p *LinuxVerifier) authorContext(c *verifier.Context, key, reference, sender string) (LinuxRegistryAgent, error) {
	if record.ValidateKey(key) != nil || !record.IsContentID(reference) {
		return LinuxRegistryAgent{}, linuxVerifierRefuse("key_binding_invalid")
	}
	identity, linux := p.config.LinuxAgents[sender]
	mac, isMac := p.config.MacAgents[sender]
	if !linux && !isMac {
		return LinuxRegistryAgent{}, ErrMUSender
	}
	var raw []byte
	var active map[string]any
	var agent LinuxRegistryAgent
	if linux {
		if identity.Key == "" {
			return agent, linuxVerifierRefuse("key_binding_unavailable")
		}
		if !strings.HasPrefix(key, "ed25519:") {
			return agent, linuxVerifierRefuse("key_binding_invalid")
		}
		if identity.Key != key {
			return agent, ErrMUSender
		}
		var err error
		agent, err = p.evidence.CurrentAgent(identity.Key)
		if err != nil || agent.Key != identity.Key || agent.UID != identity.UID || agent.RegistrationNumber != identity.RegistrationNumber {
			return agent, linuxVerifierRefuse("key_binding_unavailable")
		}
		if agent.MXID != sender || !linuxVerifierMXID(agent.MXID) {
			return agent, ErrMUSender
		}
		if !agent.Active {
			return agent, linuxVerifierRefuse("key_binding_invalid")
		}
		raw, err = p.evidence.Attestation(reference)
		if err != nil {
			return agent, linuxVerifierRefuse("key_binding_unavailable")
		}
		active = agent.binding()
	} else {
		if mac.Key != key {
			return agent, ErrMUSender
		}
		id, err := muRecordID(mac.Attestation, "attestation/1")
		if err != nil || id != reference {
			return agent, linuxVerifierRefuse("key_binding_invalid")
		}
		raw = mac.Attestation
		active = map[string]any{"profile": "mac-se-1", "mxid": sender, "generation": mac.Generation, "active": true}
	}
	values := []struct {
		dst *verifier.Evidence
		v   any
	}{
		{&c.AdmittedKeys, []any{key}}, {&c.Attestations, map[string]any{reference: raw}},
		{&c.AgentAttestationIDs, map[string]any{key: reference}}, {&c.CurrentGenerations, map[string]any{key: active}},
	}
	for _, v := range values {
		e, err := verifier.Present(v.v)
		if err != nil {
			return agent, ErrMUState
		}
		*v.dst = e
	}
	return agent, nil
}

func (p *LinuxVerifier) snapshots(c *verifier.Context, linux bool, observed *[]LinuxVerifiedSnapshot) (map[string][]byte, error) {
	roots := []string{p.config.PublisherKey}
	if linux {
		roots = append(roots, p.config.AgentRevocationRoot)
	}
	all := map[string]any{}
	wires := map[string][]byte{}
	unavailable := false
	for _, root := range roots {
		s, err := p.evidence.Snapshot(root)
		if err != nil || !s.Available {
			// A missing root refuses admission, but cannot prevent observation
			// of another signer's independently verified snapshot.
			unavailable = true
			continue
		}
		wire := bytes.Clone(s.Wire)
		all[root] = map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": s.RollbackSafe, "snapshot": wire}
		wires[root] = wire
		if sn, err := linuxVerifiedSnapshot(wire, root); err == nil {
			*observed = append(*observed, sn)
		}
	}
	if unavailable {
		return nil, linuxVerifierRefuse("revocation_unavailable")
	}
	e, err := verifier.Present(all)
	if err != nil {
		return nil, ErrMUState
	}
	c.SignedSnapshots = e
	return wires, nil
}

// VerifyProjected admits the authenticated projection, current author evidence
// and one exact pinned grant. Sources must be resolved afresh at effect admission.
// Durable monotonic revocations, root overrides, replay and accounting remain
// the receiver's responsibility; the returned decision is never an effect permit.
// This legacy port omits r4 sequence metadata; use VerifyProjectedWithSnapshots
// for an r4 receiver integration.
func (p *LinuxVerifier) VerifyProjected(pe MUEnvelopeEvent, now time.Time) (MUDecision, error) {
	result, err := p.VerifyProjectedWithSnapshots(pe, now)
	return result.Decision, err
}

// VerifyProjectedWithSnapshots returns one atomic candidate and the issued_at
// marks of all snapshots used. Integration must preserve these marks; acceptance
// alone does not establish durable highwater or revocation continuity.
func (p *LinuxVerifier) VerifyProjectedWithSnapshots(pe MUEnvelopeEvent, now time.Time) (result LinuxVerifiedDecision, retErr error) {
	var observed []LinuxVerifiedSnapshot
	defer func() { result.VerifiedSnapshots = observed }()
	if !mugrant.RequestTextAdmissible(pe.Text) {
		return LinuxVerifiedDecision{}, linuxVerifierRefuse("mu-request-text-refused")
	}
	if p == nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	if pe.Room != p.config.RoomID || pe.Receiver != p.config.ReceiverMXID || !linuxVerifierMXID(pe.Sender) || !a2aContextText(pe.EventID, '$') {
		return LinuxVerifiedDecision{}, ErrMUProjection
	}
	body, err := muMessageBody(pe.Envelope)
	if err != nil {
		return LinuxVerifiedDecision{}, err
	}
	key, reference := strOr(body["author"]), strOr(body["author_attestation"])
	c, err := p.context(now, sha256.Sum256(pe.Envelope))
	if err != nil {
		return LinuxVerifiedDecision{}, err
	}
	_, isLinux := p.config.LinuxAgents[pe.Sender]
	snapshots, err := p.snapshots(&c, isLinux, &observed)
	if err != nil {
		return LinuxVerifiedDecision{}, err
	}
	if _, err = p.authorContext(&c, key, reference, pe.Sender); err != nil {
		return LinuxVerifiedDecision{}, err
	}
	c.Delivery, err = verifier.Present(map[string]any{"room": pe.Room, "to": pe.Receiver, "text": pe.Text})
	if err != nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	v := verifier.New(c)
	if r := v.VerifyMessage(pe.Envelope); r.Code != "accept" {
		return LinuxVerifiedDecision{}, linuxVerifierRefuse(r.Code)
	}
	target, _ := body["target"].(map[string]any)
	action, kind, id := strOr(body["action"]), strOr(target["kind"]), strOr(target["id"])
	argsRaw, ok := body["arguments"].(map[string]any)
	if !ok {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	args := map[string]string{}
	for k, x := range argsRaw {
		s, ok := x.(string)
		if !ok {
			return LinuxVerifiedDecision{}, ErrMUState
		}
		args[k] = s
	}
	grant, err := muSelectGrant(p.config.Grants, key, action, kind, id)
	if err != nil {
		return LinuxVerifiedDecision{}, err
	}
	req, err := verifier.Present(map[string]any{"key": key, "action": action, "target": target})
	if err != nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	r := v.Authorize([][]byte{grant}, req)
	if r.Code != "accept" {
		return LinuxVerifiedDecision{}, linuxVerifierRefuse(r.Code)
	}
	if err := muOnceScope(grant, r.Plan.Use); err != nil {
		return LinuxVerifiedDecision{}, err
	}
	if r.Plan.Use != mugrant.UseOnce && r.Plan.Use != mugrant.UseUntilExpiry {
		return LinuxVerifiedDecision{}, linuxVerifierRefuse("grant_use_missing")
	}
	grantID, err := muRecordID(grant, "grant/1")
	if err != nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	expires, err := time.Parse(time.RFC3339, strOr(body["exp"]))
	if err != nil {
		return LinuxVerifiedDecision{}, ErrMUState
	}
	marks := make(map[string]time.Time, len(snapshots))
	bySigner := make(map[string][]MURevocation, len(snapshots))
	for signer, raw := range snapshots {
		envelope, err := muParseEnvelope(raw)
		if err != nil {
			return LinuxVerifiedDecision{}, ErrMUState
		}
		body, _ := envelope["body"].(map[string]any)
		at, err := time.Parse(time.RFC3339, strOr(body["issued_at"]))
		if err != nil {
			return LinuxVerifiedDecision{}, ErrMUState
		}
		marks[signer] = at.UTC()
		verifiedEntries, err := muSnapshotEntries(raw)
		if err != nil {
			return LinuxVerifiedDecision{}, ErrMUState
		}
		bySigner[signer] = linuxUniqueRevocations(verifiedEntries)
	}
	agentSigner := ""
	if isLinux {
		agentSigner = p.config.AgentRevocationRoot
	}
	return LinuxVerifiedDecision{SnapshotMarks: marks, SnapshotEntries: bySigner, Decision: MUDecision{GrantRoot: p.config.GrantRoot, GrantID: grantID, Use: r.Plan.Use, Author: key, Audience: p.config.Audience, Nonce: strOr(body["nonce"]), Action: action, TargetKind: kind, TargetID: id, Arguments: args, AuthorAttestation: reference, PublisherKey: p.config.PublisherKey, SnapshotMarks: marks, AgentRevocationKey: agentSigner, AgentRevocations: bySigner[p.config.AgentRevocationRoot], Revocations: bySigner[p.config.PublisherKey], Expires: expires, RequestHash: sha256.Sum256(pe.Envelope)}}, nil
}

// AdmitLinuxGrantee is the issuer-side D3 identity gate. It verifies a current
// exact Keymaker attestation and registry identity at issuance, not coverage of
// the future grant interval. The Mac issuer still owns publisher interval
// coverage, owner rendering/presence and grant assembly; no signing occurs here.
func (p *LinuxVerifier) AdmitLinuxGrantee(key, reference, mxid string, uid, registrationNumber int64, now time.Time) (LinuxRegistryAgent, error) {
	if !strings.HasPrefix(key, "ed25519:") {
		return LinuxRegistryAgent{}, linuxVerifierRefuse("key_binding_invalid")
	}
	c, err := p.context(now, [32]byte{})
	if err != nil {
		return LinuxRegistryAgent{}, err
	}
	a, err := p.authorContext(&c, key, reference, mxid)
	if err == ErrMUSender {
		// Issuance is an identity gate, not receipt of an authenticated event.
		return LinuxRegistryAgent{}, linuxVerifierRefuse("key_binding_invalid")
	}
	if err != nil {
		return LinuxRegistryAgent{}, err
	}
	if a.UID != uid || a.RegistrationNumber != registrationNumber {
		return LinuxRegistryAgent{}, linuxVerifierRefuse("key_binding_invalid")
	}
	var observed []LinuxVerifiedSnapshot
	if _, err = p.snapshots(&c, true, &observed); err != nil {
		return LinuxRegistryAgent{}, err
	}
	if _, err = verifier.New(c).VerifyAttestation(key, reference, false); err != nil {
		return LinuxRegistryAgent{}, err
	}
	return a, nil
}

// linuxVerifiedSnapshot uses the pinned verifier's static shape and evidence
// bound, including on refusals. Publisher sorting/from-order obligations do not
// decide whether an authenticated observation joins the durable union (r7).
func linuxVerifiedSnapshot(raw []byte, signer string) (LinuxVerifiedSnapshot, error) {
	sn, err := muVerifiedSnapshot(raw, signer)
	if err != nil {
		return LinuxVerifiedSnapshot{}, err
	}
	v := LinuxVerifiedSnapshot{Signer: signer, IssuedAt: sn.IssuedAt, Entries: linuxUniqueRevocations(sn.Entries)}
	if !validLinuxSnapshot(v) {
		return LinuxVerifiedSnapshot{}, ErrMUState
	}
	return v, nil
}

// Repeated entries remain verified observations (r7); durable identity unions
// store each kind/id once, independently of publisher ordering and from times.
func linuxUniqueRevocations(entries []MURevocation) []MURevocation {
	seen := map[MURevocation]bool{}
	out := make([]MURevocation, 0, len(entries))
	for _, entry := range entries {
		if !seen[entry] {
			out = append(out, entry)
			seen[entry] = true
		}
	}
	return out
}
