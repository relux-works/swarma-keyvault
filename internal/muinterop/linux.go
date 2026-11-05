package muinterop

import (
	"crypto/ed25519"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// EdKey is one published Ed25519 test key: the seed is SeedFor(name).
type EdKey struct {
	Name, ID string
	Seed     []byte
	Public   ed25519.PublicKey
	priv     ed25519.PrivateKey
}

// Ed25519 derives the named Ed25519 test key from its published seed.
func Ed25519(name string) (*EdKey, error) {
	seed := SeedFor(name)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	id, err := mugrant.Ed25519KeyID(pub)
	if err != nil {
		return nil, err
	}
	return &EdKey{Name: name, ID: id, Seed: seed, Public: pub, priv: priv}, nil
}

// Sign signs the plan's preimage and assembles the record.
func (k *EdKey) Sign(p *mugrant.Plan) ([]byte, error) {
	return mugrant.AssembleEd25519(p, ed25519.Sign(k.priv, p.Preimage()))
}

// EdKeyNames lists the published Ed25519 test keys.
var EdKeyNames = []string{"linux-agent", "linux-stranger", "keymaker-service-root", "agent-revocation"}

// LinuxPins are the receiver's protected configuration for Linux authors.
type LinuxPins struct {
	ServiceRoot        string `json:"service_root"`
	AgentRevocationKey string `json:"agent_revocation_key"`
	AgentMXID          string `json:"agent_mxid"`
	AgentKey           string `json:"agent_key"`
	UID                int64  `json:"uid"`
	RegistrationNumber int64  `json:"registration_number"`
}

// Registry is the registry evidence a Linux-author case supplies: the
// attestations it serves by content id and the current active generation.
type Registry struct {
	Attestations     map[string]string `json:"attestations"`
	ActiveGeneration ActiveGeneration  `json:"active_generation"`
}

// ActiveGeneration is the protected current active-generation evidence.
type ActiveGeneration struct {
	UID                int64  `json:"uid"`
	Generation         string `json:"generation"`
	RegistrationNumber int64  `json:"registration_number"`
	MasterEpoch        string `json:"master_epoch"`
	Owner              string `json:"owner"`
	Path               string `json:"path"`
}

func (a ActiveGeneration) binding() mugrant.KeymakerBinding {
	return mugrant.KeymakerBinding{UID: a.UID, Generation: a.Generation, RegistrationNumber: a.RegistrationNumber, MasterEpoch: a.MasterEpoch, Owner: a.Owner, Path: a.Path}
}

// Binding converts the evidence for a receiver.
func (a ActiveGeneration) Binding() mugrant.KeymakerBinding { return a.binding() }

const linuxMXID = "@linux-agent:interop.invalid"

// LinuxFamily builds the Linux-authored family: Mac-issued grants to an
// Ed25519 agent attested by the Keymaker service, and Ed25519-signed
// requests the Mac receiver must judge exactly as listed.
func LinuxFamily() ([]Case, error) {
	w, err := newWorld()
	if err != nil {
		return nil, err
	}
	agent, err := Ed25519("linux-agent")
	if err != nil {
		return nil, err
	}
	stranger, err := Ed25519("linux-stranger")
	if err != nil {
		return nil, err
	}
	service, err := Ed25519("keymaker-service-root")
	if err != nil {
		return nil, err
	}
	agentRev, err := Ed25519("agent-revocation")
	if err != nil {
		return nil, err
	}
	gen := ActiveGeneration{UID: 1000, Generation: "generation-1", RegistrationNumber: 7, MasterEpoch: "epoch-1", Owner: "owner:alexis", Path: "agents/linux-agent"}
	attest := func(nb, ex time.Time) ([]byte, string, error) {
		p, _, err := mugrant.BuildKeymakerAgentAttestation(service.ID, agent.Public, gen.binding(), nb, ex)
		if err != nil {
			return nil, "", err
		}
		wire, err := service.Sign(p)
		return wire, p.ContentID(), err
	}
	// Current at T0 (and at issuance); a later one for the expiry case.
	att, attID, err := attest(T0.Add(-2*time.Hour), T0.Add(20*time.Hour))
	if err != nil {
		return nil, err
	}
	_, publisherAtt, err := w.attestations(w.root)
	if err != nil {
		return nil, err
	}
	assign := []mugrant.Entry{{Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: product}}}
	nonce := hexDigest([]byte("linux grant nonce"))
	g, err := mugrant.BuildGrant(mugrant.GrantSpec{Issuer: w.root.ID, Subject: agent.ID, SubjectMXID: linuxMXID, SubjectAttestation: att,
		ServiceRoot: service.ID, SubjectRegistry: &mugrant.RegistryIdentity{MXID: linuxMXID, UID: gen.UID, RegistrationNumber: gen.RegistrationNumber}, IssuedAt: T0.Add(-time.Hour),
		PublisherAttestation: publisherAtt, Audience: audience, Entries: assign,
		NotBefore: T0.Add(-time.Hour), Expires: T0.Add(30 * 24 * time.Hour), Use: mugrant.UseUntilExpiry, Nonce: []byte(nonce[:16])})
	if err != nil {
		return nil, err
	}
	grant, err := w.root.Sign(g.Plan())
	if err != nil {
		return nil, err
	}
	args := map[string]string{"module": "swarma-keyvault", "title": "Linux interop acceptance"}
	const text = "Assign from Linux: interop acceptance"
	request := func(signer *EdKey, author, attestationID, action, tag string, at time.Time) ([]byte, error) {
		n := hexDigest([]byte("linux request nonce " + tag))
		r, err := mugrant.BuildRequest(mugrant.RequestSpec{Author: author, AuthorAttestation: attestationID, Audience: audience, Room: room, To: receiverMXID,
			Action: action, Target: mugrant.Target{Kind: "product", ID: product}, Arguments: args, Text: text, Nonce: []byte(n[:16]), IssuedAt: at, Lifetime: 120 * time.Second})
		if err != nil {
			return nil, err
		}
		if signer.ID == author {
			return signer.Sign(r.Plan())
		}
		return edForeignSigned(signer, author, r.Plan())
	}
	rAccept, err := request(agent, agent.ID, attID, "work.assign", "accept", T0.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	rWrongKey, err := request(stranger, agent.ID, attID, "work.assign", "wrong-key", T0.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	rAction, err := request(agent, agent.ID, attID, "work.accept", "wrong-action", T0.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	rSecondL, err := request(agent, agent.ID, attID, "work.assign", "second", T0.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	late := T0.Add(21 * time.Hour) // after the attestation, inside the grant
	rLate, err := request(agent, agent.ID, attID, "work.assign", "late", late.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	snap := func(k *EdKey, at time.Time, entries []mugrant.SnapshotEntry) ([]byte, error) {
		p, err := mugrant.BuildSnapshot(k.ID, at, entries)
		if err != nil {
			return nil, err
		}
		return k.Sign(p)
	}
	agentFresh, err := snap(agentRev, T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	agentStale, err := snap(agentRev, T0.Add(-61*time.Second), nil)
	if err != nil {
		return nil, err
	}
	agentRevoking, err := snap(agentRev, T0.Add(-5*time.Second), []mugrant.SnapshotEntry{{Kind: "key", ID: agent.ID, From: stamp(T0.Add(-time.Minute))}})
	if err != nil {
		return nil, err
	}
	agentOlder, err := snap(agentRev, T0.Add(-30*time.Second), nil)
	if err != nil {
		return nil, err
	}
	unrelatedKey := []mugrant.SnapshotEntry{{Kind: "key", ID: stranger.ID, From: stamp(T0.Add(-time.Hour))}}
	agentUnrelatedOld, err := snap(agentRev, T0.Add(-30*time.Second), unrelatedKey)
	if err != nil {
		return nil, err
	}
	// Cross-algorithm: the registry maps the Linux MXID to the Mac agent's
	// P-256 key and serves its mac-se-1 attestation.
	macAtt, _, err := w.attestations(w.root)
	if err != nil {
		return nil, err
	}
	macAttID, err := contentID(macAtt)
	if err != nil {
		return nil, err
	}
	macGrant, err := w.grant(grantSpec{root: w.root, use: mugrant.UseUntilExpiry, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: assign, nonceTag: "cross-algorithm"})
	if err != nil {
		return nil, err
	}
	macReq, err := w.request(w.agent, macAttID, "work.assign", "product", product, args, text, "cross-algorithm", T0.Add(-time.Second))
	if err != nil {
		return nil, err
	}
	pubFresh, err := w.snapshot(T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	pubLate, err := w.snapshot(late.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	agentLate, err := snap(agentRev, late.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	pins := Pins{GrantRoot: w.root.ID, Audience: audience, PublisherKey: w.publisher.ID, Room: room, ReceiverMXID: receiverMXID, SenderMXID: linuxMXID,
		Owner: "owner:alexis", RoomScope: "swarma-space", Modules: []string{"swarma-keyvault"}, RegistryOwners: map[string]string{},
		Linux: &LinuxPins{ServiceRoot: service.ID, AgentRevocationKey: agentRev.ID, AgentMXID: linuxMXID, AgentKey: agent.ID, UID: gen.UID, RegistrationNumber: gen.RegistrationNumber}}
	records := Records{Grants: []string{B64(grant)}, PublisherAttestation: B64(publisherAtt)}
	registry := func(served map[string][]byte, g ActiveGeneration) *Registry {
		r := &Registry{Attestations: map[string]string{}, ActiveGeneration: g}
		for id, b := range served {
			r.Attestations[id] = B64(b)
		}
		return r
	}
	served := map[string][]byte{attID: att}
	moved := gen
	moved.Generation = "generation-2"
	ev := func(id string, env []byte, t string) Event {
		return Event{ID: id, Envelope: B64(env), Text: B64([]byte(t))}
	}
	now, later := stamp(T0), stamp(T0.Add(20*time.Second))
	one := func(id, claim, control string, reg *Registry, sender string, e Event, at string, pub, agentSnap []byte, expected string) Case {
		p := pins
		p.SenderMXID = sender
		return Case{Format: Format, ID: id, Claim: claim, PositiveControl: control, Pins: p, Records: records, Registry: reg, Events: []Event{e},
			Steps: []Step{{Event: e.ID, Now: at, Snapshot: B64(pub), AgentSnapshot: B64(agentSnap), Expected: expected}}}
	}
	return []Case{
		one("L-P-accept", "An in-scope work.assign signed by the Keymaker-attested Linux agent under a Mac-issued until_expiry grant is accepted and executed once.", "",
			registry(served, gen), linuxMXID, ev("$l-accept", rAccept, text), now, pubFresh, agentFresh, "succeeded"),
		one("L-N-wrong-key", "A request whose Ed25519 signature is by another key refuses.", "L-P-accept",
			registry(served, gen), linuxMXID, ev("$l-wrong-key", rWrongKey, text), now, pubFresh, agentFresh, "envelope_signature_invalid"),
		one("L-N-wrong-action", "An action the grant does not list finds no applicable grant.", "L-P-accept",
			registry(served, gen), linuxMXID, ev("$l-wrong-action", rAction, text), now, pubFresh, agentFresh, "mu-no-applicable-grant"),
		one("L-N-attestation-expired", "A Linux request after its Keymaker attestation expired refuses even though the grant is still valid.", "L-P-accept",
			registry(served, gen), linuxMXID, ev("$l-late", rLate, text), stamp(late), pubLate, agentLate, "key_binding_invalid"),
		one("L-N-attestation-unavailable", "A request whose referenced attestation the registry does not serve refuses.", "L-P-accept",
			registry(nil, gen), linuxMXID, ev("$l-unavailable", rAccept, text), now, pubFresh, agentFresh, "key_binding_unavailable"),
		one("L-N-generation-moved", "A request whose attestation names a generation the registry no longer has active refuses.", "L-P-accept",
			registry(served, moved), linuxMXID, ev("$l-moved", rAccept, text), now, pubFresh, agentFresh, "key_binding_invalid"),
		one("L-N-agent-revoked", "A fresh agent revocation snapshot that revokes the agent key refuses.", "L-P-accept",
			registry(served, gen), linuxMXID, ev("$l-revoked", rAccept, text), now, pubFresh, agentRevoking, "revoked"),
		one("L-N-stale-agent-snapshot", "An agent revocation snapshot 61 s old refuses: there is no grace period.", "L-P-accept",
			registry(served, gen), linuxMXID, ev("$l-stale", rAccept, text), now, pubFresh, agentStale, "key_binding_unavailable"),
		one("L-N-sender-not-registered", "An event from an MXID with no registry identity refuses before verification.", "L-P-accept",
			registry(served, gen), "@unregistered:interop.invalid", ev("$l-sender", rAccept, text), now, pubFresh, agentFresh, "mu-sender-not-attested"),
		{Format: Format, ID: "L-N-agent-revoked-then-older", Claim: "An agent revocation snapshot that refused a request is remembered: a later, older agent snapshot without the entry does not let the key act.", PositiveControl: "L-P-accept",
			Pins: pins, Records: records, Registry: registry(served, gen), Events: []Event{ev("$l-first", rAccept, text), ev("$l-second", rSecondL, text)},
			Steps: []Step{{Event: "$l-first", Now: now, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentRevoking), Expected: "revoked"},
				{Event: "$l-second", Now: later, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentOlder), Expected: "mu-grant-revoked"}}},
		{Format: Format, ID: "L-N-agent-revoked-then-equal", Claim: "An agent revocation snapshot that refused a request is remembered: an agent snapshot with the same issued_at but without the entry does not let the key act.", PositiveControl: "L-P-accept",
			Pins: pins, Records: records, Registry: registry(served, gen), Events: []Event{ev("$l-first", rAccept, text), ev("$l-second", rSecondL, text)},
			Steps: []Step{{Event: "$l-first", Now: now, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentRevoking), Expected: "revoked"},
				{Event: "$l-second", Now: later, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentFresh), Expected: "mu-grant-revoked"}}},
		func() Case {
			c := one("L-N-registry-uid-mismatch", "A registry identity whose uid differs from the current active generation refuses.", "L-P-accept",
				registry(served, gen), linuxMXID, ev("$l-uid", rAccept, text), now, pubFresh, agentFresh, "key_binding_unavailable")
			l := *c.Pins.Linux
			l.UID = gen.UID + 1
			c.Pins.Linux = &l
			return c
		}(),
		func() Case {
			c := one("L-N-cross-algorithm", "A Linux registry identity that names a P-256 Mac agent key refuses. Its referenced attestation is a mac-se-1 attestation issued by the grant root, not a Keymaker attestation by the service root, and the Keymaker active-generation evidence does not fit that profile.", "L-P-accept",
				registry(map[string][]byte{macAttID: macAtt}, gen), linuxMXID, ev("$l-cross", macReq, text), now, pubFresh, agentFresh, "key_binding_invalid")
			l := *c.Pins.Linux
			l.AgentKey = w.agent.ID
			c.Pins.Linux = &l
			c.Records = Records{Grants: []string{B64(macGrant)}, PublisherAttestation: records.PublisherAttestation}
			return c
		}(),
		{Format: Format, ID: "L-N-agent-rollback-drops-unrelated", Claim: "A newer agent revocation snapshot that drops an entry its signer published before, here an unrelated key, refuses as rollback.", PositiveControl: "L-P-accept",
			Pins: pins, Records: records, Registry: registry(served, gen), Events: []Event{ev("$l-first", rAccept, text), ev("$l-second", rSecondL, text)},
			Steps: []Step{{Event: "$l-first", Now: now, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentUnrelatedOld), Expected: "succeeded"},
				{Event: "$l-second", Now: later, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentFresh), Expected: "mu-revocation-snapshot-rollback"}}},
		{Format: Format, ID: "L-N-agent-rollback-older-mark", Claim: "An agent revocation snapshot older than one already accepted refuses as rollback, even though it revokes nothing and is under 60 s old.", PositiveControl: "L-P-accept",
			Pins: pins, Records: records, Registry: registry(served, gen), Events: []Event{ev("$l-first", rAccept, text), ev("$l-second", rSecondL, text)},
			Steps: []Step{{Event: "$l-first", Now: now, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentFresh), Expected: "succeeded"},
				{Event: "$l-second", Now: later, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentOlder), Expected: "mu-revocation-snapshot-rollback"}}},
		{Format: Format, ID: "L-N-replay", Claim: "The same Linux request event handled twice executes once; the second refuses on the held nonce.", PositiveControl: "L-P-accept",
			Pins: pins, Records: records, Registry: registry(served, gen), Events: []Event{ev("$l-accept", rAccept, text)},
			Steps: []Step{{Event: "$l-accept", Now: now, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentFresh), Expected: "succeeded"},
				{Event: "$l-accept", Now: later, Snapshot: B64(pubFresh), AgentSnapshot: B64(agentFresh), Expected: "mu-request-nonce-already-held"}}},
	}, nil
}

func edForeignSigned(k *EdKey, keyID string, p *mugrant.Plan) ([]byte, error) {
	body, err := recordParse(p.Body())
	if err != nil {
		return nil, err
	}
	return recordCanonical(map[string]any{"version": "swarm-envelope/2", "id": p.ContentID(), "body": body,
		"signatures": []any{map[string]any{"key": keyID, "role": "author", "sig": B64(ed25519.Sign(k.priv, p.Preimage()))}}})
}
