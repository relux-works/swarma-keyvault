package muinterop

import (
	"crypto/x509"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// PublisherEd25519Family builds the Mac-authored family under an Ed25519
// grant revocation publisher (profile grant-revocation-2), appointed by the
// owner grant root: the publisher a signing service holds on Linux. Each
// negative differs from P2-P-accept in one fact.
func PublisherEd25519Family() ([]Case, error) {
	w, err := newWorld()
	if err != nil {
		return nil, err
	}
	pub, err := Ed25519("publisher-ed25519")
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
	nb, ex := T0.Add(-60*24*time.Hour), T0.Add(300*24*time.Hour)
	ap, _, err := mugrant.BuildMacAgentAttestation(w.root.ID, w.agent.SPKI, senderMXID, 1, nb, ex)
	if err != nil {
		return nil, err
	}
	agentAtt, err := w.root.Sign(ap)
	if err != nil {
		return nil, err
	}
	attID, err := contentID(agentAtt)
	if err != nil {
		return nil, err
	}
	pubSPKI, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		return nil, err
	}
	pp, _, err := mugrant.BuildEd25519PublisherAttestation(w.root.ID, pubSPKI, nb, ex)
	if err != nil {
		return nil, err
	}
	pubAtt, err := w.root.Sign(pp)
	if err != nil {
		return nil, err
	}
	// The same body with a grant-revocation-2 binding over the P-256 publisher,
	// signed by the root: profile and algorithm do not belong together.
	p1, _, err := mugrant.BuildPublisherAttestation(w.root.ID, w.publisher.SPKI, nb, ex)
	if err != nil {
		return nil, err
	}
	mixedBody, err := recordParse(p1.Body())
	if err != nil {
		return nil, err
	}
	mixed := mixedBody.(map[string]any)
	mixed["binding"] = map[string]any{"profile": "grant-revocation-2", "domain": w.root.ID}
	mixedRaw, err := recordCanonical(mixed)
	if err != nil {
		return nil, err
	}
	mp, err := mugrant.Prepare("attestation/1", w.root.ID, mixedRaw)
	if err != nil {
		return nil, err
	}
	mixedAtt, err := w.root.Sign(mp)
	if err != nil {
		return nil, err
	}
	// The grant-revocation-2 attestation issued and signed by the signing
	// service root instead of the owner grant root.
	svcBody, err := recordParse(pp.Body())
	if err != nil {
		return nil, err
	}
	svc := svcBody.(map[string]any)
	svc["issuer"] = service.ID
	svcRaw, err := recordCanonical(svc)
	if err != nil {
		return nil, err
	}
	sp, err := mugrant.PrepareEd25519("attestation/1", service.ID, svcRaw)
	if err != nil {
		return nil, err
	}
	serviceAtt, err := service.Sign(sp)
	if err != nil {
		return nil, err
	}

	assign := []mugrant.Entry{{Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: product}}}
	nonce := hexDigest([]byte("publisher-ed25519 grant nonce"))
	g, err := mugrant.BuildGrant(mugrant.GrantSpec{Issuer: w.root.ID, Subject: w.agent.ID, SubjectMXID: senderMXID, SubjectAttestation: agentAtt,
		PublisherAttestation: pubAtt, Audience: audience, Entries: assign,
		NotBefore: T0.Add(-time.Hour), Expires: T0.Add(30 * 24 * time.Hour), Use: mugrant.UseUntilExpiry, Nonce: []byte(nonce[:16])})
	if err != nil {
		return nil, err
	}
	grant, err := w.root.Sign(g.Plan())
	if err != nil {
		return nil, err
	}
	grantID, err := contentID(grant)
	if err != nil {
		return nil, err
	}

	snapshot := func(at time.Time, entries []mugrant.SnapshotEntry) ([]byte, error) {
		p, err := mugrant.BuildSnapshot(pub.ID, at, entries)
		if err != nil {
			return nil, err
		}
		return pub.Sign(p)
	}
	fresh, err := snapshot(T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	older, err := snapshot(T0.Add(-30*time.Second), nil)
	if err != nil {
		return nil, err
	}
	revoking, err := snapshot(T0.Add(-5*time.Second), []mugrant.SnapshotEntry{{Kind: "record", ID: grantID, From: stamp(T0.Add(-time.Minute))}})
	if err != nil {
		return nil, err
	}
	fp, err := mugrant.BuildSnapshot(pub.ID, T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	foreignSigned, err := edForeignSigned(stranger, pub.ID, fp)
	if err != nil {
		return nil, err
	}
	p256Fresh, err := w.snapshot(T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}

	args := map[string]string{"module": "swarma-keyvault", "title": "Ed25519 publisher acceptance"}
	const text = "Assign: Ed25519 publisher acceptance"
	req := func(tag string) ([]byte, error) {
		return w.request(w.agent, attID, "work.assign", "product", product, args, text, tag, T0.Add(-time.Second))
	}
	rAccept, err := req("p2-accept")
	if err != nil {
		return nil, err
	}
	rSecond, err := req("p2-second")
	if err != nil {
		return nil, err
	}
	pins := Pins{GrantRoot: w.root.ID, Audience: audience, PublisherKey: pub.ID, Room: room, ReceiverMXID: receiverMXID, SenderMXID: senderMXID,
		AgentKey: w.agent.ID, AgentGeneration: 1, Owner: "owner:test-owner", RoomScope: "swarma-space", Modules: []string{"swarma-keyvault"},
		RegistryOwners: map[string]string{"@own-agent:interop.invalid": "owner:test-owner"}}
	p256Pins := pins
	p256Pins.PublisherKey = w.publisher.ID
	records := func(publisher []byte) Records {
		return Records{Grants: []string{B64(grant)}, AgentAttestation: B64(agentAtt), PublisherAttestation: B64(publisher)}
	}
	ev := func(id string, env []byte) Event { return Event{ID: id, Envelope: B64(env), Text: B64([]byte(text))} }
	now, later := stamp(T0), stamp(T0.Add(20*time.Second))
	one := func(id, claim, control string, p Pins, r Records, e Event, snap []byte, expected string) Case {
		return Case{Format: Format, ID: id, Claim: claim, PositiveControl: control, Pins: p, Records: r, Events: []Event{e},
			Steps: []Step{{Event: e.ID, Now: now, Snapshot: B64(snap), Expected: expected}}}
	}
	return []Case{
		one("P2-P-accept", "A Mac agent request under a grant whose revocation publisher is an Ed25519 key appointed by the owner grant root (grant-revocation-2) is accepted with that publisher's fresh snapshot.", "",
			pins, records(pubAtt), ev("$p2-accept", rAccept), fresh, "succeeded"),
		one("P2-N-revoked", "A fresh Ed25519 publisher snapshot that lists the grant revokes it.", "P2-P-accept",
			pins, records(pubAtt), ev("$p2-revoked", rAccept), revoking, "revoked"),
		one("P2-N-snapshot-foreign-signer", "A snapshot naming the Ed25519 publisher as issuer but signed by another Ed25519 key is refused. Entry point: VerifyMessage for a Mac author, where publisher evidence is resolved during agent-attestation intake and exposes the binding code.", "P2-P-accept",
			pins, records(pubAtt), ev("$p2-foreign", rAccept), foreignSigned, "key_binding_invalid"),
		one("P2-N-profile-2-p256-subject", "A root-signed publisher attestation of profile grant-revocation-2 over a P-256 key is refused at the publisher binding gate: profile and algorithm are bound. Entry point as P2-N-snapshot-foreign-signer.", "P2-P-accept",
			p256Pins, records(mixedAtt), ev("$p2-mixed", rAccept), p256Fresh, "key_binding_invalid"),
		one("P2-N-issued-by-service-root", "A grant-revocation-2 attestation issued and signed by the signing-service root instead of the owner grant root does not appoint a publisher; it is refused at the publisher binding gate. Entry point as P2-N-snapshot-foreign-signer.", "P2-P-accept",
			pins, records(serviceAtt), ev("$p2-service", rAccept), fresh, "key_binding_invalid"),
		{Format: Format, ID: "P2-N-snapshot-older", Claim: "An Ed25519 publisher snapshot older than one already accepted refuses as rollback, even though it is under 60 s old and drops nothing.", PositiveControl: "P2-P-accept",
			Pins: pins, Records: records(pubAtt), Events: []Event{ev("$p2-first", rAccept), ev("$p2-second", rSecond)},
			Steps: []Step{{Event: "$p2-first", Now: now, Snapshot: B64(fresh), Expected: "succeeded"}, {Event: "$p2-second", Now: later, Snapshot: B64(older), Expected: "mu-revocation-snapshot-rollback"}}},
	}, nil
}
