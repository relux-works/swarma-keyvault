package muinterop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"strings"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// foreignSigned assembles the plan's record with a signature by k under the
// plan's declared key: a record whose signature does not verify.
func foreignSigned(k *Key, keyID string, p *mugrant.Plan) ([]byte, error) {
	d := p.Digest()
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	if err != nil {
		return nil, err
	}
	raw, ok := mugrant.NativeP256Raw(der)
	if !ok {
		return nil, errBuild
	}
	body, err := record.Parse(p.Body(), mugrant.MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, err
	}
	return record.Canonical(map[string]any{"version": "swarm-envelope/2", "id": p.ContentID(), "body": body,
		"signatures": []any{map[string]any{"key": keyID, "role": "author", "sig": B64(raw[:])}}})
}

// MacFamily builds the Mac-issued, Mac-authored family: every case a Linux
// verifier must judge exactly as the Mac receiver does. Each negative differs
// from its positive control in one fact.
func MacFamily() ([]Case, error) {
	w, err := newWorld()
	if err != nil {
		return nil, err
	}
	assign := []mugrant.Entry{{Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: product}}}
	account := mugrant.Entry{Action: "account.manage", Target: mugrant.Target{Kind: "account-scope", ID: "owner:alexis"}}
	current := grantSpec{root: w.root, use: mugrant.UseUntilExpiry, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: append(assign, account), nonceTag: "until-expiry"}
	once := grantSpec{root: w.root, use: mugrant.UseOnce, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: assign, nonceTag: "once"}
	expired := grantSpec{root: w.root, use: mugrant.UseUntilExpiry, nb: T0.Add(-31 * 24 * time.Hour), ex: T0.Add(-24 * time.Hour), entries: assign, nonceTag: "expired"}
	foreign := grantSpec{root: w.other, use: mugrant.UseUntilExpiry, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: assign, nonceTag: "foreign"}

	agentAtt, publisherAtt, err := w.attestations(w.root)
	if err != nil {
		return nil, err
	}
	attID, err := contentID(agentAtt)
	if err != nil {
		return nil, err
	}
	fresh, err := w.snapshot(T0.Add(-5*time.Second), nil)
	if err != nil {
		return nil, err
	}
	stale, err := w.snapshot(T0.Add(-61*time.Second), nil)
	if err != nil {
		return nil, err
	}
	pins := Pins{GrantRoot: w.root.ID, Audience: audience, PublisherKey: w.publisher.ID, Room: room, ReceiverMXID: receiverMXID, SenderMXID: senderMXID,
		AgentKey: w.agent.ID, AgentGeneration: 1, Owner: "owner:alexis", RoomScope: "swarma-space", Modules: []string{"swarma-keyvault"},
		RegistryOwners: map[string]string{"@own-agent:interop.invalid": "owner:alexis", "@other-owner-agent:interop.invalid": "owner:other"}}
	records := func(grants ...[]byte) Records {
		r := Records{AgentAttestation: B64(agentAtt), PublisherAttestation: B64(publisherAtt)}
		for _, g := range grants {
			r.Grants = append(r.Grants, B64(g))
		}
		return r
	}
	args := map[string]string{"module": "swarma-keyvault", "title": "Interop acceptance"}
	const text = "Assign: interop acceptance\nsecond line"
	ev := func(id string, env []byte, text string) Event {
		return Event{ID: id, Envelope: B64(env), Text: B64([]byte(text))}
	}
	req := func(signer *Key, action, kind, id string, a map[string]string, text, tag string) ([]byte, error) {
		return w.request(signer, attID, action, kind, id, a, text, tag, T0.Add(-time.Second))
	}

	gCurrent, err := w.grant(current)
	if err != nil {
		return nil, err
	}
	gOnce, err := w.grant(once)
	if err != nil {
		return nil, err
	}
	gExpired, err := w.grant(expired)
	if err != nil {
		return nil, err
	}
	gForeign, err := w.grant(foreign)
	if err != nil {
		return nil, err
	}
	rAccept, err := req(w.agent, "work.assign", "product", product, args, text, "accept")
	if err != nil {
		return nil, err
	}
	rSecond, err := req(w.agent, "work.assign", "product", product, args, text, "second")
	if err != nil {
		return nil, err
	}
	rWrongKey, err := req(w.stranger, "work.assign", "product", product, args, text, "wrong-key")
	if err != nil {
		return nil, err
	}
	rAction, err := req(w.agent, "work.accept", "product", product, args, text, "wrong-action")
	if err != nil {
		return nil, err
	}
	rTarget, err := req(w.agent, "work.assign", "product", "other-product", args, text, "wrong-target")
	if err != nil {
		return nil, err
	}
	rIvan, err := req(w.agent, "account.manage", "account-scope", "owner:alexis", map[string]string{"account": "@other-owner-agent:interop.invalid"}, "Retire an account another owner holds", "other-owner")
	if err != nil {
		return nil, err
	}
	grantID, err := contentID(gCurrent)
	if err != nil {
		return nil, err
	}
	revoking, err := w.snapshot(T0.Add(-5*time.Second), []mugrant.SnapshotEntry{{Kind: "record", ID: grantID, From: stamp(T0.Add(-time.Minute))}})
	if err != nil {
		return nil, err
	}
	otherEntry := []mugrant.SnapshotEntry{{Kind: "record", ID: "sha256:" + hexDigest([]byte("unrelated record")), From: stamp(T0.Add(-time.Hour))}}
	withEntry, err := w.snapshot(T0.Add(-30*time.Second), otherEntry)
	if err != nil {
		return nil, err
	}
	limitText := strings.Repeat("я", (mugrant.MaxRequestText-4)/2) + "\nend"
	if len(limitText) != mugrant.MaxRequestText {
		return nil, errBuild
	}
	rLimit, err := req(w.agent, "work.assign", "product", product, args, limitText, "limit")
	if err != nil {
		return nil, err
	}
	overText := limitText + "!"
	rOver, err := w.rehashed(rLimit, overText)
	if err != nil {
		return nil, err
	}
	crText := "Assign: interop acceptance\r\nsecond line"
	rCR, err := w.rehashed(rAccept, crText)
	if err != nil {
		return nil, err
	}
	now := stamp(T0)
	later := stamp(T0.Add(20 * time.Second))
	one := func(id, claim, control string, r Records, e Event, snap []byte, expected string) Case {
		return Case{Format: Format, ID: id, Claim: claim, PositiveControl: control, Pins: pins, Records: r, Events: []Event{e},
			Steps: []Step{{Event: e.ID, Now: now, Snapshot: B64(snap), Expected: expected}}}
	}
	cases := []Case{
		one("M-P-accept", "An in-scope work.assign by the attested Mac agent under a current until_expiry grant is accepted and executed once.", "",
			records(gCurrent), ev("$accept", rAccept, text), fresh, "succeeded"),
		one("M-N-wrong-key", "A request whose signature does not verify under the author key refuses before any grant check.", "M-P-accept",
			records(gCurrent), ev("$wrong-key", rWrongKey, text), fresh, "envelope_signature_invalid"),
		one("M-N-wrong-action", "An action the grant does not list finds no applicable grant.", "M-P-accept",
			records(gCurrent), ev("$wrong-action", rAction, text), fresh, "mu-no-applicable-grant"),
		one("M-N-wrong-target", "A target the grant does not list finds no applicable grant.", "M-P-accept",
			records(gCurrent), ev("$wrong-target", rTarget, text), fresh, "mu-no-applicable-grant"),
		one("M-N-account-other-owner", "account.manage on an account another owner holds refuses by owner scope before any reservation.", "M-P-accept",
			records(gCurrent), ev("$other-owner", rIvan, "Retire an account another owner holds"), fresh, "mu-request-out-of-owner-scope"),
		one("M-N-expired", "A grant whose interval ended before the trusted time refuses.", "M-P-accept",
			records(gExpired), ev("$expired", rAccept, text), fresh, "expired"),
		one("M-N-revoked", "A fresh publisher snapshot that revokes the grant refuses the request.", "M-P-accept",
			records(gCurrent), ev("$revoked", rAccept, text), revoking, "revoked"),
		one("M-N-foreign-domain", "A grant issued by another root has no binding evidence under this receiver's pinned grant root and refuses.", "M-P-accept",
			records(gForeign), ev("$foreign", rAccept, text), fresh, "key_binding_unavailable"),
		one("M-N-stale-snapshot", "A publisher snapshot 61 s old refuses (at the author attestation evidence check, which reads the same snapshot first): there is no grace period.", "M-P-accept",
			records(gCurrent), ev("$stale", rAccept, text), stale, "key_binding_unavailable"),
		one("M-P-text-at-limit", "Event text of exactly 4096 bytes of valid UTF-8 is admitted.", "",
			records(gCurrent), ev("$limit", rLimit, limitText), fresh, "succeeded"),
		one("M-N-text-over-limit", "Event text of 4097 bytes refuses on receipt even when the signed body_sha256 binds it.", "M-P-text-at-limit",
			records(gCurrent), ev("$over", rOver, overText), fresh, "mu-request-text-refused"),
		one("M-N-text-cr", "Event text containing CR refuses on receipt even when the signed body_sha256 binds it.", "M-P-accept",
			records(gCurrent), ev("$cr", rCR, crText), fresh, "mu-request-text-refused"),
		one("M-N-body-hash", "Delivered text that differs from the signed body_sha256 refuses.", "M-P-accept",
			records(gCurrent), ev("$text", rAccept, text+" (edited)"), fresh, "message_text_mismatch"),
		{Format: Format, ID: "M-N-replay", Claim: "The same request event handled twice executes once; the second refuses on the held nonce.", PositiveControl: "M-P-accept",
			Pins: pins, Records: records(gCurrent), Events: []Event{ev("$accept", rAccept, text)},
			Steps: []Step{{Event: "$accept", Now: now, Snapshot: B64(fresh), Expected: "succeeded"}, {Event: "$accept", Now: later, Snapshot: B64(fresh), Expected: "mu-request-nonce-already-held"}}},
		{Format: Format, ID: "M-N-use-refill", Claim: "A once grant used by one request is not refilled by a second request with a new nonce.", PositiveControl: "M-P-until-expiry-second-use",
			Pins: pins, Records: records(gOnce), Events: []Event{ev("$first", rAccept, text), ev("$second", rSecond, text)},
			Steps: []Step{{Event: "$first", Now: now, Snapshot: B64(fresh), Expected: "succeeded"}, {Event: "$second", Now: later, Snapshot: B64(fresh), Expected: "mu-grant-use-already-held"}}},
		{Format: Format, ID: "M-P-until-expiry-second-use", Claim: "An until_expiry grant admits a second request with a new nonce.", Pins: pins, Records: records(gCurrent),
			Events: []Event{ev("$first", rAccept, text), ev("$second", rSecond, text)},
			Steps:  []Step{{Event: "$first", Now: now, Snapshot: B64(fresh), Expected: "succeeded"}, {Event: "$second", Now: later, Snapshot: B64(fresh), Expected: "succeeded"}}},
		{Format: Format, ID: "M-N-snapshot-rollback", Claim: "A newer publisher snapshot that drops a revocation the receiver already holds refuses as rollback.", PositiveControl: "M-P-accept",
			Pins: pins, Records: records(gCurrent), Events: []Event{ev("$first", rAccept, text), ev("$second", rSecond, text)},
			Steps: []Step{{Event: "$first", Now: now, Snapshot: B64(withEntry), Expected: "succeeded"}, {Event: "$second", Now: later, Snapshot: B64(fresh), Expected: "mu-revocation-snapshot-rollback"}}},
	}
	return cases, nil
}

// rehashed re-signs the request's body by the agent with body_sha256 bound
// to text: a well-signed request carrying text the requester rule forbids.
func (w *world) rehashed(valid []byte, text string) ([]byte, error) {
	v, err := record.Parse(valid, mugrant.MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, err
	}
	body := v.(map[string]any)["body"].(map[string]any)
	body["body_sha256"] = hexDigest([]byte(text))
	raw, err := record.Canonical(body)
	if err != nil {
		return nil, err
	}
	p, err := mugrant.Prepare("message/1", w.agent.ID, raw)
	if err != nil {
		return nil, err
	}
	return w.agent.Sign(p)
}

func contentID(wire []byte) (string, error) {
	v, err := record.Parse(wire, mugrant.MaxEnvelopeBytes, 16)
	if err != nil {
		return "", err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "", errBuild
	}
	id, _ := m["id"].(string)
	if id == "" {
		return "", errBuild
	}
	return id, nil
}
