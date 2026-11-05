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
	account := mugrant.Entry{Action: "account.manage", Target: mugrant.Target{Kind: "account-scope", ID: "owner:test-owner"}}
	current := grantSpec{root: w.root, use: mugrant.UseUntilExpiry, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: append(assign, account), nonceTag: "until-expiry"}
	once := grantSpec{root: w.root, use: mugrant.UseOnce, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: append(assign, account), nonceTag: "until-expiry"}
	expired := grantSpec{root: w.root, use: mugrant.UseUntilExpiry, nb: T0.Add(-31 * 24 * time.Hour), ex: T0.Add(-24 * time.Hour), entries: append(assign, account), nonceTag: "until-expiry"}
	foreign := grantSpec{root: w.other, use: mugrant.UseUntilExpiry, nb: T0.Add(-time.Hour), ex: T0.Add(30 * 24 * time.Hour), entries: append(assign, account), nonceTag: "until-expiry"}
	twin := current
	twin.nonceTag = "until-expiry-twin"

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
		AgentKey: w.agent.ID, AgentGeneration: 1, Owner: "owner:test-owner", RoomScope: "swarma-space", Modules: []string{"swarma-keyvault"},
		RegistryOwners: map[string]string{"@own-agent:interop.invalid": "owner:test-owner", "@other-owner-agent:interop.invalid": "owner:other"}}
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
	rWrongKey, err := req(w.stranger, "work.assign", "product", product, args, text, "accept")
	if err != nil {
		return nil, err
	}
	rAction, err := req(w.agent, "work.accept", "product", product, args, text, "accept")
	if err != nil {
		return nil, err
	}
	rTarget, err := req(w.agent, "work.assign", "product", "other-product", args, text, "accept")
	if err != nil {
		return nil, err
	}
	const accountText = "Retire an agent account"
	rIvan, err := req(w.agent, "account.manage", "account-scope", "owner:test-owner", map[string]string{"account": "@other-owner-agent:interop.invalid"}, accountText, "account")
	if err != nil {
		return nil, err
	}
	rOwn, err := req(w.agent, "account.manage", "account-scope", "owner:test-owner", map[string]string{"account": "@own-agent:interop.invalid"}, accountText, "account")
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
	type textCase struct{ id, claim, text string }
	var textCases []textCase
	for _, tc := range []textCase{
		{"nul", "NUL (U+0000)", "Assign\x00text"}, {"del", "DEL (U+007F)", "Assign\x7ftext"}, {"c1", "C1 control U+0085", "Assign\u0085text"},
		{"fffd", "U+FFFD", "Assign\ufffdtext"}, {"invalid-utf8", "invalid UTF-8", "Assign\xfftext"},
		{"blank", "only ASCII white space", "  \n\t "}, {"ideographic-space", "only non-ASCII white space (U+3000)", "\u3000\u3000"},
		{"bidi-061c", "U+061C", "Assign\u061ctext"}, {"bidi-200e", "U+200E", "Assign\u200etext"}, {"bidi-200f", "U+200F", "Assign\u200ftext"},
		{"bidi-202a", "U+202A", "Assign\u202atext"}, {"bidi-202b", "U+202B", "Assign\u202btext"}, {"bidi-202c", "U+202C", "Assign\u202ctext"},
		{"bidi-202d", "U+202D", "Assign\u202dtext"}, {"bidi-202e", "U+202E", "Assign\u202etext"}, {"bidi-2066", "U+2066", "Assign\u2066text"},
		{"bidi-2067", "U+2067", "Assign\u2067text"}, {"bidi-2068", "U+2068", "Assign\u2068text"}, {"bidi-2069", "U+2069", "Assign\u2069text"},
	} {
		textCases = append(textCases, tc)
	}
	gTwin, err := w.grant(twin)
	if err != nil {
		return nil, err
	}
	mut := map[string]func(map[string]any){
		"audience":  func(b map[string]any) { b["aud"] = "other-receiver" },
		"room":      func(b map[string]any) { b["room"] = "!other-room:interop.invalid" },
		"recipient": func(b map[string]any) { b["to"] = "@other-receiver:interop.invalid" },
		"lifetime":  func(b map[string]any) { b["exp"] = stamp(T0.Add(-time.Second + 121*time.Second)) },
	}
	mutatedReq := map[string][]byte{}
	for name, m := range mut {
		if mutatedReq[name], err = w.mutated(rAccept, m); err != nil {
			return nil, err
		}
	}
	older, err := w.snapshot(T0.Add(-30*time.Second), nil)
	if err != nil {
		return nil, err
	}
	rootRevP, err := mugrant.BuildSnapshot(w.root.ID, T0.Add(-10*time.Minute), []mugrant.SnapshotEntry{{Kind: "record", ID: grantID, From: stamp(T0.Add(-10 * time.Minute))}})
	if err != nil {
		return nil, err
	}
	rootRev, err := w.root.Sign(rootRevP)
	if err != nil {
		return nil, err
	}
	rootRecords := records(gCurrent)
	rootRecords.RootRevocations = []string{B64(rootRev)}
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
		one("M-P-account-own-owner", "account.manage on an account the owner holds is admitted and executed once.", "",
			records(gCurrent), ev("$own-owner", rOwn, accountText), fresh, "succeeded"),
		one("M-N-account-other-owner", "account.manage on an account another owner holds refuses by owner scope before any reservation; only the account argument differs from the positive control.", "M-P-account-own-owner",
			records(gCurrent), ev("$other-owner", rIvan, accountText), fresh, "mu-request-out-of-owner-scope"),
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
		// Text rule, one class per case; each is signed (body_sha256 binds it).
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
		{Format: Format, ID: "M-N-snapshot-older", Claim: "A publisher snapshot older than one already accepted refuses as rollback, even though it is under 60 s old and drops nothing.", PositiveControl: "M-P-until-expiry-second-use",
			Pins: pins, Records: records(gCurrent), Events: []Event{ev("$first", rAccept, text), ev("$second", rSecond, text)},
			Steps: []Step{{Event: "$first", Now: now, Snapshot: B64(fresh), Expected: "succeeded"}, {Event: "$second", Now: later, Snapshot: B64(older), Expected: "mu-revocation-snapshot-rollback"}}},
		one("M-N-root-revoked", "An owner-root revocation in the receiver's protected configuration revokes the grant at any age, while the fresh publisher snapshot does not list it.", "M-P-accept",
			rootRecords, ev("$root-revoked", rAccept, text), fresh, "mu-grant-revoked"),
		{Format: Format, ID: "M-N-snapshot-rollback", Claim: "A newer publisher snapshot that drops a revocation the receiver already holds refuses as rollback.", PositiveControl: "M-P-accept",
			Pins: pins, Records: records(gCurrent), Events: []Event{ev("$first", rAccept, text), ev("$second", rSecond, text)},
			Steps: []Step{{Event: "$first", Now: now, Snapshot: B64(withEntry), Expected: "succeeded"}, {Event: "$second", Now: later, Snapshot: B64(fresh), Expected: "mu-revocation-snapshot-rollback"}}},
	}
	for _, m := range []struct{ name, id, claim, code string }{
		{"audience", "M-N-audience-mismatch", "A signed request for another audience refuses.", "audience_mismatch"},
		{"room", "M-N-room-mismatch", "A signed request naming another room than the delivering room refuses.", "message_room_mismatch"},
		{"recipient", "M-N-recipient-mismatch", "A signed request addressed to another recipient refuses.", "message_recipient_mismatch"},
		{"lifetime", "M-N-lifetime-over-120s", "A signed request with exp - iat of 121 s refuses as malformed.", "envelope_malformed"},
	} {
		cases = append(cases, one(m.id, m.claim, "M-P-accept", records(gCurrent), ev("$"+m.name, mutatedReq[m.name], text), fresh, m.code))
	}
	cases = append(cases,
		one("M-N-ambiguous-grant", "Two pinned grants that both cover the request make grant selection refuse as ambiguous.", "M-P-accept",
			records(gCurrent, gTwin), ev("$ambiguous", rAccept, text), fresh, "mu-ambiguous-grant"),
		one("M-N-text-rule-before-hash", "Text that breaks the text rule and also differs from body_sha256 refuses on the text rule, which runs first.", "M-P-accept",
			records(gCurrent), ev("$order", rAccept, "Assign: interop acceptance\r\nsecond line"), fresh, "mu-request-text-refused"))
	for _, tc := range textCases {
		r, err := w.rehashed(rAccept, tc.text)
		if err != nil {
			return nil, err
		}
		cases = append(cases, one("M-N-text-"+tc.id, "Event text containing "+tc.claim+" refuses on receipt even when the signed body_sha256 binds it.", "M-P-accept",
			records(gCurrent), ev("$text-"+tc.id, r, tc.text), fresh, "mu-request-text-refused"))
	}
	return cases, nil
}

// mutated re-signs the request's body by the agent after mutate: a
// well-signed request carrying one fact the builder would refuse.
func (w *world) mutated(valid []byte, mutate func(map[string]any)) ([]byte, error) {
	v, err := record.Parse(valid, mugrant.MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, err
	}
	body := v.(map[string]any)["body"].(map[string]any)
	mutate(body)
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
