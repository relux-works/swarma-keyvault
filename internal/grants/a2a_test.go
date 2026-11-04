package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type a2aFixture struct {
	owner, requester             *ecdsa.PrivateKey
	ownerDER, requesterDER       []byte
	certificate, request, action map[string]any
	keyRegistry, grantsRegistry  map[string]any
	now                          time.Time
}

func a2aHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Keys are ephemeral in-memory fixtures. No native store, process, network or
// deployment state participates in this public contract test.
func a2aFixtureForTest(t *testing.T) *a2aFixture {
	t.Helper()
	owner, ownerDER, _ := certificateSignatureFixture(t)
	requester, requesterDER, _ := certificateSignatureFixture(t)
	f := &a2aFixture{owner: owner, ownerDER: ownerDER, requester: requester, requesterDER: requesterDER,
		now: time.Date(2026, 11, 4, 14, 1, 0, 0, time.UTC)}
	f.action = map[string]any{"name": A2ARepository, "organization": LocalOrganization, "visibility": "private"}
	f.keyRegistry = map[string]any{"type": "grants-a2a-key-registry-1", "keys": map[string]any{
		"@requester:example.invalid": map[string]any{"generation": "1", "spki": base64.RawURLEncoding.EncodeToString(requesterDER), "spki_sha256": a2aHash(requesterDER), "status": "active"},
	}}
	f.certificate = map[string]any{
		"type": "grants-a2a-certificate-1", "audience": "@receiver:example.invalid", "certificate_id": "a2a-grant-A",
		"subject":    map[string]any{"account_mxid": "@requester:example.invalid", "spki_sha256": a2aHash(requesterDER)},
		"issuer":     map[string]any{"owner_mxid": "@owner:example.invalid", "purpose": "grants-owner-v1", "key_id": "sha256:" + a2aHash(ownerDER)},
		"not_before": "2026-11-04T14:00:00Z", "expires_at": "2026-11-04T14:30:00Z", "supersedes": []any{},
		"key_registry_sha256": a2aHash(requestTestBytes(t, f.keyRegistry)),
		"entries":             []any{map[string]any{"action": "repository.create", "entry_id": "create", "target": f.action, "use_count": "1"}},
	}
	f.request = map[string]any{
		"version": "grants-a2a-request-1", "sender_mxid": "@requester:example.invalid", "audience": "@receiver:example.invalid",
		"room_id": "!test:example.invalid", "topic": "test-grant", "action": "repository.create",
		"resource": "github:" + LocalOrganization + "/" + A2ARepository, "nonce": strings.Repeat("ab", 32),
		"issued_at": "2026-11-04T14:00:00Z", "expires_at": "2026-11-04T14:05:00Z",
		"request_sha256": a2aHash(requestTestBytes(t, f.action)), "grant_registry_sha256": strings.Repeat("00", 32),
	}
	return f
}

func a2aFixtureSignature(t *testing.T, key *ecdsa.PrivateKey, domain string, raw []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain+"\n"), raw...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Curve.Params().N, s)
	}
	result, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *a2aFixture) receiver(t *testing.T) (*A2AReceiver, A2AEvent) {
	t.Helper()
	keyRaw := requestTestBytes(t, f.keyRegistry)
	f.certificate["key_registry_sha256"] = a2aHash(keyRaw)
	certRaw := requestTestBytes(t, f.certificate)
	signed := requestTestBytes(t, map[string]any{"type": "grants-a2a-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(certRaw),
		"signature": base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-certificate/1", certRaw))})
	f.grantsRegistry = map[string]any{"type": "grants-a2a-grants-registry-1", "key_registry_sha256": a2aHash(keyRaw), "revoked": []any{},
		"grants": map[string]any{f.certificate["subject"].(map[string]any)["account_mxid"].(string): []any{base64.RawURLEncoding.EncodeToString(signed)}}}
	grantRaw := requestTestBytes(t, f.grantsRegistry)
	f.request["grant_registry_sha256"] = a2aHash(grantRaw)
	r, err := NewA2AReceiver(A2AReceiverConfig{OwnerMXID: "@owner:example.invalid", OwnerSPKIDER: f.ownerDER, Audience: "@receiver:example.invalid",
		RoomID: "!test:example.invalid", Topic: "test-grant", KeyRegistry: keyRaw, KeyRegistrySHA256: a2aHash(keyRaw), GrantRegistry: grantRaw, GrantRegistrySHA256: a2aHash(grantRaw)})
	if err != nil {
		t.Fatal(err)
	}
	return r, f.event(t)
}

// Existing legitimate full-MXID server forms remain accepted when independently
// enrolled. Exact matching does not turn a foreign same-localpart into a local
// account, nor reject all foreign accounts to avoid doing the binding check.
func TestA2AFullMXIDCompatibility(t *testing.T) {
	for _, account := range []string{"@requester:example.invalid", "@requester:foreign.invalid", "@requester:example.invalid:8448", "@requester:[2001:db8::1]:8448", "@requester:127.0.0.1:8448"} {
		t.Run(account, func(t *testing.T) {
			f := a2aFixtureForTest(t)
			keys := f.keyRegistry["keys"].(map[string]any)
			key := keys["@requester:example.invalid"]
			delete(keys, "@requester:example.invalid")
			keys[account] = key
			f.certificate["subject"].(map[string]any)["account_mxid"] = account
			f.request["sender_mxid"] = account
			r, e := f.receiver(t)
			e.SenderMXID = account
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("legitimate full sender", err)
			}
			e.SenderMXID = "requester"
			if _, err := r.Verify(e, f.now); !errors.Is(err, ErrA2ASenderUnavailable) {
				t.Fatal("alias accepted", err)
			}
		})
	}
}

// Even where two explicitly enrolled accounts share a public key, their grants
// do not authenticate each other's signed sender field. Removing this equality
// is the bounded checker-control plant exercised outside the working candidate.
func TestA2AActualSenderBindingWhenKeyIsShared(t *testing.T) {
	f := a2aFixtureForTest(t)
	keys := f.keyRegistry["keys"].(map[string]any)
	keys["@second:example.invalid"] = keys["@requester:example.invalid"]
	_, _ = f.receiver(t)
	f.certificate["certificate_id"] = "a2a-grant-B"
	f.certificate["subject"].(map[string]any)["account_mxid"] = "@second:example.invalid"
	raw := requestTestBytes(t, f.certificate)
	outer := requestTestBytes(t, map[string]any{"type": "grants-a2a-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(raw), "signature": base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-certificate/1", raw))})
	f.grantsRegistry["grants"].(map[string]any)["@second:example.invalid"] = []any{base64.RawURLEncoding.EncodeToString(outer)}
	r, err := NewA2AReceiver(a2aCurrentConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	f.request["grant_registry_sha256"] = a2aHash(requestTestBytes(t, f.grantsRegistry))
	e := f.event(t)
	if _, err := r.Verify(e, f.now); err != nil {
		t.Fatal("valid same-sender control", err)
	}
	e.SenderMXID = "@second:example.invalid"
	if _, err := r.Verify(e, f.now); !errors.Is(err, ErrA2AContext) {
		t.Fatal("sender substitution accepted; wanted context mismatch", err)
	}
}

func (f *a2aFixture) event(t *testing.T) A2AEvent {
	t.Helper()
	raw, action := requestTestBytes(t, f.request), requestTestBytes(t, f.action)
	body := requestTestBytes(t, map[string]any{"type": "grants-a2a-envelope-1", "payload": base64.RawURLEncoding.EncodeToString(raw), "request": base64.RawURLEncoding.EncodeToString(action),
		"signature": base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.requester, "swarma-grants/a2a-request/1", raw))})
	return A2AEvent{SenderMXID: "@requester:example.invalid", RecipientMXID: "@receiver:example.invalid", RoomID: "!test:example.invalid", Topic: "test-grant", Kind: "request", EventID: "$event-A", Body: body}
}

// Exact domains and copied immutable bytes match independently signed fixtures;
// the public result does not check use state or authorize provider dispatch.
func TestA2ARequestAndReceiverPositive(t *testing.T) {
	f := a2aFixtureForTest(t)
	r, event := f.receiver(t)
	got, err := r.Verify(event, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertificateID != "a2a-grant-A" || got.EntryID != "create" || got.Nonce != f.request["nonce"] {
		t.Fatal("lost identity", got)
	}
	p, err := PrepareA2ARequest(requestTestBytes(t, f.request), requestTestBytes(t, f.action))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte("swarma-grants/a2a-request/1\n"), requestTestBytes(t, f.request)...))
	if p.Digest() != want {
		t.Fatal("digest/domain changed")
	}
	sig := a2aFixtureSignature(t, f.requester, "swarma-grants/a2a-request/1", requestTestBytes(t, f.request))
	wire, err := p.SignedEnvelope(sig, f.requesterDER)
	if err != nil {
		t.Fatal(err)
	}
	event.Body = wire
	if _, err := r.Verify(event, f.now); err != nil {
		t.Fatal(err)
	}
	event.Body[0] = 'x'
	if _, err := r.Verify(f.event(t), f.now); err != nil {
		t.Fatal("caller mutation affected verifier", err)
	}
}

// Each forbidden request has an accepted neighbor and the intended refusal;
// none can be dispatched because this component has no state/provider/signer API.
func TestA2AReceiverRefusals(t *testing.T) {
	for _, mode := range []string{"short-sender", "other-server", "no-grant", "repost", "missing", "signature", "audience", "room", "topic", "recipient", "kind", "payload", "registry", "outside-action", "outside-resource", "future", "expired", "grant-expired", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			f := a2aFixtureForTest(t)
			r, event := f.receiver(t)
			if _, err := r.Verify(event, f.now); err != nil {
				t.Fatal("valid control", err)
			}
			want := ErrA2AContext
			now := f.now
			switch mode {
			case "short-sender":
				event.SenderMXID = "requester"
				want = ErrA2ASenderUnavailable
			case "other-server":
				event.SenderMXID = "@requester:another.invalid"
				want = ErrA2ANoGrant
			case "no-grant":
				event.SenderMXID = "@other:example.invalid"
				event.Body = []byte("plain request")
				want = ErrA2ANoGrant
			case "repost":
				event.SenderMXID = "@owner:example.invalid"
				want = ErrA2ANoGrant
			case "missing":
				event.Body = nil
				want = errBadEncoding
			case "signature":
				var v map[string]any
				json.Unmarshal(event.Body, &v)
				v["signature"] = base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-request/1", requestTestBytes(t, f.request)))
				event.Body = requestTestBytes(t, v)
				want = errSignatureInvalid
			case "audience":
				f.request["audience"] = "@else:example.invalid"
				event = f.event(t)
			case "room":
				event.RoomID = "!other:example.invalid"
			case "topic":
				event.Topic = "other"
			case "recipient":
				event.RecipientMXID = "@else:example.invalid"
			case "kind":
				event.Kind = "notice"
			case "payload":
				f.action["visibility"] = "public"
				event = f.event(t)
				want = errResourceMismatch
			case "registry":
				f.request["grant_registry_sha256"] = strings.Repeat("fe", 32)
				event = f.event(t)
				want = ErrA2ARegistryPin
			case "outside-action":
				f.request["action"] = "repository.delete"
				event = f.event(t)
				want = errResourceMismatch
			case "outside-resource":
				f.request["resource"] = f.request["resource"].(string) + "-other"
				event = f.event(t)
				want = errResourceMismatch
			case "future":
				now = f.now.Add(-2 * time.Minute)
				want = ErrA2ATerm
			case "expired":
				now = time.Date(2026, 11, 4, 14, 5, 0, 0, time.UTC)
				want = ErrA2ATerm
			case "grant-expired":
				now = time.Date(2026, 11, 4, 14, 30, 0, 0, time.UTC)
				want = ErrA2ATerm
			case "noncanonical":
				event.Body = append(event.Body, '\n')
				want = errBadEncoding
			}
			if _, err := r.Verify(event, now); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			if _, err := r.Verify(fixedA2AEvent(t, f, r), f.now); err != nil {
				t.Fatal("valid neighbor after refusal", err)
			}
		})
	}
}

func fixedA2AEvent(t *testing.T, old *a2aFixture, _ *A2AReceiver) A2AEvent {
	t.Helper()
	// Restore only request mutations; use the original registry/key fixture.
	fresh := a2aFixtureForTest(t)
	old.request["audience"] = fresh.request["audience"]
	old.request["action"] = fresh.request["action"]
	old.request["resource"] = fresh.request["resource"]
	old.request["grant_registry_sha256"] = a2aHash(requestTestBytes(t, old.grantsRegistry))
	old.action["visibility"] = "private"
	return old.event(t)
}

// Issuance and the reason are derived from one immutable typed payload. The
// complete scope, 16-hex key fingerprint and MSK interval survive unchanged;
// over-cap summaries refuse before any private signing API exists here.
func TestA2ACertificatePrompt(t *testing.T) {
	f := a2aFixtureForTest(t)
	raw := requestTestBytes(t, f.certificate)
	p, err := PrepareA2ACertificate(raw, "@owner:example.invalid", f.ownerDER, f.requesterDER)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := p.Prompt()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"CREATE private", LocalOrganization + "/" + A2ARepository, "@requester:example.invalid", a2aHash(f.requesterDER)[:16], "04.11.2026 17:00–17:30 MSK", hex.EncodeToString(p.digest[26:])} {
		if !strings.Contains(reason, part) {
			t.Fatal("missing reason scope", part, reason)
		}
	}
	if utf8.RuneCountInString(reason) > 200 {
		t.Fatal("over-cap reason released")
	}
	if !strings.Contains(p.Review(), string(raw)) || !strings.Contains(p.Review(), reason) {
		t.Fatal("full review not bound")
	}
	raw[0] = 'x'
	if p.Payload()[0] == 'x' {
		t.Fatal("mutable payload")
	}
	sig := a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-certificate/1", p.Payload())
	if _, err := p.SignedEnvelope(sig); err != nil {
		t.Fatal("owner signature positive", err)
	}
	if _, err := p.SignedEnvelope(a2aFixtureSignature(t, f.requester, "swarma-grants/a2a-certificate/1", p.Payload())); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("other signer", err)
	}
	f.certificate["subject"].(map[string]any)["account_mxid"] = "@" + strings.Repeat("a", 180) + ":example.invalid"
	if _, err := PrepareA2ACertificate(requestTestBytes(t, f.certificate), "@owner:example.invalid", f.ownerDER, f.requesterDER); !errors.Is(err, ErrA2APromptOverflow) {
		t.Fatal("overflow", err)
	}
}

// The helper cap is on Unicode scalars, not UTF-8 byte count; disallowed control
// or ill-formed input is refused rather than cleaned, clipped or re-signed.
func TestA2APromptBoundary(t *testing.T) {
	for _, n := range []int{199, 200, 201} {
		_, err := a2aCheckedReason(strings.Repeat("я", n))
		if (n <= 200 && err != nil) || (n > 200 && !errors.Is(err, ErrA2APromptOverflow)) {
			t.Fatalf("%d: %v", n, err)
		}
	}
	for _, s := range []string{"", "reason\nrest", "a\x00b", "reason\u202erest", string([]byte{0xff})} {
		if _, err := a2aCheckedReason(s); !errors.Is(err, ErrA2APromptOverflow) {
			t.Fatal("unsafe reason accepted", []byte(s), err)
		}
	}
}

// Non-minute and cross-midnight grant bounds are displayed exactly in MSK,
// without rounding a wider or narrower interval into the owner's reason.
func TestA2APromptExactSecondsAndDate(t *testing.T) {
	for _, tc := range []struct{ start, end, want string }{
		{"2026-11-04T14:00:30Z", "2026-11-04T14:05:45Z", "04.11.2026 17:00:30–17:05:45 MSK"},
		{"2026-11-04T20:50:00Z", "2026-11-04T21:10:00Z", "04.11.2026 23:50–05.11.2026 00:10 MSK"},
	} {
		f := a2aFixtureForTest(t)
		f.certificate["not_before"], f.certificate["expires_at"] = tc.start, tc.end
		p, err := PrepareA2ACertificate(requestTestBytes(t, f.certificate), "@owner:example.invalid", f.ownerDER, f.requesterDER)
		if err != nil {
			t.Fatal(err)
		}
		reason, err := p.Prompt()
		if err != nil || !strings.Contains(reason, tc.want) {
			t.Fatal("interval", reason, err)
		}
	}
}

func a2aCurrentConfig(t *testing.T, f *a2aFixture) A2AReceiverConfig {
	t.Helper()
	keys, grants := requestTestBytes(t, f.keyRegistry), requestTestBytes(t, f.grantsRegistry)
	return A2AReceiverConfig{OwnerMXID: "@owner:example.invalid", OwnerSPKIDER: f.ownerDER, Audience: "@receiver:example.invalid", RoomID: "!test:example.invalid", Topic: "test-grant", KeyRegistry: keys, GrantRegistry: grants, KeyRegistrySHA256: a2aHash(keys), GrantRegistrySHA256: a2aHash(grants)}
}

// Custodian pins and the owner signature are independently required; locally
// rehashing a modified signed registry does not make its certificate trusted.
func TestA2ARegistryAdmissionRefusals(t *testing.T) {
	for _, mode := range []string{"file-pin", "key-hash", "owner-pin", "owner-signature", "duplicate-grant", "too-many-grants", "unknown-field", "too-large"} {
		t.Run(mode, func(t *testing.T) {
			f := a2aFixtureForTest(t)
			r, e := f.receiver(t)
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("positive control", err)
			}
			c := a2aCurrentConfig(t, f)
			want := error(ErrA2ARegistryPin)
			switch mode {
			case "file-pin":
				c.KeyRegistry = append(c.KeyRegistry, '\n')
			case "key-hash":
				f.keyRegistry["keys"].(map[string]any)["@requester:example.invalid"].(map[string]any)["spki_sha256"] = strings.Repeat("00", 32)
				c = a2aCurrentConfig(t, f)
			case "owner-pin":
				c.OwnerSPKIDER = f.requesterDER
				want = errIssuerUntrusted
			case "owner-signature":
				m := f.grantsRegistry["grants"].(map[string]any)
				values := m["@requester:example.invalid"].([]any)
				b, _ := base64.RawURLEncoding.DecodeString(values[0].(string))
				var outer map[string]any
				json.Unmarshal(b, &outer)
				outer["signature"] = base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.requester, "swarma-grants/a2a-certificate/1", requestTestBytes(t, f.certificate)))
				values[0] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, outer))
				c = a2aCurrentConfig(t, f)
				want = errSignatureInvalid
			case "duplicate-grant":
				m := f.grantsRegistry["grants"].(map[string]any)
				v := m["@requester:example.invalid"].([]any)
				m["@requester:example.invalid"] = append(v, v[0])
				c = a2aCurrentConfig(t, f)
				want = errBadSchema
			case "too-many-grants":
				m := f.grantsRegistry["grants"].(map[string]any)
				v := m["@requester:example.invalid"].([]any)
				m["@requester:example.invalid"] = []any{v[0], v[0], v[0], v[0], v[0]}
				c = a2aCurrentConfig(t, f)
				want = errBadSchema
			case "unknown-field":
				f.keyRegistry["extra"] = "x"
				c = a2aCurrentConfig(t, f)
				want = errBadSchema
			case "too-large":
				c.GrantRegistry = bytes.Repeat([]byte("x"), 98305)
				want = errInputLimit
			}
			if _, err := NewA2AReceiver(c); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("original immutable verifier affected", err)
			}
		})
	}
}

// Revoked keys/grants are never selected, and two distinct valid grants do not
// silently add authority. Fresh file hashes do not waive the signed predicates.
func TestA2ARegistrySelection(t *testing.T) {
	for _, mode := range []string{"revoked-key", "revoked-grant", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			f := a2aFixtureForTest(t)
			r, e := f.receiver(t)
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal(err)
			}
			want := error(ErrA2ANoGrant)
			if mode == "revoked-key" {
				f.keyRegistry["keys"].(map[string]any)["@requester:example.invalid"].(map[string]any)["status"] = "revoked"
				r, e = f.receiver(t)
			} else {
				if mode == "revoked-grant" {
					f.grantsRegistry["revoked"] = []any{"a2a-grant-A"}
				} else {
					f.certificate["certificate_id"] = "a2a-grant-B"
					raw := requestTestBytes(t, f.certificate)
					outer := requestTestBytes(t, map[string]any{"type": "grants-a2a-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(raw), "signature": base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-certificate/1", raw))})
					m := f.grantsRegistry["grants"].(map[string]any)
					m["@requester:example.invalid"] = append(m["@requester:example.invalid"].([]any), base64.RawURLEncoding.EncodeToString(outer))
					want = ErrA2AAmbiguousGrant
				}
				var err error
				r, err = NewA2AReceiver(a2aCurrentConfig(t, f))
				if err != nil {
					t.Fatal(err)
				}
				f.request["grant_registry_sha256"] = a2aHash(requestTestBytes(t, f.grantsRegistry))
				e = f.event(t)
			}
			if _, err := r.Verify(e, f.now); !errors.Is(err, want) {
				t.Fatal(mode, err, want)
			}
		})
	}
}

// Request representation forbids extra fields and spelling aliases even when
// JSON is otherwise valid; valid bytes remain copied and exactly hashed.
func TestA2ARequestClosedCanonical(t *testing.T) {
	f := a2aFixtureForTest(t)
	raw, action := requestTestBytes(t, f.request), requestTestBytes(t, f.action)
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"action":`), []byte(`"action" :`), 1), bytes.Replace(raw, []byte(`"action":`), []byte(`"unknown":"x","action":`), 1)} {
		if _, err := PrepareA2ARequest(bad, action); !errors.Is(err, errBadEncoding) {
			t.Fatal("canonical refusal", err)
		}
	}
	f.request["expires_at"] = "2026-11-04T14:05:01Z"
	if _, err := PrepareA2ARequest(requestTestBytes(t, f.request), action); !errors.Is(err, ErrA2ATerm) {
		t.Fatal("five-minute bound", err)
	}
}
