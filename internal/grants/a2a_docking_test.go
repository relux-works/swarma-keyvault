package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func a2aDockingReceiver(t *testing.T) (*a2aFixture, *A2AReceiver, A2AObservationContext, map[string]any) {
	t.Helper()
	f := a2aFixtureForTest(t)
	f.now = time.Date(2026, 11, 4, 14, 30, 0, 0, time.UTC)
	f.certificate["not_before"], f.certificate["expires_at"] = "2026-11-04T14:29:00Z", "2026-11-04T14:59:00Z"
	f.request["issued_at"], f.request["expires_at"] = "2026-11-04T14:29:00Z", "2026-11-04T14:34:00Z"
	x := A2AObservationContext{Audience: "@alice:test.local", RoomID: "!fixture:test.local", EventID: "$fixture-event", Topic: "alpha", ThreadRoot: "$ev001", DeclaredFrom: "bob", DeclaredTo: "alice"}
	keys := f.keyRegistry["keys"].(map[string]any)
	keys["@bob:test.local"] = keys["@requester:example.invalid"]
	delete(keys, "@requester:example.invalid")
	f.certificate["subject"].(map[string]any)["account_mxid"] = "@bob:test.local"
	f.certificate["audience"] = x.Audience
	f.request["sender_mxid"], f.request["audience"] = "@bob:test.local", x.Audience
	f.request["room_id"], f.request["topic"] = x.RoomID, x.Topic
	keyRaw := requestTestBytes(t, f.keyRegistry)
	f.certificate["key_registry_sha256"] = a2aHash(keyRaw)
	certRaw := requestTestBytes(t, f.certificate)
	signed := requestTestBytes(t, map[string]any{"type": "grants-a2a-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(certRaw), "signature": base64.RawURLEncoding.EncodeToString(a2aFixtureSignature(t, f.owner, "swarma-grants/a2a-certificate/1", certRaw))})
	f.grantsRegistry = map[string]any{"type": "grants-a2a-grants-registry-1", "key_registry_sha256": a2aHash(keyRaw), "revoked": []any{}, "grants": map[string]any{"@bob:test.local": []any{base64.RawURLEncoding.EncodeToString(signed)}}}
	grantRaw := requestTestBytes(t, f.grantsRegistry)
	f.request["grant_registry_sha256"] = a2aHash(grantRaw)
	r, err := NewA2AReceiver(A2AReceiverConfig{OwnerMXID: "@owner:example.invalid", OwnerSPKIDER: f.ownerDER, Audience: x.Audience, RoomID: x.RoomID, Topic: x.Topic, KeyRegistry: keyRaw, KeyRegistrySHA256: a2aHash(keyRaw), GrantRegistry: grantRaw, GrantRegistrySHA256: a2aHash(grantRaw)})
	if err != nil {
		t.Fatal(err)
	}
	p := map[string]any{"type": "a2a.event-verification-input/1", "observation_status": "observed", "requested_room_id": x.RoomID, "requested_event_id": x.EventID, "returned_event_id": x.EventID, "sender_mxid": "@bob:test.local", "receiver_mxid": x.Audience, "receiver_identity_source": "selected-stored-session", "event_type": "m.room.message", "returned_room_id_present": true, "returned_room_id": x.RoomID, "room_context_source": "returned-room-and-original-endpoint"}
	return f, r, x, p
}

// These exact content bytes came from the real post formatter through a fake
// homeserver. Both reply shapes extract the inert envelope unchanged, but that
// envelope cannot authenticate or touch use state/provider. A derived wrapper
// replacing only its body suffix with an independently signed fixture proves
// the neighboring valid path. This is not live projection-binary qualification.
func TestA2AFormatterDocking(t *testing.T) {
	for name, hash := range map[string]string{
		"explicit-re": "cf0849646a7ee92f39ae3249fd13d2c5cccbb5fdd06036b187b572b68cd1cde7",
		"no-re":       "17b1a0e6addec832cfcc928d1f3d04bf96c685b14fd5eaaf3a3ea61cd91b9828",
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "a2a-post-"+name+".json"))
			if err != nil || a2aHash(raw) != hash {
				t.Fatal("formatter fixture bytes changed", err)
			}
			f, r, x, p := a2aDockingReceiver(t)
			p["content_base64"] = base64.RawURLEncoding.EncodeToString(raw)
			e, err := ParseA2AObservation(requestTestBytes(t, p), x)
			inert := []byte(`{"payload":"e30","request":"e30","signature":"AA","type":"grants-a2a-envelope-1"}`)
			if err != nil || !bytes.Equal(e.Body, inert) {
				t.Fatal("actual formatter extraction", err)
			}
			if _, err := r.Verify(e, f.now); !errors.Is(err, errSignatureInvalid) {
				t.Fatal("inert envelope must fail signature before authorization", err)
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			state := A2AStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("formatter-docking-fixture"))}
			if err := InitializeA2AState(state, r); err != nil {
				t.Fatal(err)
			}
			path, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			m := NewA2AMediator(r, state, path)
			m.now = func() time.Time { return f.now }
			provider := &a2aFakeProvider{result: a2aReceiptFixture(t)}
			m.provider = provider
			before := a2aJournalBytes(t, m)
			if _, err := m.Execute(context.Background(), e); !errors.Is(err, errSignatureInvalid) || provider.calls.Load() != 0 || !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("inert formatter envelope caused effects", err, provider.calls.Load())
			}
			var w map[string]any
			if err := json.Unmarshal(raw, &w); err != nil {
				t.Fatal(err)
			}
			prefix := strings.SplitN(w["body"].(string), "\n\n", 2)[0] + "\n\n"
			w["body"] = prefix + string(f.event(t).Body)
			valid, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x)
			if err != nil {
				t.Fatal("derived signed neighbor extraction", err)
			}
			if _, err := r.Verify(valid, f.now); err != nil {
				t.Fatal("derived valid signature", err)
			}
			// Declared bob remains unchanged; the actual full sender is binding.
			foreign := valid
			foreign.SenderMXID = "@bob:foreign.invalid"
			if _, err := m.Execute(context.Background(), foreign); !errors.Is(err, ErrA2ANoGrant) || provider.calls.Load() != 0 || !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("declared header substituted for actual sender", err)
			}
			for _, mode := range []string{"suffix-lf", "header-sender", "reply-target", "fallback"} {
				t.Run(mode, func(t *testing.T) {
					var bad map[string]any
					if err := json.Unmarshal(requestTestBytes(t, w), &bad); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "suffix-lf":
						bad["body"] = bad["body"].(string) + "\n"
					case "header-sender":
						bad["ai.relux.a2a"].(map[string]any)["from"] = "other"
					case "reply-target":
						bad["m.relates_to"].(map[string]any)["m.in_reply_to"] = map[string]any{"event_id": "$other"}
					case "fallback":
						bad["m.relates_to"].(map[string]any)["is_falling_back"] = false
					}
					if _, err := ParseA2AObservation(a2aObservedBytes(t, bad, p), x); !errors.Is(err, ErrA2AContext) {
						t.Fatal("malformed derived wrapper accepted", err)
					}
					if _, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x); err != nil {
						t.Fatal("valid wrapper rejected after negative", err)
					}
				})
			}
			out, err := m.Execute(context.Background(), valid)
			if err != nil || out.State != "succeeded" || provider.calls.Load() != 1 {
				t.Fatal("derived signed neighbor dispatch", out, err)
			}
			if _, err := m.Execute(context.Background(), valid); !errors.Is(err, ErrA2AUseHeld) || provider.calls.Load() != 1 {
				t.Fatal("derived signed neighbor replayed", err)
			}
		})
	}
}
