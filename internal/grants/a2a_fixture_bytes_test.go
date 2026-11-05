package grants

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Literal canonical bytes of the public G2 action payload and request payload.
// Digests were computed outside Go with shasum (independent oracle):
//
//	SHA-256(action)                              = cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562
//	SHA-256("swarma-grants/a2a-request/1" LF request) = 420c32ea20d8ea90bddfae3338d55dcff9eb3cc63832cd8e5b5c559254da27dc
const (
	a2aLiteralAction        = `{"name":"matrix-grants-g2-261104","organization":"relux-works","visibility":"private"}`
	a2aLiteralRequest       = `{"action":"repository.create","audience":"@receiver:example.invalid","expires_at":"2026-11-04T14:05:00Z","grant_registry_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issued_at":"2026-11-04T14:00:00Z","nonce":"abababababababababababababababababababababababababababababababab","request_sha256":"cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562","resource":"github:relux-works/matrix-grants-g2-261104","room_id":"!test:example.invalid","sender_mxid":"@requester:example.invalid","topic":"test-grant","version":"grants-a2a-request-1"}`
	a2aLiteralRequestDigest = "420c32ea20d8ea90bddfae3338d55dcff9eb3cc63832cd8e5b5c559254da27dc"
)

// Claim: the shared test fixture serializes to exactly the pinned literal
// action/request bytes, the request preparation admits those bytes unchanged,
// and its domain digest equals the independently computed value. Limit: one
// fixture; it pins bytes, it does not prove a native signature.
func TestA2APublicFixtureLiteralBytes(t *testing.T) {
	f := a2aFixtureForTest(t)
	if got := requestTestBytes(t, f.action); string(got) != a2aLiteralAction {
		t.Fatalf("action fixture bytes drifted:\n%s", got)
	}
	if got := requestTestBytes(t, f.request); string(got) != a2aLiteralRequest {
		t.Fatalf("request fixture bytes drifted:\n%s", got)
	}
	prepared, err := PrepareA2ARequest([]byte(a2aLiteralRequest), []byte(a2aLiteralAction))
	if err != nil {
		t.Fatal("literal canonical request refused", err)
	}
	if !bytes.Equal(prepared.Payload(), []byte(a2aLiteralRequest)) {
		t.Fatal("prepared payload changed the literal bytes")
	}
	digest := prepared.Digest()
	if hex.EncodeToString(digest[:]) != a2aLiteralRequestDigest {
		t.Fatal("request domain digest differs from the independent value", hex.EncodeToString(digest[:]))
	}
}

// Claim: non-canonical spellings of the same request (reordered keys, added
// whitespace, a trailing LF) and a different action payload are refused rather
// than normalized.
func TestA2APublicFixtureLiteralRefusals(t *testing.T) {
	request, action := []byte(a2aLiteralRequest), []byte(a2aLiteralAction)
	reordered := bytes.Replace(request, []byte(`{"action":"repository.create","audience"`), []byte(`{"audience"`), 1)
	reordered = bytes.Replace(reordered, []byte(`"version":`), []byte(`"action":"repository.create","version":`), 1)
	for name, bad := range map[string][]byte{
		"reordered-keys": reordered,
		"space":          bytes.Replace(request, []byte(`":"`), []byte(`": "`), 1),
		"trailing-lf":    append(append([]byte{}, request...), '\n'),
	} {
		if _, err := PrepareA2ARequest(bad, action); err == nil {
			t.Fatal("non-canonical request admitted", name)
		}
	}
	otherAction := bytes.Replace(action, []byte("private"), []byte("public"), 1)
	if _, err := PrepareA2ARequest(request, otherAction); err == nil {
		t.Fatal("request admitted with a different action payload")
	}
}
