package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// G2 contract fixture r2: the published G2 interaction-contract request fixture
// with its four identity/context fields (sender_mxid, audience, room_id, topic)
// replaced by example.invalid values. Field order, grammar and every other value
// are byte-identical to r1. Digests were computed outside Go with shasum
// (independent oracle):
//
//	SHA-256(action), 86 bytes                          = cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562
//	SHA-256(request), 577 bytes                        = e2f9cf83033a3845f3a04b5a8c5d52576f285327b992b7f325b3e8fe20b33f39
//	SHA-256("swarma-grants/a2a-request/1" LF request) = facc7de78c58c6e82ef1d22d8d0c4f62c82e9bb580d03129a16ad9d5439be5aa
const (
	a2aContractAction        = `{"name":"matrix-grants-g2-261104","organization":"relux-works","visibility":"private"}`
	a2aContractActionSHA     = "cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562"
	a2aContractRequest       = `{"action":"repository.create","audience":"@receiver:example.invalid","expires_at":"2026-11-04T13:40:00Z","grant_registry_sha256":"2222222222222222222222222222222222222222222222222222222222222222","issued_at":"2026-11-04T13:35:00Z","nonce":"1111111111111111111111111111111111111111111111111111111111111111","request_sha256":"cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562","resource":"github:relux-works/matrix-grants-g2-261104","room_id":"!room:example.invalid","sender_mxid":"@requester:example.invalid","topic":"test-grant","version":"grants-a2a-request-1"}`
	a2aContractRequestSHA    = "e2f9cf83033a3845f3a04b5a8c5d52576f285327b992b7f325b3e8fe20b33f39"
	a2aContractRequestDigest = "facc7de78c58c6e82ef1d22d8d0c4f62c82e9bb580d03129a16ad9d5439be5aa"
)

// Literal bytes of the shared test fixture (a2aFixtureForTest), pinned so that
// fixture drift is caught. Digest from shasum:
//
//	SHA-256("swarma-grants/a2a-request/1" LF request) = 420c32ea20d8ea90bddfae3338d55dcff9eb3cc63832cd8e5b5c559254da27dc
const (
	a2aFixtureRequest       = `{"action":"repository.create","audience":"@receiver:example.invalid","expires_at":"2026-11-04T14:05:00Z","grant_registry_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issued_at":"2026-11-04T14:00:00Z","nonce":"abababababababababababababababababababababababababababababababab","request_sha256":"cc4634957dbc722be7822d5fdf2ae480cc6a38e404c16d4a152c95678e9a0562","resource":"github:relux-works/matrix-grants-g2-261104","room_id":"!test:example.invalid","sender_mxid":"@requester:example.invalid","topic":"test-grant","version":"grants-a2a-request-1"}`
	a2aFixtureRequestDigest = "420c32ea20d8ea90bddfae3338d55dcff9eb3cc63832cd8e5b5c559254da27dc"
)

// Claim: the G2 contract fixture r2 hashes to the independently computed
// values, is admitted unchanged by request preparation, and its domain digest
// equals the shasum value. Limit: public bytes only; no signature or native
// backend is exercised.
func TestA2AContractFixtureLiteralBytes(t *testing.T) {
	if got := sha256.Sum256([]byte(a2aContractAction)); hex.EncodeToString(got[:]) != a2aContractActionSHA || len(a2aContractAction) != 86 {
		t.Fatal("contract action bytes differ from the published fixture")
	}
	if got := sha256.Sum256([]byte(a2aContractRequest)); hex.EncodeToString(got[:]) != a2aContractRequestSHA || len(a2aContractRequest) != 577 {
		t.Fatal("contract request bytes differ from the published r2 fixture")
	}
	prepared, err := PrepareA2ARequest([]byte(a2aContractRequest), []byte(a2aContractAction))
	if err != nil {
		t.Fatal("contract fixture refused", err)
	}
	if !bytes.Equal(prepared.Payload(), []byte(a2aContractRequest)) {
		t.Fatal("prepared payload changed the contract bytes")
	}
	digest := prepared.Digest()
	if hex.EncodeToString(digest[:]) != a2aContractRequestDigest {
		t.Fatal("contract domain digest differs from the independent value", hex.EncodeToString(digest[:]))
	}
}

// Claim: the shared test fixture serializes to exactly the pinned literal bytes,
// shares the contract action, and its domain digest equals the shasum value.
// Limit: one fixture; it pins bytes, not a native signature.
func TestA2ASharedFixtureLiteralBytes(t *testing.T) {
	f := a2aFixtureForTest(t)
	if got := requestTestBytes(t, f.action); string(got) != a2aContractAction {
		t.Fatalf("action fixture bytes drifted:\n%s", got)
	}
	if got := requestTestBytes(t, f.request); string(got) != a2aFixtureRequest {
		t.Fatalf("request fixture bytes drifted:\n%s", got)
	}
	prepared, err := PrepareA2ARequest([]byte(a2aFixtureRequest), []byte(a2aContractAction))
	if err != nil {
		t.Fatal("shared fixture refused", err)
	}
	digest := prepared.Digest()
	if hex.EncodeToString(digest[:]) != a2aFixtureRequestDigest {
		t.Fatal("shared fixture domain digest differs", hex.EncodeToString(digest[:]))
	}
}

// Claim: non-canonical spellings of the contract request (reordered keys, added
// whitespace, a trailing LF) and a different action payload are refused rather
// than normalized.
func TestA2AContractFixtureLiteralRefusals(t *testing.T) {
	request, action := []byte(a2aContractRequest), []byte(a2aContractAction)
	reordered := bytes.Replace(request, []byte(`{"action":"repository.create","audience"`), []byte(`{"audience"`), 1)
	reordered = bytes.Replace(reordered, []byte(`"version":`), []byte(`"action":"repository.create","version":`), 1)
	if bytes.Equal(reordered, request) {
		t.Fatal("reorder fixture did not change the bytes")
	}
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
