package namecoinwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, path ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, path...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func contextFor(t *testing.T, s Snapshot) ReviewContext {
	t.Helper()
	p := s.Plan()
	var pin [32]byte
	if _, err := hex.Decode(pin[:], []byte(p.AccountPinSHA256)); err != nil {
		t.Fatal(err)
	}
	cap, ok := Decimal(p.Policy.PerTxFeeCap)
	if !ok {
		t.Fatal("fixture fee spelling")
	}
	// These are explicit public fixture facts for commitment tests, not proof
	// that an untrusted plan can select a production policy or account.
	return ReviewContext{Group: p.Group, Account: p.Account, Network: p.Network, Genesis: p.Genesis, PolicyRevision: p.Policy.Revision, AccountPinSHA256: pin, PerTxFeeCap: cap}
}

// Both reachable release modes reproduce all eight externally pinned frames;
// this does not exercise account custody, live policy admission or signatures.
func TestFrozenReviewFrames(t *testing.T) {
	rows := []struct {
		mode, slot, digest string
		length             int
	}{
		{"all-four-before-release", "A", "ef24dcde9bad069c632e66980252172859a0de5d39bd0ebaeb513f72478eec52", 881},
		{"all-four-before-release", "B", "b72f10ff7ef17ab76822bc96704c93f2420ef0fcc6615d6c1cff948e064be1e0", 903},
		{"all-four-before-release", "C", "e30e14c0516e652336ecd73ae9314f1592b1f5ed55d420383f062820a76d9016", 1655},
		{"all-four-before-release", "D", "e95384a3bf656eb4a8269b67f6039e064f64212e1e835ff8e412c8f0a54b4ca4", 1712},
		{"two-stage", "A", "bd10299aaf522d405d00df76802dfb8b1d7e7fc4c74b4bfa080cc368509e0cce", 879},
		{"two-stage", "B", "7be18e68c342e5bd2e0a17045969fdd5e4fbfd1ad7707488d28614578f56a986", 901},
		{"two-stage", "C", "0820dc1ef3c13cacf86c802142150f76b9fde5623d2ca181849cdf32e12a32b2", 1651},
		{"two-stage", "D", "d1540c83a9d2b09b6ab3f53e7615dff0c797958b5c851ddf737a48911fa55947", 1706},
	}
	for _, row := range rows {
		t.Run(row.mode+"/"+row.slot, func(t *testing.T) {
			s, err := Decode(fixture(t, row.mode, row.slot+"-request.json"))
			if err != nil {
				t.Fatal(err)
			}
			frame, err := s.ReviewFrame(contextFor(t, s))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := hex.DecodeString(strings.TrimSpace(string(fixture(t, row.mode, row.slot+"-review-frame.hex"))))
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(frame)
			if len(frame) != row.length || hex.EncodeToString(h[:]) != row.digest || !bytes.Equal(frame, expected) {
				t.Fatal("frozen review frame differs")
			}
			if _, err := DecodeReconcile(fixture(t, row.mode, row.slot+"-reconcile-query.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRevealPin(fixture(t, row.mode, "trusted-reveal-values-pin.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Known malformed requests return the intended code alongside a valid control.
// Expiry is intentionally not tested here: syntax decoding is not admission.
func TestFrozenNegativeRequests(t *testing.T) {
	if _, err := Decode(fixture(t, "all-four-before-release", "A-request.json")); err != nil {
		t.Fatal(err)
	}
	rows := map[string]Code{
		"unknown-request-field.json": InvalidRequest, "request-schema-v1.json": InvalidRequest,
		"noncanonical-base64.json": UnsupportedPSBT, "wrong-account-plan-hash.json": IntentMismatch,
		"wrong-reservation-hash.json": IntentMismatch, "request-id-short.json": InvalidRequest,
		"phase-slot-mismatch.json": IntentMismatch, "name-new-forbidden-value.json": InvalidRequest,
		"duplicate-request-schema.json": InvalidRequest,
	}
	for name, code := range rows {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(fixture(t, "negative", name))
			var f Failure
			if !errors.As(err, &f) || f.Code() != code {
				t.Fatalf("code: got %v, want %s", err, code)
			}
		})
	}
}

func rewritten(t *testing.T, good []byte, edit func(map[string]json.RawMessage)) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Returned views and caller bytes cannot mutate the frozen snapshot. A changed
// trusted binding refuses rather than silently creating a different approval.
func TestSnapshotOwnershipAndBinding(t *testing.T) {
	raw := fixture(t, "all-four-before-release", "A-request.json")
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := contextFor(t, s)
	original, err := s.ReviewFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	clear(raw)
	psbt := s.PSBTBytes()
	clear(psbt)
	manifest := s.ManifestBytes()
	clear(manifest)
	r := s.Request()
	clear(r.Intent)
	p := s.Plan()
	p.Transactions[0].Inputs[0].Path = "m/84h/7h/0h/0/9"
	p.Transactions[0].Outputs[0].Kind = "change"
	p.Registrations[0].NameHex = "00"
	again, err := s.ReviewFrame(c)
	if err != nil || !bytes.Equal(again, original) {
		t.Fatal("snapshot changed through external view")
	}
	for _, edit := range []func(*ReviewContext){func(c *ReviewContext) { c.Account = "other/namecoin@1" }, func(c *ReviewContext) { c.AccountPinSHA256[0] ^= 1 }, func(c *ReviewContext) { c.PerTxFeeCap++ }, func(c *ReviewContext) { c.Network = "namecoin-mainnet" }} {
		bad := c
		edit(&bad)
		if _, err := s.ReviewFrame(bad); err == nil {
			t.Fatal("changed trusted binding admitted")
		}
	}
	if _, err := (Snapshot{}).ReviewFrame(ReviewContext{}); err == nil {
		t.Fatal("empty snapshot admitted")
	}
}

// Exact closed spelling, required values and bounded JSON reject aliases/null
// before any frame can be used; insignificant outer JSON whitespace is valid.
func TestClosedRequestJSON(t *testing.T) {
	good := fixture(t, "all-four-before-release", "A-request.json")
	if _, err := Decode(append(append([]byte(" \n"), good...), '\n')); err != nil {
		t.Fatal(err)
	}
	rows := map[string][]byte{
		"case-alias":    rewritten(t, good, func(m map[string]json.RawMessage) { m["Schema"] = m["schema"]; delete(m, "schema") }),
		"missing":       rewritten(t, good, func(m map[string]json.RawMessage) { delete(m, "expires_at") }),
		"null":          rewritten(t, good, func(m map[string]json.RawMessage) { m["expires_at"] = []byte("null") }),
		"exponent":      rewritten(t, good, func(m map[string]json.RawMessage) { m["expires_at"] = []byte("1e3") }),
		"negative-zero": rewritten(t, good, func(m map[string]json.RawMessage) { m["expires_at"] = []byte("-0") }),
		"boolean":       rewritten(t, good, func(m map[string]json.RawMessage) { m["expires_at"] = []byte("true") }),
		"tail":          append(bytes.Clone(good), []byte(" {}")...),
		"oversize":      bytes.Repeat([]byte(" "), MaxRequestBytes+1),
	}
	for name, raw := range rows {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(raw); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v, want invalid_request", err)
			}
		})
	}
}

// The lexical layer accepts real UTF-8 and valid paired UTF-16 escapes while
// refusing replacement of an unpaired surrogate or invalid raw UTF-8.
func TestUnicodeJSONLexing(t *testing.T) {
	for _, raw := range []string{`{"text":"plain"}`, `{"text":"\ud83d\ude00"}`, `{"text":"😀"}`, `{"text":"\\ud800"}`} {
		var v struct {
			Text string `json:"text"`
		}
		if decodeClosed([]byte(raw), &v, 256) != nil {
			t.Fatal("valid JSON string refused")
		}
	}
	for _, raw := range [][]byte{[]byte(`{"text":"\ud800"}`), []byte(`{"text":"\udc00"}`), []byte(`{"text":"\ud800\u0061"}`), []byte("{\"text\":\"\xff\"}"), []byte(`{"text":"x","te\u0078t":"y"}`)} {
		var v struct {
			Text string `json:"text"`
		}
		if decodeClosed(raw, &v, 256) == nil {
			t.Fatal("malformed string/alias duplicate admitted")
		}
	}
}

// Display-order hashes and exact decoded manifest bytes are committed: adding
// legal manifest whitespace requires its new plan hash, never reserialization.
func TestExactManifestBytesAndForbiddenPendingFields(t *testing.T) {
	good := fixture(t, "all-four-before-release", "A-request.json")
	var request Request
	if json.Unmarshal(good, &request) != nil {
		t.Fatal("fixture")
	}
	request.ManifestUTF8 = " \n" + request.ManifestUTF8 + "\n"
	if _, err := Decode(rawJSON(t, request)); !errors.Is(err, ErrIntentMismatch) {
		t.Fatal("changed uncommitted manifest admitted")
	}
	request.PlanSHA256 = PlanDigest([]byte(request.ManifestUTF8))
	request.ReservationPlanSHA256 = request.PlanSHA256
	if _, err := Decode(rawJSON(t, request)); err != nil {
		t.Fatal("committed legal manifest whitespace refused", err)
	}
	for _, future := range []string{`{"state":"pending","value_hex":"00"}`, `{"state":"fixed","value_hex":"00","value_sha256":"00"}`, `{"state":null}`} {
		var r Request
		_ = json.Unmarshal(good, &r)
		var p ReservationPlan
		_ = json.Unmarshal([]byte(r.ManifestUTF8), &p)
		p.Registrations[0].FutureValue = []byte(future)
		r.ManifestUTF8 = string(rawJSON(t, p))
		r.PlanSHA256 = PlanDigest([]byte(r.ManifestUTF8))
		r.ReservationPlanSHA256 = r.PlanSHA256
		if _, err := Decode(rawJSON(t, r)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("pending id acquired a hidden future value")
		}
	}
}

// Public canonical forms preserve zero/maximum child indices and existing
// service spelling while rejecting alternate numeric/path authority forms.
func TestCanonicalPathsAndAmounts(t *testing.T) {
	for _, s := range []string{"m/84h/7h/0h/0/0", "m/84h/7h/0h/1/2147483647"} {
		if !Path(s) {
			t.Fatal("valid path refused")
		}
	}
	for _, s := range []string{"m/84'/7'/0'/0/0", "m/84h/7h/0h/2/0", "m/84h/7h/0h/0/01", "m/84h/7h/0h/0/2147483648", "m/84h/7h/0h/0/1h", "m/84h/7h/1h/0/0"} {
		if Path(s) {
			t.Fatal("forbidden path admitted")
		}
	}
	for _, s := range []string{"0", "100000", "18446744073709551615"} {
		if _, ok := Decimal(s); !ok {
			t.Fatal("canonical integer refused")
		}
	}
	for _, s := range []string{"", "00", "+1", "-0", "1.0", "1e3", "18446744073709551616"} {
		if _, ok := Decimal(s); ok {
			t.Fatal("alternate/overflow integer admitted")
		}
	}
}
