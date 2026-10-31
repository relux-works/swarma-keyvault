package kekclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// testKey is a P-256 key whose private half the test holds, standing in for
// the keyvault key.
type testKey struct {
	priv *ecdh.PrivateKey
	spki []byte
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv, spki: spki}
}

// open is the receiving side of seal, written independently from the
// Security.framework description: split the ephemeral point, agree, derive
// key and IV with the X9.63 KDF, open GCM.
func (k testKey) open(sealed []byte) ([]byte, error) {
	if len(sealed) < 65+16 {
		return nil, errShort
	}
	eph, err := ecdh.P256().NewPublicKey(sealed[:65])
	if err != nil {
		return nil, err
	}
	z, err := k.priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	derived := x963KDF(z, sealed[:65], 32)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, derived[16:], sealed[65:], nil)
}

var errShort = errors.New("sealed envelope is too short")

const testCDHash = "0123456789abcdef0123456789abcdef01234567"

func testSpec(k testKey) WrapSpec {
	return WrapSpec{SPKI: k.spki, Fingerprint: Fingerprint(k.spki), Address: "network-proxy/store-kek", Generation: 1, Requirement: `cdhash H"` + testCDHash + `"`, InstallPath: "/Users/someone/.local/bin/network-proxy"}
}

func testKEK() []byte { return bytes.Repeat([]byte{0xa5}, KEKLen) }

// A wrapped KEK opens with the key's private half, its payload repeats the
// header, carries the binding and the install path, and the KEK comes back
// unchanged. Positive control for the refusals below.
func TestWrapOpensWithTheKeyAndBindsTheHeader(t *testing.T) {
	k := newTestKey(t)
	sealed, err := Wrap(testSpec(k), testKEK())
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if env.Address != "network-proxy/store-kek" || env.Generation != 1 || env.Fingerprint != Fingerprint(k.spki) || len(env.ECIES) != 65+len(mustJSONPayload(t, k))+16 {
		t.Fatalf("envelope header = %+v (ecies %d bytes)", env, len(env.ECIES))
	}
	plain, err := k.open(env.ECIES)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePayload(plain, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.KEK, testKEK()) || p.Requirement != testSpec(k).Requirement || p.InstallPath != testSpec(k).InstallPath {
		t.Fatalf("payload = %+v", p)
	}
	if bytes.Contains(sealed, testKEK()) {
		t.Fatal("the envelope carries the KEK in the clear")
	}
	if !MatchesKCV(testKEK(), env.KCV) || MatchesKCV(bytes.Repeat([]byte{1}, KEKLen), env.KCV) {
		t.Fatal("the check value does not identify exactly the wrapped KEK")
	}
}

func mustJSONPayload(t *testing.T, k testKey) []byte {
	s := testSpec(k)
	b, err := json.Marshal(Payload{Version: 1, Address: s.Address, Generation: s.Generation, Fingerprint: s.Fingerprint, Requirement: s.Requirement, InstallPath: s.InstallPath, KCV: KeyCheckValue(testKEK()), KEK: testKEK()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A changed ciphertext or tag byte, or an envelope sealed to another key,
// does not open; the untouched envelope does (positive control).
func TestTamperedOrForeignEnvelopeDoesNotOpen(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	sealed, _ := Wrap(testSpec(k), testKEK())
	env, _ := ParseEnvelope(sealed)
	if _, err := k.open(env.ECIES); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, i := range []int{0, 70, len(env.ECIES) - 1} {
		c := bytes.Clone(env.ECIES)
		c[i] ^= 1
		if plain, err := k.open(c); err == nil {
			t.Fatalf("byte %d changed and it still opened: %x", i, plain)
		}
	}
	if _, err := other.open(env.ECIES); err == nil {
		t.Fatal("another key opened the envelope")
	}
}

// Wrap refuses every malformed spec and a public key whose fingerprint is
// not the pinned one; the valid spec wraps (positive control).
func TestWrapRefusesUnpinnedOrMalformedSpecs(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	if _, err := Wrap(testSpec(k), testKEK()); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string]func(*WrapSpec){
		"other key's spki":    func(s *WrapSpec) { s.SPKI = other.spki },
		"empty fingerprint":   func(s *WrapSpec) { s.Fingerprint = "" },
		"address no slash":    func(s *WrapSpec) { s.Address = "network-proxy" },
		"address upper":       func(s *WrapSpec) { s.Address = "Network-proxy/store-kek" },
		"address dots":        func(s *WrapSpec) { s.Address = "../store-kek" },
		"generation 0":        func(s *WrapSpec) { s.Generation = 0 },
		"requirement free":    func(s *WrapSpec) { s.Requirement = `identifier "network-proxy"` },
		"relative install":    func(s *WrapSpec) { s.InstallPath = "bin/network-proxy" },
		"unclean install":     func(s *WrapSpec) { s.InstallPath = "/opt/../opt/proxy" },
		"spki not p256 point": func(s *WrapSpec) { s.SPKI = []byte("junk"); s.Fingerprint = Fingerprint(s.SPKI) },
	}
	for name, mutate := range cases {
		s := testSpec(k)
		mutate(&s)
		if out, err := Wrap(s, testKEK()); err == nil {
			t.Fatalf("%s: wrapped %d bytes", name, len(out))
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := Wrap(testSpec(k), make([]byte, n)); err == nil {
			t.Fatalf("KEK of %d bytes wrapped", n)
		}
	}
}

// The legacy cdhash form retains its exact spelling and constructor behavior.
// Expressions that widen it, other hash lengths and spellings refuse.
func TestRequirementAllowlist(t *testing.T) {
	good := `cdhash H"` + testCDHash + `"`
	if !ValidRequirement(good) {
		t.Fatal("control refused")
	}
	if got, ok := RequirementCDHash(good); !ok || got != testCDHash {
		t.Fatalf("cdhash of control = %q %v", got, ok)
	}
	if req, err := RequirementForCDHash(strings.ToUpper(testCDHash)); err != nil || req != good {
		t.Fatalf("upper-case input normalises: %q %v", req, err)
	}
	bad := []string{
		"",
		`cdhash H"` + strings.ToUpper(testCDHash) + `"`,
		`cdhash H"` + testCDHash[:39] + `"`,
		`cdhash H"` + testCDHash + `0"`,
		`cdhash H"` + strings.Repeat("ab", 32) + `"`,
		good + ` or anchor apple`,
		`anchor apple or ` + good,
		` ` + good,
		good + "\n",
		`cdhash  H"` + testCDHash + `"`,
		`cdhash h"` + testCDHash + `"`,
		`identifier "works.relux.network-proxy"`,
		`anchor apple generic`,
		`cdhash H"` + testCDHash[:38] + `zz"`,
	}
	for _, req := range bad {
		if ValidRequirement(req) {
			t.Fatalf("admitted %q", req)
		}
	}
	if _, err := RequirementForCDHash("xyz"); err == nil {
		t.Fatal("non-hex cdhash admitted")
	}
}

// ParseEnvelope admits only the exact contract object: unknown or repeated
// members, trailing data, another format or version, and invalid headers
// are refused; the genuine envelope parses (positive control).
func TestParseEnvelopeIsStrict(t *testing.T) {
	k := newTestKey(t)
	sealed, _ := Wrap(testSpec(k), testKEK())
	if _, err := ParseEnvelope(sealed); err != nil {
		t.Fatalf("control: %v", err)
	}
	var obj map[string]any
	json.Unmarshal(sealed, &obj)
	variant := func(change func(map[string]any)) []byte {
		m := map[string]any{}
		for k, v := range obj {
			m[k] = v
		}
		change(m)
		b, _ := json.Marshal(m)
		return b
	}
	bad := map[string][]byte{
		"unknown member":   variant(func(m map[string]any) { m["kek"] = "x" }),
		"other format":     variant(func(m map[string]any) { m["format"] = "other" }),
		"version 2":        variant(func(m map[string]any) { m["v"] = 2 }),
		"bad address":      variant(func(m map[string]any) { m["address"] = "x" }),
		"generation 0":     variant(func(m map[string]any) { m["generation"] = 0 }),
		"no fingerprint":   variant(func(m map[string]any) { m["fingerprint"] = "" }),
		"no ciphertext":    variant(func(m map[string]any) { delete(m, "ecies") }),
		"no kcv":           variant(func(m map[string]any) { delete(m, "kcv") }),
		"trailing data":    append(bytes.Clone(sealed), []byte(` {}`)...),
		"repeated member":  []byte(strings.Replace(string(sealed), `{"format"`, `{"v":1,"format"`, 1)),
		"not an object":    []byte(`[]`),
		"trailing brace":   append(bytes.Clone(sealed), '}'),
		"trailing bracket": append(bytes.Clone(sealed), ']'),
		"case alias":       []byte(strings.Replace(string(sealed), `"format"`, `"Format"`, 1)),
		"null member":      []byte(strings.Replace(string(sealed), `"kcv":`, `"kcv":null,"x":`, 1)),
		"escaped repeat":   []byte(strings.Replace(string(sealed), `{"format"`, `{"f\u006frmat":"x","format"`, 1)),
		"number as text":   []byte(strings.Replace(string(sealed), `"generation":1`, `"generation":"1"`, 1)),
		"too large":        bytes.Repeat([]byte(" "), maxEnvelopeBytes+1),
	}
	for name, data := range bad {
		if _, err := ParseEnvelope(data); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}

// ParsePayload refuses a payload whose header differs from its envelope's,
// a binding outside the allowlist, a short KEK and unknown members; the
// matching payload parses (positive control).
func TestParsePayloadChecksItsEnvelope(t *testing.T) {
	k := newTestKey(t)
	sealed, _ := Wrap(testSpec(k), testKEK())
	env, _ := ParseEnvelope(sealed)
	base := Payload{Version: 1, Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, Requirement: `cdhash H"` + testCDHash + `"`, InstallPath: "/opt/proxy", KCV: env.KCV, KEK: testKEK()}
	enc := func(p Payload) []byte { b, _ := json.Marshal(p); return b }
	if _, err := ParsePayload(enc(base), env); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string]func(*Payload){
		"other address":     func(p *Payload) { p.Address = "network-proxy/other" },
		"other generation":  func(p *Payload) { p.Generation = 2 },
		"other fingerprint": func(p *Payload) { p.Fingerprint = "x" },
		"version 2":         func(p *Payload) { p.Version = 2 },
		"free requirement":  func(p *Payload) { p.Requirement = "anchor apple" },
		"relative install":  func(p *Payload) { p.InstallPath = "proxy" },
		"short kek":         func(p *Payload) { p.KEK = p.KEK[:16] },
		"kcv not header's":  func(p *Payload) { p.KEK = bytes.Repeat([]byte{1}, KEKLen); p.KCV = KeyCheckValue(p.KEK) },
		"kek not its kcv":   func(p *Payload) { p.KEK = bytes.Repeat([]byte{1}, KEKLen) },
		"no kcv":            func(p *Payload) { p.KCV = nil },
	}
	for name, mutate := range cases {
		p := base
		mutate(&p)
		if _, err := ParsePayload(enc(p), env); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
	for name, data := range map[string][]byte{
		"unknown member": bytes.Replace(enc(base), []byte(`{"v":1`), []byte(`{"v":1,"note":"x"`), 1),
		"case alias":     bytes.Replace(enc(base), []byte(`"kek"`), []byte(`"KEK"`), 1),
		"repeated kek":   bytes.Replace(enc(base), []byte(`{"v":1`), []byte(`{"kek":"AAAA","v":1`), 1),
		"trailing data":  append(enc(base), '}'),
	} {
		if _, err := ParsePayload(data, env); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}

// A refused answer has no KEK decoded at all: every nested shape is checked
// on the raw bytes before the typed decode, so a repeated or case-aliased
// "kek" (with a string or null second value) cannot leave an overwritten
// decoded allocation behind. Review r6's witness. Control: the valid
// answer decodes its KEK.
func TestRefusedNestedAnswerDecodesNoKEK(t *testing.T) {
	_, env := func() ([]byte, Envelope) {
		k := newTestKey(t)
		sealed, _ := Wrap(testSpec(k), testKEK())
		e, _ := ParseEnvelope(sealed)
		return sealed, e
	}()
	b64 := base64.StdEncoding.EncodeToString(testKEK())
	head := `{"contract":"kek-1","ok":true,"result":{"address":"` + env.Address + `","generation":1,"fingerprint":"` + env.Fingerprint + `",`
	valid := head + `"kek":"` + b64 + `"}}`
	resp, err := parseResponse([]byte(valid))
	if err != nil || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK()) {
		t.Fatalf("control: %+v %v", resp.Result, err)
	}
	cases := map[string]string{
		"repeated kek, string": head + `"kek":"` + b64 + `","kek":"` + b64 + `"}}`,
		"repeated kek, null":   head + `"kek":"` + b64 + `","kek":null}}`,
		"alias KEK, string":    head + `"kek":"` + b64 + `","KEK":"` + b64 + `"}}`,
		"alias KEK, null":      head + `"kek":"` + b64 + `","KEK":null}}`,
		"unknown member":       head + `"kek":"` + b64 + `","note":"x"}}`,
	}
	for name, line := range cases {
		resp, err := parseResponse([]byte(line))
		if err == nil || resp.Result != nil {
			t.Fatalf("%s: err=%v, a result was decoded: %+v", name, err, resp.Result)
		}
	}
}

// The strict parser keeps no copy of what it reads: every member value, a
// nested object's members included, is a view into the caller's buffer, so
// clearing that buffer (the answer, the decrypted payload) clears every
// value with it. Review r7's witness: copied raw values outlived the clear.
// The control reads the values before the clear and finds the KEK.
func TestParsedValuesAreViewsIntoTheInput(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(testKEK())
	data := []byte(`{"contract":"kek-1","ok":true,"result":{"address":"a/b","generation":1,"fingerprint":"f","kek":"` + b64 + `"}}`)
	outer, err := checkShape(data, responseShape)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := checkShape(outer["result"], resultShape)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(outer["result"], []byte(b64)) || string(inner["kek"]) != `"`+b64+`"` {
		t.Fatalf("control: values do not hold the KEK before the clear")
	}
	clear(data)
	for name, v := range outer {
		if bytes.ContainsFunc(v, func(r rune) bool { return r != 0 }) {
			t.Fatalf("outer member %q survived the clear: %q", name, v)
		}
	}
	for name, v := range inner {
		if bytes.ContainsFunc(v, func(r rune) bool { return r != 0 }) {
			t.Fatalf("nested member %q survived the clear: %q", name, v)
		}
	}
}

// MarshalWithSecret produces the same JSON object as json.Marshal of the
// full value would, for the payload and for a KEK-bearing answer, and for
// an object with no other members; it refuses a value that is not an
// object.
func TestMarshalWithSecretMatchesJSON(t *testing.T) {
	kcv := KeyCheckValue(testKEK())
	same := func(a, b []byte) bool {
		var x, y any
		return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && fmt.Sprint(x) == fmt.Sprint(y)
	}
	got, err := MarshalWithSecret(payloadHeader{Version: 1, Address: "a/b", Generation: 2, Fingerprint: "f", Requirement: "r", InstallPath: "/p", KCV: kcv}, "kek", testKEK())
	want, _ := json.Marshal(Payload{Version: 1, Address: "a/b", Generation: 2, Fingerprint: "f", Requirement: "r", InstallPath: "/p", KCV: kcv, KEK: testKEK()})
	if err != nil || !same(got, want) {
		t.Fatalf("payload:\n%s\n%s (%v)", got, want, err)
	}
	got, err = MarshalWithSecret(Result{Address: "a/b", Generation: 1, Fingerprint: "f"}, "kek", testKEK())
	want, _ = json.Marshal(Result{Address: "a/b", Generation: 1, Fingerprint: "f", KEK: testKEK()})
	if err != nil || !same(got, want) {
		t.Fatalf("result:\n%s\n%s (%v)", got, want, err)
	}
	got, err = MarshalWithSecret(struct{}{}, "kek", testKEK())
	if err != nil || string(got) != `{"kek":"`+base64.StdEncoding.EncodeToString(testKEK())+`"}` {
		t.Fatalf("empty object: %s %v", got, err)
	}
	if _, err := MarshalWithSecret([]int{1}, "kek", testKEK()); err == nil {
		t.Fatal("a non-object was accepted")
	}
}
