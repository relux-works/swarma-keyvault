package mugrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// Literal body and its content id computed outside Go:
// printf 'swarma-waggle grant/1\n%s' "$B" | shasum -a 256
const (
	fixtureBody      = `{"type":"grant/1","x":"fixture"}`
	fixtureContentID = "sha256:73e0da436ccbc6e8f10fe5376de7cfa0e086e5e0886c00ea539af70544dd935b"
)

// testKey is a software key standing in for a Secure Enclave key in tests only.
func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	return k, id
}

func signDER(t *testing.T, k *ecdsa.PrivateKey, digest [32]byte) []byte {
	t.Helper()
	der, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func derOf(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Claim: a native DER signature over the plan digest assembles into canonical
// swarm-envelope/2 wire whose id equals the independently computed content id,
// whose preimage starts with the grant/1 tag, and whose raw64 signature checks
// with stdlib ECDSA (independent of the platform verifier). Limit: software key.
func TestAssembleNativeGrant(t *testing.T) {
	k, id := testKey(t)
	p, err := Prepare("grant/1", id, []byte(fixtureBody))
	if err != nil {
		t.Fatal(err)
	}
	if p.ContentID() != fixtureContentID {
		t.Fatal("content id differs from the independent value", p.ContentID())
	}
	if !bytes.HasPrefix(p.Preimage(), []byte("swarma-waggle grant/1\n")) {
		t.Fatal("preimage tag missing")
	}
	wire, err := AssembleNative(p, signDER(t, k, p.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Body       json.RawMessage `json:"body"`
		ID         string          `json:"id"`
		Signatures []struct{ Key, Role, Sig string }
		Version    string `json:"version"`
	}
	if err := json.Unmarshal(wire, &e); err != nil || e.ID != fixtureContentID || e.Version != "swarm-envelope/2" || string(e.Body) != fixtureBody || len(e.Signatures) != 1 || e.Signatures[0].Role != "author" || e.Signatures[0].Key != id {
		t.Fatal("wire shape", err, string(wire))
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Signatures[0].Sig)
	if err != nil || len(sig) != 64 {
		t.Fatal("raw64 signature", err)
	}
	d := sha256.Sum256(p.Preimage())
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&k.PublicKey, d[:], r, s) {
		t.Fatal("stdlib ECDSA rejects assembled signature")
	}
	if s.Cmp(new(big.Int).Rsh(elliptic.P256().Params().N, 1)) > 0 {
		t.Fatal("assembled signature is high-S")
	}
}

// Claim: a valid high-S DER signature is normalized to low-S and still binds
// the plan; the same plan rejects a signature from another key or over another
// digest.
func TestAssembleNativeNormalizesAndBinds(t *testing.T) {
	k, id := testKey(t)
	p, err := Prepare("grant/1", id, []byte(fixtureBody))
	if err != nil {
		t.Fatal(err)
	}
	digest := p.Digest()
	var pair struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signDER(t, k, digest), &pair); err != nil {
		t.Fatal(err)
	}
	r, s := pair.R, pair.S
	n := elliptic.P256().Params().N
	high := s
	if s.Cmp(new(big.Int).Rsh(n, 1)) <= 0 {
		high = new(big.Int).Sub(n, s)
	}
	if _, err := AssembleNative(p, derOf(t, r, high)); err != nil {
		t.Fatal("high-S native signature not normalized", err)
	}
	other, _ := testKey(t)
	if _, err := AssembleNative(p, signDER(t, other, digest)); !errors.Is(err, ErrAssembly) {
		t.Fatal("foreign key signature assembled", err)
	}
	if _, err := AssembleNative(p, signDER(t, k, sha256.Sum256([]byte("other")))); !errors.Is(err, ErrAssembly) {
		t.Fatal("signature over another digest assembled", err)
	}
}

// Claim: malformed native signatures refuse before any verification.
func TestNativeP256RawRefusals(t *testing.T) {
	k, _ := testKey(t)
	good := signDER(t, k, sha256.Sum256([]byte("x")))
	if _, ok := NativeP256Raw(good); !ok {
		t.Fatal("valid DER refused")
	}
	n := elliptic.P256().Params().N
	nonMinimal := append([]byte{0x30, byte(len(good) - 2 + 1)}, append([]byte{0x02, good[3] + 1, 0x00}, good[4:]...)...)
	for name, der := range map[string][]byte{
		"empty":         nil,
		"trailing-byte": append(append([]byte{}, good...), 0x00),
		"non-minimal":   nonMinimal,
		"r-zero":        derOf(t, big.NewInt(0), big.NewInt(1)),
		"s-zero":        derOf(t, big.NewInt(1), big.NewInt(0)),
		"s-equals-n":    derOf(t, big.NewInt(1), n),
		"r-equals-n":    derOf(t, n, big.NewInt(1)),
		"too-long":      bytes.Repeat([]byte{0x30}, 73),
	} {
		if _, ok := NativeP256Raw(der); ok {
			t.Fatal("malformed DER admitted", name)
		}
	}
}

// Claim: Prepare refuses non-canonical bodies, a type that does not match the
// kind, unknown kinds, non-P-256 or invalid keys and oversized bodies, beside
// the valid control.
func TestPrepareRefusals(t *testing.T) {
	_, id := testKey(t)
	if _, err := Prepare("grant/1", id, []byte(fixtureBody)); err != nil {
		t.Fatal("valid control refused", err)
	}
	ed := "ed25519:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	badPoint := "p256:" + base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, bytes.Repeat([]byte{0xff}, 32)...))
	cases := map[string]struct{ kind, key, body string }{
		"whitespace":    {"grant/1", id, `{"type": "grant/1","x":"fixture"}`},
		"key-order":     {"grant/1", id, `{"x":"fixture","type":"grant/1"}`},
		"type-mismatch": {"grant/1", id, `{"type":"message/1","x":"fixture"}`},
		"unknown-kind":  {"operator-act/1", id, `{"type":"operator-act/1"}`},
		"ed25519-key":   {"grant/1", ed, fixtureBody},
		"invalid-point": {"grant/1", badPoint, fixtureBody},
		"not-object":    {"grant/1", id, `["grant/1"]`},
		"empty":         {"grant/1", id, ``},
	}
	for name, c := range cases {
		if _, err := Prepare(c.kind, c.key, []byte(c.body)); !errors.Is(err, ErrPlan) {
			t.Fatal("refusal expected", name, err)
		}
	}
	big := append([]byte(`{"type":"grant/1","x":"`), bytes.Repeat([]byte{'a'}, MaxEnvelopeBytes)...)
	big = append(big, '"', '}')
	if _, err := Prepare("grant/1", id, big); !errors.Is(err, ErrPlan) {
		t.Fatal("oversized body admitted", err)
	}
}

// Claim: the key id comes only from a canonical P-256 SPKI.
func TestKeyIDFromSPKI(t *testing.T) {
	k, id := testKey(t)
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	again, err := KeyIDFromSPKI(spki)
	if err != nil || again != id {
		t.Fatal("stable key id", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	for name, b := range map[string][]byte{"p384": p384, "trailing": append(append([]byte{}, spki...), 0), "empty": nil} {
		if _, err := KeyIDFromSPKI(b); err == nil {
			t.Fatal("bad spki admitted", name)
		}
	}
}
