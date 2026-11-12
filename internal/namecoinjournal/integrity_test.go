package namecoinjournal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixtureBinding() Binding {
	b := Binding{Group: "fixture/recovery@1", Account: "wallet/namecoin@1", Policy: "fixture-policy-1"}
	for i := range b.PublicPin {
		b.PublicPin[i] = 3
	}
	return b
}
func fixtureMaterial() []byte {
	// Public disposable scalar 1 and synthetic chaincode. Never an owner fixture.
	p := make([]byte, 64)
	p[31] = 1
	for i := 32; i < 64; i++ {
		p[i] = 2
	}
	return p
}
func requireHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatal("public fixture vector mismatch")
	}
}
func fixtureAnchor(t *testing.T) *Anchor {
	t.Helper()
	a, e := NewInitialization(fixtureBinding(), fixtureMaterial())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.Clear)
	return a
}

// Literal vectors were independently calculated with Python's stdlib SHA256/HMAC
// from the written length/domain contract and public fixture, not this encoder.
// They are internal-format regression controls, not frozen facade vectors or
// native qualification. No production KDF/MAC service is invoked.
func TestExactKDFHeadAndLocator(t *testing.T) {
	b := fixtureBinding()
	a := fixtureAnchor(t)
	requireHex(t, a.key[:], "79e3dc3a4b6e681184de44f594a7c6dbce06d89c8740e5b50c4534564a716b7b")
	requireHex(t, a.head[:], "bdefbfe3d74fa628d7d358af008012d32b423f86e661f9efa80fabf4be54392d")
	requireHex(t, a.token[:], "302d6282879fb8b261212c473d669fb0904a7c8799c97a26228445507b25ed33")
	locator, err := Locator(b)
	if err != nil || locator != "e5c1360201e9ed838c085610fce78de3ed75b4d81170bf49e4d2f1f18797b73c" {
		t.Fatal("locator vector")
	}
	if err := a.VerifyAccount(fixtureMaterial()); err != nil {
		t.Fatal(err)
	}
	variants := []Binding{b, b, b}
	variants[0].Group = "other/recovery@1"
	variants[1].Account = "other/namecoin@1"
	variants[2].PublicPin[0] ^= 1
	for _, wrong := range variants {
		key, e := derive(fixtureMaterial(), wrong)
		if e != nil || key == a.key {
			t.Fatal("KDF binding not separated")
		}
	}
	// Policy belongs to the token, not the admitted KDF salt.
	wrong := b
	wrong.Policy = "fixture-policy-2"
	key, e := derive(fixtureMaterial(), wrong)
	if e != nil || key != a.key || headToken(key, wrong, 0, a.head) == a.token {
		t.Fatal("policy frame binding")
	}
	for _, material := range [][]byte{nil, make([]byte, 64), make([]byte, 63), bytes.Repeat([]byte{255}, 64)} {
		if _, e := derive(material, b); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid account admitted")
		}
	}
}

// Valid roundtrip is paired with every-byte tamper, truncation and a substituted
// self-consistent anchor. The latter passes stored-key consistency but MUST fail
// rederivation from retained authority. No Keychain isolation is claimed.
func TestProtectedAnchorAndAccountRederivation(t *testing.T) {
	b := fixtureBinding()
	a := fixtureAnchor(t)
	raw, e := a.EncodeProtected()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	decoded, e := DecodeProtected(raw, b)
	if e != nil {
		t.Fatal(e)
	}
	defer decoded.Clear()
	if e = decoded.VerifyAccount(fixtureMaterial()); e != nil {
		t.Fatal(e)
	}
	for i := range raw {
		bad := bytes.Clone(raw)
		bad[i] ^= 1
		other, err := DecodeProtected(bad, b)
		clear(bad)
		if err == nil {
			other.Clear()
			t.Fatalf("tamper accepted at %d", i)
		}
	}
	for i := 0; i < len(raw); i++ {
		if _, err := DecodeProtected(raw[:i], b); err == nil {
			t.Fatalf("truncated anchor accepted at %d", i)
		}
	}
	if _, e = DecodeProtected(append(bytes.Clone(raw), 0), b); e == nil {
		t.Fatal("trailing bytes")
	}
	if _, e = DecodeProtected(nil, b); !errors.Is(e, ErrMissing) {
		t.Fatal("missing initialized")
	}
	material := fixtureMaterial()
	material[31] = 2
	forged, e := NewInitialization(b, material)
	if e != nil {
		t.Fatal(e)
	}
	defer forged.Clear()
	forgedRaw, e := forged.EncodeProtected()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(forgedRaw)
	loaded, e := DecodeProtected(forgedRaw, b)
	if e != nil {
		t.Fatal("fixture must be self-consistent")
	}
	defer loaded.Clear()
	if e = loaded.VerifyAccount(fixtureMaterial()); !errors.Is(e, ErrUnknown) {
		t.Fatal("substituted key trusted")
	}
	a.Clear()
	if _, _, e = a.Head(); e == nil {
		t.Fatal("cleared anchor usable")
	}
	if _, e = a.EncodeProtected(); e == nil {
		t.Fatal("cleared anchor encoded")
	}
}

// Existing identities accept their declared forms and reject noncanonical
// versions/path plants. This table does not invent a new public identity syntax.
func TestIdentityCompatibilityAndRefusals(t *testing.T) {
	for _, s := range []string{"a/recovery@1", "a-0/recovery@2", strings.Repeat("a", 40) + "/recovery@2147483647"} {
		if !identity(s, "recovery") {
			t.Fatalf("legitimate form rejected %q", s)
		}
	}
	for _, s := range []string{"", "a/recovery@0", "a/recovery@01", "a/recovery@+1", "A/recovery@1", "a/../recovery@1", "a/recovery@1/x", "a/nostr@1", "a/recovery@2147483648", "a/recovery@9223372036854775807", "a/recovery@9223372036854775808", strings.Repeat("a", 41) + "/recovery@1"} {
		if identity(s, "recovery") {
			t.Fatalf("forbidden form accepted %q", s)
		}
	}
}

// Accidental formatting must not expose confined fields. This does not prevent
// a deliberate unsafe caller from logging an encoded protected buffer.
func TestAnchorFormattingIsOpaque(t *testing.T) {
	a := fixtureAnchor(t)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if got := fmt.Sprintf(format, a); got != "<confined Namecoin anchor>" {
			t.Fatal("anchor formatting exposed fields")
		}
	}
}
