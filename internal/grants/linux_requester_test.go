package grants

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

type linuxTestSigner struct {
	private ed25519.PrivateKey
	calls   int
	bad     bool
}

func (s *linuxTestSigner) SignMessage(_ context.Context, _ string, pre []byte) ([]byte, error) {
	s.calls++
	if s.bad {
		return make([]byte, 64), nil
	}
	return ed25519.Sign(s.private, pre), nil
}

func linuxTestSpec(t *testing.T) (mugrant.RequestSpec, *linuxTestSigner) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return mugrant.RequestSpec{Author: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), AuthorAttestation: "sha256:" + strings.Repeat("a", 64),
		Audience: muDockAud, Room: muDockRoom, To: muDockReceiver, Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: "swarma-platform"},
		Arguments: map[string]string{"module": "swarma-keyvault", "title": "synthetic request"}, Text: "assign\n\tthis task", Nonce: nonce, IssuedAt: muNow, Lifetime: 120 * time.Second}, &linuxTestSigner{private: priv}
}

// Every refused text must win over invalid keys, context, projection, signer
// and receiver configuration; neither signing nor verification may occur.
// Claim: Forbidden text refuses before signing or receiver admission, while text at the byte limit and permitted whitespace pass.
func TestLinuxTextFirst(t *testing.T) {
	bad := [][]byte{nil, []byte(" \n\t"), []byte(strings.Repeat("x", 4097)), []byte(strings.Repeat("é", 2049)), {0xff}, []byte("a\r"), []byte("a\x00"), []byte("a\x1f"), []byte("a\x7f"), []byte("a\u0085"), []byte("a\ufffd"), []byte("a\u202e"), []byte("a\u2067"), []byte("a\u200f"), []byte("a\u061c")}
	for i, text := range bad {
		spec, signer := linuxTestSpec(t)
		spec.Text = string(text)
		spec.Author = "broken"
		if _, err := SignLinuxRequest(nil, spec, signer); !errors.Is(err, ErrLinuxRequestText) || signer.calls != 0 {
			t.Fatalf("requester case %d: %v calls %d", i, err, signer.calls)
		}
		var receiver *LinuxReceiver
		if _, err := receiver.Handle(nil, MUEnvelopeEvent{Text: text}); !errors.Is(err, ErrLinuxRequestText) {
			t.Fatalf("receiver case %d: %v", i, err)
		}
	}
	for _, text := range []string{strings.Repeat("x", 4096), strings.Repeat("é", 2048), "hello\n\tworld", "🙂"} {
		if err := ValidateLinuxRequestText([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
}

// Claim: Linux requests use canonical platform records and exact text hashes with verified raw Ed25519 signatures.
func TestLinuxRequesterPlatformWire(t *testing.T) {
	spec, s := linuxTestSpec(t)
	spec.Text = strings.Repeat("é", 2048)
	raw, err := SignLinuxRequest(context.Background(), spec, s)
	if err != nil || s.calls != 1 {
		t.Fatal(err, s.calls)
	}
	e, err := muParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := e["body"].(map[string]any)
	if len(e) != 4 || len(b) != 13 || e["version"] != "swarm-envelope/2" || b["author_attestation"] != spec.AuthorAttestation {
		t.Fatal("changed format", e)
	}
	id, _ := record.ContentID("message/1", b)
	pre, _ := record.SigningPreimage("message/1", spec.Author, "author", b)
	sig := e["signatures"].([]any)[0].(map[string]any)
	rawSig, err := record.DecodeBase64(sig["sig"].(string), 64)
	if err != nil || e["id"] != id || record.VerifySignature(spec.Author, rawSig, pre) != nil {
		t.Fatal("platform signature mismatch", err)
	}
	sum := sha256.Sum256([]byte(spec.Text))
	if b["body_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatal("text bytes changed")
	}
	canonical, _ := record.Canonical(e)
	if !bytes.Equal(raw, canonical) {
		t.Fatal("noncanonical record")
	}
	s.bad = true
	if _, err := SignLinuxRequest(context.Background(), spec, s); !errors.Is(err, ErrLinuxRequest) {
		t.Fatal("bad signer accepted", err)
	}
}

// Claim: Invalid request identity, scope, interval or arguments refuses before invoking the signer.
func TestLinuxRequesterRefusesBeforeSigner(t *testing.T) {
	cases := map[string]func(*mugrant.RequestSpec){
		"alias":                     func(s *mugrant.RequestSpec) { s.Room = "#alias:invalid" },
		"missing-exact-attestation": func(s *mugrant.RequestSpec) { s.AuthorAttestation = "current" },
		"wildcard":                  func(s *mugrant.RequestSpec) { s.Target.ID = "swarma-*" },
		"two-qualifiers":            func(s *mugrant.RequestSpec) { s.Target.ID = "owner:a:b" },
		"wrong-kind":                func(s *mugrant.RequestSpec) { s.Target.Kind = "room-scope" },
		"unknown-action":            func(s *mugrant.RequestSpec) { s.Action = "grant.issue" },
		"fractional-lifetime":       func(s *mugrant.RequestSpec) { s.Lifetime = time.Second + 1 },
		"too-long":                  func(s *mugrant.RequestSpec) { s.Lifetime = 121 * time.Second },
		"short-nonce":               func(s *mugrant.RequestSpec) { s.Nonce = []byte{1} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			spec, s := linuxTestSpec(t)
			change(&spec)
			if _, err := SignLinuxRequest(context.Background(), spec, s); err == nil || s.calls != 0 {
				t.Fatal(err, s.calls)
			}
		})
	}
}
