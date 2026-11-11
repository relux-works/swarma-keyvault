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
	"fmt"
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
	err     error
}

func (s *linuxTestSigner) SignMessage(_ context.Context, _ string, pre []byte) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
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
		"two-qualifiers":            func(s *mugrant.RequestSpec) { s.Target.ID = "owner:fixture-1:b" },
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

// linuxAssertRequestControl checks the whole decoded body and verifies the
// emitted signature with the standard library, independently of the requester.
func linuxAssertRequestControl(t *testing.T, spec mugrant.RequestSpec, s *linuxTestSigner) {
	t.Helper()
	raw, err := SignLinuxRequest(context.Background(), spec, s)
	if err != nil || s.calls != 1 {
		t.Fatalf("valid control: err=%v signer calls=%d", err, s.calls)
	}
	e, err := muParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	args := make(map[string]any, len(spec.Arguments))
	for k, v := range spec.Arguments {
		args[k] = v
	}
	sum := sha256.Sum256([]byte(spec.Text))
	wantBody := map[string]any{
		"type": "message/1", "author": spec.Author, "author_attestation": spec.AuthorAttestation,
		"aud": spec.Audience, "nonce": base64.RawURLEncoding.EncodeToString(spec.Nonce),
		"iat": spec.IssuedAt.Format("2006-01-02T15:04:05Z"), "exp": spec.IssuedAt.Add(spec.Lifetime).Format("2006-01-02T15:04:05Z"),
		"action": spec.Action, "target": map[string]any{"kind": spec.Target.Kind, "id": spec.Target.ID},
		"arguments": args, "room": spec.Room, "to": spec.To, "body_sha256": hex.EncodeToString(sum[:]),
	}
	body, err := record.Canonical(e["body"])
	if err != nil {
		t.Fatal(err)
	}
	want, err := record.Canonical(wantBody)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("control body changed: %v", err)
	}
	id, err := record.ContentID("message/1", wantBody)
	if err != nil || len(e) != 4 || e["version"] != "swarm-envelope/2" || e["id"] != id {
		t.Fatalf("control envelope changed: %v", err)
	}
	sigs, ok := e["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		t.Fatal("control must have exactly one signature")
	}
	sig, ok := sigs[0].(map[string]any)
	if !ok || len(sig) != 3 || sig["key"] != spec.Author || sig["role"] != "author" {
		t.Fatal("control signature binding changed")
	}
	sigText, ok := sig["sig"].(string)
	if !ok {
		t.Fatal("control signature is not a string")
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(spec.Author, "ed25519:"))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("control public key: %v", err)
	}
	pre, err := record.SigningPreimage("message/1", spec.Author, "author", wantBody)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), pre, rawSig) {
		t.Fatalf("control signature does not verify: %v", err)
	}
	canonical, err := record.Canonical(e)
	if err != nil || !bytes.Equal(raw, canonical) {
		t.Fatalf("control is not canonical: %v", err)
	}
}

func linuxAssertRequestRefusal(t *testing.T, ctx context.Context, spec mugrant.RequestSpec, s *linuxTestSigner) {
	t.Helper()
	raw, err := SignLinuxRequest(ctx, spec, s)
	if !errors.Is(err, ErrLinuxRequest) || raw != nil || s.calls != 0 {
		t.Fatalf("refusal: err=%v envelope bytes=%d nil=%t signer calls=%d", err, len(raw), raw == nil, s.calls)
	}
}

// Claim: Seventeen arguments refuse before signing; sixteen survive in a verified envelope.
func TestLinuxRequesterArgumentCountBoundary(t *testing.T) {
	spec, s := linuxTestSpec(t)
	spec.Arguments = make(map[string]string)
	for i := 0; i < 16; i++ {
		spec.Arguments[fmt.Sprintf("arg-%02d", i)] = "value"
	}
	spec.Arguments["arg-16"] = "value"
	linuxAssertRequestRefusal(t, context.Background(), spec, s)
	delete(spec.Arguments, "arg-16")
	linuxAssertRequestControl(t, spec, s)
}

// Claim: A 65-byte argument name refuses before signing; its 64-byte neighbor survives exactly.
func TestLinuxRequesterArgumentNameBoundary(t *testing.T) {
	spec, s := linuxTestSpec(t)
	name := strings.Repeat("n", 64)
	spec.Arguments = map[string]string{name + "n": "value"}
	linuxAssertRequestRefusal(t, context.Background(), spec, s)
	spec.Arguments = map[string]string{name: "value"}
	linuxAssertRequestControl(t, spec, s)
}

// Claim: A 513-byte Unicode argument refuses before signing; 512 bytes survive without truncation.
func TestLinuxRequesterArgumentValueBoundary(t *testing.T) {
	spec, s := linuxTestSpec(t)
	value := strings.Repeat("é", 256)
	if len([]byte(value)) != 512 || len([]byte(value+"x")) != 513 {
		t.Fatal("incorrect byte-boundary fixtures")
	}
	spec.Arguments = map[string]string{"value": value + "x"}
	linuxAssertRequestRefusal(t, context.Background(), spec, s)
	spec.Arguments["value"] = value
	linuxAssertRequestControl(t, spec, s)
}

// Claim: Invalid argument UTF-8 refuses with valid body text; ordinary Unicode survives exactly.
func TestLinuxRequesterArgumentUTF8(t *testing.T) {
	spec, s := linuxTestSpec(t)
	spec.Arguments = map[string]string{"value": string([]byte{'v', 0xff})}
	linuxAssertRequestRefusal(t, context.Background(), spec, s)
	spec.Arguments["value"] = "valid é🙂"
	linuxAssertRequestControl(t, spec, s)
}

// Claim: Pre-canceled and nil contexts refuse without signing; the identical live request signs once.
func TestLinuxRequesterCanceledBeforeEntry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, ctx := range map[string]context.Context{"canceled": ctx, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			spec, s := linuxTestSpec(t)
			linuxAssertRequestRefusal(t, ctx, spec, s)
			linuxAssertRequestControl(t, spec, s)
		})
	}
}

// Claim: Signer failures preserve errors.Is, emit no envelope and never retry; a healthy signer succeeds once.
func TestLinuxRequesterSignerErrorNoRetry(t *testing.T) {
	for name, sentinel := range map[string]error{"sentinel": errors.New("synthetic signer failure"), "deadline": context.DeadlineExceeded} {
		t.Run(name, func(t *testing.T) {
			spec, s := linuxTestSpec(t)
			s.err = fmt.Errorf("synthetic signer: %w", sentinel)
			raw, err := SignLinuxRequest(context.Background(), spec, s)
			if !errors.Is(err, sentinel) || raw != nil || s.calls != 1 {
				t.Fatalf("signer failure: err=%v envelope bytes=%d nil=%t signer calls=%d", err, len(raw), raw == nil, s.calls)
			}
			linuxAssertRequestControl(t, spec, &linuxTestSigner{private: s.private})
		})
	}
}

type linuxCallbackSigner struct {
	private  ed25519.PrivateKey
	mutate   bool
	calls    int
	ctx      context.Context
	key      string
	preimage []byte
	signed   []byte
	sig      []byte
}

func (s *linuxCallbackSigner) SignMessage(ctx context.Context, key string, pre []byte) ([]byte, error) {
	s.calls++
	s.ctx, s.key, s.preimage = ctx, key, bytes.Clone(pre)
	if s.mutate && len(pre) > 0 {
		pre[0] ^= 1
	}
	s.signed = bytes.Clone(pre)
	s.sig = ed25519.Sign(s.private, pre)
	return s.sig, nil
}

// Claim: The callback receives the exact context, key and platform preimage;
// signing a mutated callback buffer refuses without an envelope or retry.
func TestLinuxRequesterCallbackExactness(t *testing.T) {
	spec, fixture := linuxTestSpec(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	args := make(map[string]any, len(spec.Arguments))
	for k, v := range spec.Arguments {
		args[k] = v
	}
	textHash := sha256.Sum256([]byte(spec.Text))
	wantBody := map[string]any{
		"type": "message/1", "author": spec.Author, "author_attestation": spec.AuthorAttestation,
		"aud": spec.Audience, "nonce": base64.RawURLEncoding.EncodeToString(spec.Nonce),
		"iat": spec.IssuedAt.Format("2006-01-02T15:04:05Z"), "exp": spec.IssuedAt.Add(spec.Lifetime).Format("2006-01-02T15:04:05Z"),
		"action": spec.Action, "target": map[string]any{"kind": spec.Target.Kind, "id": spec.Target.ID},
		"arguments": args, "room": spec.Room, "to": spec.To, "body_sha256": hex.EncodeToString(textHash[:]),
	}
	// Reconstruct the domain and complete signed record from the input spec,
	// independently of both the requester and record.SigningPreimage.
	signedRecord, err := record.Canonical(map[string]any{
		"version": "swarm-envelope/2", "body": wantBody, "key": spec.Author, "role": "author",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPreimage := append([]byte("swarma-msg/2\n"), signedRecord...)
	body, err := record.Canonical(wantBody)
	if err != nil {
		t.Fatal(err)
	}
	idHash := sha256.Sum256(append([]byte("swarma-msg/2\n"), body...))
	pub := fixture.private.Public().(ed25519.PublicKey)
	for _, mutate := range []bool{false, true} {
		name := "valid"
		if mutate {
			name = "mutated-preimage"
		}
		t.Run(name, func(t *testing.T) {
			signer := &linuxCallbackSigner{private: fixture.private, mutate: mutate}
			raw, err := SignLinuxRequest(ctx, spec, signer)
			if signer.calls != 1 || signer.ctx != ctx || signer.key != spec.Author || !bytes.Equal(signer.preimage, wantPreimage) {
				t.Fatalf("callback binding: calls=%d context=%t key=%t preimage=%t", signer.calls, signer.ctx == ctx, signer.key == spec.Author, bytes.Equal(signer.preimage, wantPreimage))
			}
			if !ed25519.Verify(pub, signer.signed, signer.sig) {
				t.Fatal("fixture did not sign the bytes it supplied")
			}
			if mutate {
				if bytes.Equal(signer.signed, wantPreimage) || ed25519.Verify(pub, wantPreimage, signer.sig) {
					t.Fatal("malicious fixture must sign changed bytes, not the original preimage")
				}
				if !errors.Is(err, ErrLinuxRequest) || raw != nil {
					t.Fatalf("mutated callback: err=%v envelope nil=%t", err, raw == nil)
				}
				return
			}
			if err != nil || !ed25519.Verify(pub, wantPreimage, signer.sig) {
				t.Fatalf("valid callback: err=%v signature must verify against the expected body", err)
			}
			wantEnvelope, err := record.Canonical(map[string]any{
				"version": "swarm-envelope/2", "id": "sha256:" + hex.EncodeToString(idHash[:]), "body": wantBody,
				"signatures": []any{map[string]any{"key": spec.Author, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(signer.sig)}},
			})
			if err != nil || !bytes.Equal(raw, wantEnvelope) {
				t.Fatalf("valid callback did not emit the exact canonical signed envelope: %v", err)
			}
		})
	}
}
