package mugrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

const requestText = "Meta assigns: review the integrated multi-use grant solution"

// Computed outside Go: printf '%s' "$requestText" | shasum -a 256
const requestTextSHA = "2a00b04ba9f207e26dcb7016ed05025b32ee4b8c3ee5f5de819ad08947f7e9a9"

func requestSpec(t *testing.T) RequestSpec {
	t.Helper()
	_, author := testKey(t)
	return RequestSpec{
		Author: author, AuthorAttestation: "sha256:" + strings.Repeat("ab", 32), Audience: "swarma-keyvault-receiver",
		Room: "!room:gr.relux.works", To: "@keyvault.orch-altair:gr.relux.works",
		Action: "work.assign", Target: Target{"product", "swarma-platform"},
		Arguments: map[string]string{"module": "swarma-keyvault", "title": "Review the integrated multi-use grant solution"},
		Text:      requestText, Nonce: bytes.Repeat([]byte{0x22}, 16),
		IssuedAt: time.Date(2026, 11, 5, 17, 0, 0, 0, time.UTC), Lifetime: 120 * time.Second,
	}
}

// Claim: the request body has exactly the v0 message/1 members (the set of
// public vector PA1), binds the exact text by an independently computed
// SHA-256, keeps the 120-second lifetime, and signs and assembles under the
// author key (software stand-in) but not under another key.
func TestBuildRequest(t *testing.T) {
	k, author := testKey(t)
	spec := requestSpec(t)
	spec.Author = author
	r, err := BuildRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(r.Plan().Body(), &b); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range b {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "action,arguments,aud,author,author_attestation,body_sha256,exp,iat,nonce,room,target,to,type" {
		t.Fatal("member set", keys)
	}
	if b["body_sha256"] != requestTextSHA || b["iat"] != "2026-11-05T17:00:00Z" || b["exp"] != "2026-11-05T17:02:00Z" || r.Text() != requestText {
		t.Fatal("binding", b)
	}
	if _, err := AssembleNative(r.Plan(), signDER(t, k, r.Plan().Digest())); err != nil {
		t.Fatal("author signature refused", err)
	}
	other, _ := testKey(t)
	if _, err := AssembleNative(r.Plan(), signDER(t, other, r.Plan().Digest())); !errors.Is(err, ErrAssembly) {
		t.Fatal("foreign signature assembled", err)
	}
}

// Claim: every malformed request refuses before a plan exists, beside the
// valid spec.
func TestBuildRequestRefusals(t *testing.T) {
	cases := map[string]func(*RequestSpec){
		"lifetime-121s":    func(s *RequestSpec) { s.Lifetime = 121 * time.Second },
		"lifetime-zero":    func(s *RequestSpec) { s.Lifetime = 0 },
		"sub-second":       func(s *RequestSpec) { s.Lifetime = 1500 * time.Millisecond },
		"non-utc":          func(s *RequestSpec) { s.IssuedAt = s.IssuedAt.In(time.FixedZone("MSK", 3*3600)) },
		"unknown-action":   func(s *RequestSpec) { s.Action = "grant.issue" },
		"kind-mismatch":    func(s *RequestSpec) { s.Target.Kind = "room-scope" },
		"bad-author":       func(s *RequestSpec) { s.Author = "p256:AAAA" },
		"bad-attestation":  func(s *RequestSpec) { s.AuthorAttestation = "att-1" },
		"room-alias":       func(s *RequestSpec) { s.Room = "#swarma-keyvault:relux.works" },
		"bad-recipient":    func(s *RequestSpec) { s.To = "altair" },
		"empty-text":       func(s *RequestSpec) { s.Text = "" },
		"long-text":        func(s *RequestSpec) { s.Text = strings.Repeat("x", MaxRequestText+1) },
		"invalid-utf8":     func(s *RequestSpec) { s.Text = "\xff" },
		"short-nonce":      func(s *RequestSpec) { s.Nonce = s.Nonce[:8] },
		"bad-argument-key": func(s *RequestSpec) { s.Arguments["two words"] = "x" },
	}
	if _, err := BuildRequest(requestSpec(t)); err != nil {
		t.Fatal("valid control refused", err)
	}
	for name, mutate := range cases {
		s := requestSpec(t)
		mutate(&s)
		if _, err := BuildRequest(s); !errors.Is(err, ErrRequestSpec) {
			t.Fatal("refusal expected", name, err)
		}
	}
}
