package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

var (
	ErrLinuxRequest     = mugrant.ErrRequestSpec
	ErrLinuxRequestText = errors.New("mu-request-text-refused")
)

// ValidateLinuxRequestText applies the shared contract's byte-exact text rule.
// Both entry points call it before inspecting identities, trust, state or a signer.
func ValidateLinuxRequestText(text []byte) error {
	if !mugrant.RequestTextAdmissible(text) {
		return ErrLinuxRequestText
	}
	return nil
}

// LinuxRequestSigner is a local signing seam, not a remote API. It signs the
// exact platform preimage with the requested Ed25519 key, returning raw64.
// This unit supplies no provider, key loader or runtime account credentials.
type LinuxRequestSigner interface {
	SignMessage(context.Context, string, []byte) ([]byte, error)
}

// SignLinuxRequest emits the existing swarm-envelope/2 message/1. The caller
// supplies the exact current Keymaker attestation content id; receivers must
// authenticate that id and current generation afresh, never substitute by key.
func SignLinuxRequest(ctx context.Context, spec mugrant.RequestSpec, signer LinuxRequestSigner) ([]byte, error) {
	if err := ValidateLinuxRequestText([]byte(spec.Text)); err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || signer == nil {
		return nil, ErrLinuxRequest
	}
	alg, _, err := record.KeyBytes(spec.Author)
	if err != nil || alg != "ed25519" || record.ValidateKey(spec.Author) != nil || !record.IsContentID(spec.AuthorAttestation) {
		return nil, ErrLinuxRequest
	}
	if !linuxActionTarget(spec.Action, spec.Target.Kind) || !linuxTarget(spec.Target.ID) ||
		!linuxToken(spec.Audience, 255) || !a2aContextText(spec.Room, '!') || !linuxMXID(spec.To) || len(spec.Nonce) != 16 {
		return nil, ErrLinuxRequest
	}
	if spec.IssuedAt.Location() != time.UTC || spec.IssuedAt.Nanosecond() != 0 || spec.IssuedAt.Year() < 1970 ||
		spec.IssuedAt.Add(spec.Lifetime).Year() > 9999 || spec.Lifetime <= 0 || spec.Lifetime > 120*time.Second || spec.Lifetime%time.Second != 0 || len(spec.Arguments) > 16 {
		return nil, ErrLinuxRequest
	}
	args := map[string]any{}
	for k, v := range spec.Arguments {
		if !linuxToken(k, 64) || len(v) > 512 || !utf8.ValidString(v) {
			return nil, ErrLinuxRequest
		}
		args[k] = v
	}
	sum := sha256.Sum256([]byte(spec.Text))
	body := map[string]any{
		"type": "message/1", "author": spec.Author, "author_attestation": spec.AuthorAttestation,
		"aud": spec.Audience, "nonce": base64.RawURLEncoding.EncodeToString(spec.Nonce),
		"iat": spec.IssuedAt.Format("2006-01-02T15:04:05Z"), "exp": spec.IssuedAt.Add(spec.Lifetime).Format("2006-01-02T15:04:05Z"),
		"action": spec.Action, "target": map[string]any{"kind": spec.Target.Kind, "id": spec.Target.ID},
		"arguments": args, "room": spec.Room, "to": spec.To, "body_sha256": hex.EncodeToString(sum[:]),
	}
	id, err := record.ContentID("message/1", body)
	if err != nil {
		return nil, err
	}
	pre, err := record.SigningPreimage("message/1", spec.Author, "author", body)
	if err != nil {
		return nil, err
	}
	sig, err := signer.SignMessage(ctx, spec.Author, bytes.Clone(pre))
	if err != nil {
		return nil, err
	}
	if len(sig) != 64 || record.VerifySignature(spec.Author, sig, pre) != nil {
		return nil, ErrLinuxRequest
	}
	return record.Canonical(map[string]any{
		"version": "swarm-envelope/2", "id": id, "body": body,
		"signatures": []any{map[string]any{"key": spec.Author, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(sig)}},
	})
}

func linuxToken(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func linuxMXID(s string) bool {
	a, b, ok := strings.Cut(strings.TrimPrefix(s, "@"), ":")
	return strings.HasPrefix(s, "@") && ok && a != "" && b != "" && linuxToken(s, 255)
}

func linuxTarget(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range []byte(p) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func linuxActionTarget(action, kind string) bool {
	switch action {
	case "work.assign", "work.require", "work.contract", "work.prioritize", "work.land-order", "work.accept":
		return kind == "product"
	case "account.manage":
		return kind == "account-scope"
	case "room.membership":
		return kind == "room-scope"
	}
	return false
}
