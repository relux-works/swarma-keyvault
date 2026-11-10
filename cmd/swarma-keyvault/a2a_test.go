package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func a2aCLIBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func a2aCLIHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func a2aCLIFixture(t *testing.T) ([]string, map[string]any, *cliIssueStore) {
	t.Helper()
	_, _, store := issueCLIFixture(t)
	public := store.item.SPKI
	requester, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requesterDER, err := x509.MarshalPKIXPublicKey(&requester.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ownerFile, subjectFile := filepath.Join(dir, "owner.der"), filepath.Join(dir, "subject.der")
	for name, b := range map[string][]byte{ownerFile: public, subjectFile: requesterDER} {
		if err := os.WriteFile(name, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	certificate := map[string]any{"type": "grants-a2a-certificate-1", "audience": "@receiver:example.invalid", "certificate_id": "test-A",
		"issuer":              map[string]any{"owner_mxid": fixtureOwnerPrincipal, "purpose": "grants-owner-v1", "key_id": "sha256:" + a2aCLIHash(public)},
		"subject":             map[string]any{"account_mxid": "@requester:example.invalid", "spki_sha256": a2aCLIHash(requesterDER)},
		"key_registry_sha256": strings.Repeat("11", 32), "not_before": "2026-11-04T14:00:00Z", "expires_at": "2026-11-04T14:30:00Z", "supersedes": []any{},
		"entries": []any{map[string]any{"action": "repository.create", "entry_id": "create", "use_count": "1", "target": map[string]any{"organization": "relux-works", "name": grants.A2ARepository, "visibility": "private"}}}}
	newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
		store.factories++
		digest := sha256.Sum256(append([]byte("swarma-grants/a2a-certificate/1\n"), a2aCLIBytes(t, certificate)...))
		reason := prompt(digest[:])
		if !strings.Contains(reason, "@requester:example.invalid") || !strings.Contains(reason, a2aCLIHash(requesterDER)[:16]) || !strings.Contains(reason, "MSK") || utf8.RuneCountInString(reason) > 200 || prompt(make([]byte, 32)) != "" {
			t.Fatal("incorrect actual reason callback", reason)
		}
		return keyvault.NewManager(store, nil, keyvault.Origin{})
	}
	return withFixtureOwnerArgs([]string{"grants", "a2a-prepare", "--payload", "-", "--owner-spki-der", ownerFile, "--requester-spki-der", subjectFile}), certificate, store
}

// Public prepare never constructs a manager; the positive issue path signs
// exactly once through an in-memory fake and its digest-bound full-scope reason.
func TestA2ACertificateCLI(t *testing.T) {
	args, c, store := a2aCLIFixture(t)
	payload := a2aCLIBytes(t, c)
	var out, errout bytes.Buffer
	if code := run(args, bytes.NewReader(payload), &out, &errout); code != 0 || store.factories != 0 || store.signs != 0 || !bytes.Equal(out.Bytes(), payload) || !strings.Contains(errout.String(), string(payload)) {
		t.Fatal("public prepare", code, errout.String(), store.factories, store.signs)
	}
	args[1] = "a2a-issue"
	out.Reset()
	errout.Reset()
	if code := run(args, bytes.NewReader(payload), &out, &errout); code != 0 || store.factories != 1 || store.signs != 1 {
		t.Fatal("fake issue", code, errout.String(), store.factories, store.signs)
	}
	var envelope map[string]string
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil || envelope["type"] != "grants-a2a-signed-certificate-1" {
		t.Fatal("incorrect envelope", err)
	}
}

// Overflow, wrong scope/key and review sink failure prevent the relevant
// private operation; denied signing is attempted once with no retry/fallback.
func TestA2AIssueCLIRefusals(t *testing.T) {
	for _, mode := range []string{"overflow", "scope", "pin", "short-review", "denied", "newline", "unknown-flag"} {
		t.Run(mode, func(t *testing.T) {
			args, c, store := a2aCLIFixture(t)
			args[1] = "a2a-issue"
			var out, errout bytes.Buffer
			var review io.Writer = &errout
			wantFactories, wantSigns := 0, 0
			switch mode {
			case "overflow":
				c["subject"].(map[string]any)["account_mxid"] = "@" + strings.Repeat("a", 180) + ":example.invalid"
			case "scope":
				c["entries"].([]any)[0].(map[string]any)["action"] = "repository.delete"
			case "pin":
				c["subject"].(map[string]any)["spki_sha256"] = strings.Repeat("fe", 32)
			case "short-review":
				review = a2aShortWriter{}
				wantFactories = 1
			case "denied":
				store.deny = true
				wantFactories, wantSigns = 1, 1
			case "unknown-flag":
				args = append(args, "--force")
			}
			payload := a2aCLIBytes(t, c)
			if mode == "newline" {
				payload = append(payload, '\n')
			}
			if code := run(args, bytes.NewReader(payload), &out, review); code == 0 || store.factories != wantFactories || store.signs != wantSigns || out.Len() != 0 {
				t.Fatal(mode, code, store.factories, store.signs, out.String())
			}
		})
	}
}

type a2aShortWriter struct{}

func (a2aShortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

// Request preparation is public-only and binds the exact payload hash/domain;
// packing admits an independent valid fixture signature and rejects mutations.
func TestA2ARequestCLI(t *testing.T) {
	action := a2aCLIBytes(t, map[string]any{"name": grants.A2ARepository, "organization": "relux-works", "visibility": "private"})
	request := map[string]any{"version": "grants-a2a-request-1", "sender_mxid": "@requester:example.invalid", "audience": "@receiver:example.invalid", "room_id": "!room:example.invalid", "topic": "test-grant", "action": "repository.create", "resource": "github:relux-works/" + grants.A2ARepository, "nonce": strings.Repeat("ab", 32), "issued_at": "2026-11-04T14:00:00Z", "expires_at": "2026-11-04T14:05:00Z", "request_sha256": a2aCLIHash(action), "grant_registry_sha256": strings.Repeat("cd", 32)}
	raw := a2aCLIBytes(t, request)
	dir := t.TempDir()
	file := filepath.Join(dir, "action.json")
	if err := os.WriteFile(file, action, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"grants", "a2a-request-prepare", "--payload", "-", "--request", file}
	var out, errout bytes.Buffer
	previous := newIssueManager
	t.Cleanup(func() { newIssueManager = previous })
	newIssueManager = func(func([]byte) string) *keyvault.Manager { t.Fatal("request touched issuer"); return nil }
	if code := run(args, bytes.NewReader(raw), &out, &errout); code != 0 {
		t.Fatal(code, errout.String())
	}
	var result map[string]string
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte("swarma-grants/a2a-request/1\n"), raw...))
	if result["digest_sha256"] != hex.EncodeToString(want[:]) {
		t.Fatal("wrong domain digest", result)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, want[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		s.Sub(key.Params().N, s)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	sigFile, pubFile := filepath.Join(dir, "sig.der"), filepath.Join(dir, "key.der")
	for name, b := range map[string][]byte{sigFile: sig, pubFile: public} {
		if err := os.WriteFile(name, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	packArgs := []string{"grants", "a2a-request-pack", "--payload", "-", "--request", file, "--signature", sigFile, "--public-spki-der", pubFile}
	out.Reset()
	errout.Reset()
	if code := run(packArgs, bytes.NewReader(raw), &out, &errout); code != 0 {
		t.Fatal("valid pack", code, errout.String())
	}
	var wire map[string]string
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil || wire["payload"] != base64.RawURLEncoding.EncodeToString(raw) || wire["request"] != base64.RawURLEncoding.EncodeToString(action) || wire["signature"] != base64.RawURLEncoding.EncodeToString(sig) || wire["type"] != "grants-a2a-envelope-1" {
		t.Fatal("pack changed wire", err)
	}
	sig[len(sig)-1] ^= 1
	if err := os.WriteFile(sigFile, sig, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if code := run(packArgs, bytes.NewReader(raw), &out, &errout); code != 1 || out.Len() != 0 {
		t.Fatal("mutated pack signature", code, out.String())
	}
	request["request_sha256"] = strings.Repeat("00", 32)
	out.Reset()
	errout.Reset()
	if code := run(args, bytes.NewReader(a2aCLIBytes(t, request)), &out, &errout); code != 1 || out.Len() != 0 || !strings.Contains(errout.String(), "a2a-context-mismatch") {
		t.Fatal("changed action hash", code, out.String(), errout.String())
	}
}
