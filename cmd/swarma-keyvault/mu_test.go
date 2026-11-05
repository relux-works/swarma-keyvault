package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

func muCLIKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // software stand-in, tests only
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	id, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	return k, id
}

func muCLIWrite(t *testing.T, name string, v any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	raw, ok := v.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func muCLIRun(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func muGrantSpecMap(issuer, subject string) map[string]any {
	return map[string]any{
		"issuer": issuer, "subject": subject, "subject_mxid": "@meta-keeper.keeper-sirius:gr.relux.works", "audience": "swarma-keyvault-receiver",
		"entries":    []any{map[string]any{"action": "work.assign", "kind": "product", "id": "swarma-platform"}},
		"not_before": "2026-11-05T17:00:00Z", "expires": "2027-11-05T17:00:00Z", "use": "until_expiry",
	}
}

// muSignAndAssemble signs the prepared digest with k and runs mu-assemble.
func muSignAndAssemble(t *testing.T, prepared map[string]string, k *ecdsa.PrivateKey) (int, string, string) {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(prepared["body"])
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(prepared["digest_sha256"])
	if err != nil {
		t.Fatal(err)
	}
	der, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		t.Fatal(err)
	}
	return muCLIRun("grants", "mu-assemble", "--kind", prepared["kind"], "--body", muCLIWrite(t, "body.json", body), "--key", prepared["key"], "--signature", muCLIWrite(t, "sig.der", der))
}

// Claim: mu-grant-prepare prints the canonical body, digest, the Touch ID
// reason and the pre-sign rendering; signing that digest with the issuer key
// and mu-assemble yields a swarm-envelope/2 grant; a signature by another key
// is refused.
func TestMUCLIGrantRoundTrip(t *testing.T) {
	ik, issuer := muCLIKey(t)
	_, subject := muCLIKey(t)
	code, out, errText := muCLIRun("grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "spec.json", muGrantSpecMap(issuer, subject)))
	if code != 0 {
		t.Fatal(code, errText)
	}
	var p map[string]string
	if err := json.Unmarshal([]byte(out), &p); err != nil || p["type"] != "mu-grant-prepared-1" || !strings.HasPrefix(p["reason"], "до срока · @meta-keeper") || !strings.Contains(p["rendering"], "use policy: until_expiry") {
		t.Fatal("prepared output", err, out)
	}
	code, wire, errText := muSignAndAssemble(t, p, ik)
	if code != 0 || !strings.Contains(wire, `"version":"swarm-envelope/2"`) || !strings.Contains(wire, `"id":"`+p["content_id"]+`"`) {
		t.Fatal("assemble", code, errText, wire)
	}
	other, _ := muCLIKey(t)
	if code, _, _ := muSignAndAssemble(t, p, other); code == 0 {
		t.Fatal("foreign signature assembled")
	}
}

// Claim: mu-request-prepare builds a message/1 under the author key and binds
// the exact text; assemble accepts only the author's signature.
func TestMUCLIRequestRoundTrip(t *testing.T) {
	ak, author := muCLIKey(t)
	spec := map[string]any{"author": author, "author_attestation": "sha256:" + strings.Repeat("cd", 32), "audience": "swarma-keyvault-receiver",
		"room": "!room:gr.relux.works", "to": "@keyvault.orch-altair:gr.relux.works", "action": "work.assign", "kind": "product", "id": "swarma-platform",
		"arguments": map[string]string{"module": "swarma-keyvault", "title": "Review"}, "text": "assign: review", "issued_at": "2026-11-05T17:00:00Z", "lifetime_seconds": 120}
	code, out, errText := muCLIRun("grants", "mu-request-prepare", "--spec", muCLIWrite(t, "req.json", spec))
	if code != 0 {
		t.Fatal(code, errText)
	}
	var p map[string]string
	if err := json.Unmarshal([]byte(out), &p); err != nil || p["kind"] != "message/1" || p["text"] != "assign: review" {
		t.Fatal("prepared request", err, out)
	}
	if code, _, errText := muSignAndAssemble(t, p, ak); code != 0 {
		t.Fatal("author signature refused", errText)
	}
	other, _ := muCLIKey(t)
	if code, _, _ := muSignAndAssemble(t, p, other); code == 0 {
		t.Fatal("foreign request signature assembled")
	}
}

// Claim: specifications with unknown fields, non-exact times, an over-cap
// interval or missing arguments are refused with a non-zero exit and no
// stdout, beside the valid control above.
func TestMUCLIRefusals(t *testing.T) {
	_, issuer := muCLIKey(t)
	_, subject := muCLIKey(t)
	unknown := muGrantSpecMap(issuer, subject)
	unknown["max_uses"] = 5
	badTime := muGrantSpecMap(issuer, subject)
	badTime["not_before"] = "2026-11-05 17:00:00"
	overCap := muGrantSpecMap(issuer, subject)
	overCap["expires"] = "2027-11-05T17:00:01Z"
	for name, spec := range map[string]map[string]any{"unknown-field": unknown, "bad-time": badTime, "over-cap": overCap} {
		if code, out, _ := muCLIRun("grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", spec)); code == 0 || out != "" {
			t.Fatal("spec admitted", name, code, out)
		}
	}
	for name, args := range map[string][]string{
		"no-spec":       {"grants", "mu-grant-prepare"},
		"stdin-spec":    {"grants", "mu-grant-prepare", "--spec", "-"},
		"repeated-spec": {"grants", "mu-grant-prepare", "--spec", "a", "--spec", "b"},
		"bad-kind":      {"grants", "mu-assemble", "--kind", "operator-act/1", "--body", "b", "--key", "k", "--signature", "s"},
	} {
		if code, out, _ := muCLIRun(args...); code != 2 || out != "" {
			t.Fatal("usage not refused", name, code, out)
		}
	}
}
