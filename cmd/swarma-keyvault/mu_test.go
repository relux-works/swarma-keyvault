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
	"time"

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

func muPrepareOwnerArgs(t *testing.T, owner *ecdsa.PrivateKey) []string {
	t.Helper()
	return []string{"--owner-key", "synthetic-mu-owner/grants-owner-v1", "--owner-key-version", "12", "--owner-spki-der", muCLIWrite(t, "prepare-owner.der", muSPKI(t, owner))}
}

func muCLIRun(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func muGrantSpecMap(issuer, subject string) map[string]any {
	return map[string]any{
		"issuer": issuer, "subject": subject, "subject_mxid": "@agent:example.invalid", "audience": "swarma-keyvault-receiver",
		"entries":    []any{map[string]any{"action": "work.assign", "kind": "product", "id": "swarma-platform"}},
		"not_before": "2026-11-05T17:00:00Z", "expires": "2027-11-05T17:00:00Z", "use": "until_expiry",
	}
}

// muAttestFiles signs, under the issuer key, a Mac agent attestation of the
// subject key for mxid and a publisher attestation of a fresh key, both with a
// 366-day window from the spec start, and returns the two flags.
func muAttestFiles(t *testing.T, ik *ecdsa.PrivateKey, issuer string, sk *ecdsa.PrivateKey, mxid string) []string {
	t.Helper()
	nb := time.Date(2026, 11, 5, 17, 0, 0, 0, time.UTC)
	ex := nb.Add(mugrant.MaxAttestationWindow)
	sign := func(p *mugrant.Plan) []byte {
		d := p.Digest()
		der, err := ecdsa.SignASN1(rand.Reader, ik, d[:])
		if err != nil {
			t.Fatal(err)
		}
		w, err := mugrant.AssembleNative(p, der)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	subjectSPKI, _ := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	ap, _, err := mugrant.BuildMacAgentAttestation(issuer, subjectSPKI, mxid, 1, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := muCLIKey(t)
	publisherSPKI, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pp, _, err := mugrant.BuildPublisherAttestation(issuer, publisherSPKI, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	return []string{"--subject-attestation", muCLIWrite(t, "agent.json", sign(ap)), "--publisher-attestation", muCLIWrite(t, "publisher.json", sign(pp))}
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
	sk, subject := muCLIKey(t)
	args := append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "spec.json", muGrantSpecMap(issuer, subject))}, muAttestFiles(t, ik, issuer, sk, "@agent:example.invalid")...)
	code, out, errText := muCLIRun(append(args, muPrepareOwnerArgs(t, ik)...)...)
	if code != 0 {
		t.Fatal(code, errText)
	}
	var p map[string]string
	if err := json.Unmarshal([]byte(out), &p); err != nil || p["type"] != "mu-grant-prepared-1" || !strings.HasPrefix(p["reason"], "до срока · @agent:example.invalid") || !strings.Contains(p["rendering"], "use policy: until_expiry") || !strings.Contains(p["rendering"], "revocation publisher key fingerprint (as mac-keyvault prints it): ") || !strings.Contains(p["rendering"], "grantee: @agent:example.invalid (generation 1, from attestation sha256:") {
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
		"room": "!room:example.invalid", "to": "@agent:example.invalid", "action": "work.assign", "kind": "product", "id": "swarma-platform",
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
	ik, issuer := muCLIKey(t)
	sk, subject := muCLIKey(t)
	attest := append(muAttestFiles(t, ik, issuer, sk, "@agent:example.invalid"), muPrepareOwnerArgs(t, ik)...)
	if code, _, errText := muCLIRun(append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", muGrantSpecMap(issuer, subject))}, attest...)...); code != 0 {
		t.Fatal("valid control refused", errText)
	}
	otherRoot, otherID := muCLIKey(t)
	mismatch := muGrantSpecMap(issuer, subject)
	mismatch["subject_mxid"] = "@other-agent:example.invalid"
	unknown := muGrantSpecMap(issuer, subject)
	unknown["max_uses"] = 5
	badTime := muGrantSpecMap(issuer, subject)
	badTime["not_before"] = "2026-11-05 17:00:00"
	overCap := muGrantSpecMap(issuer, subject)
	overCap["expires"] = "2027-11-05T17:00:01Z"
	for name, spec := range map[string]map[string]any{"unknown-field": unknown, "bad-time": badTime, "over-cap": overCap, "mxid-not-attested": mismatch} {
		if code, out, _ := muCLIRun(append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", spec)}, attest...)...); code != 1 || out != "" {
			t.Fatal("spec admitted", name, code, out)
		}
	}
	// Attestations signed by another root do not bind this issuer's grant.
	foreign := muAttestFiles(t, otherRoot, otherID, sk, "@agent:example.invalid")
	foreign = append(foreign, muPrepareOwnerArgs(t, ik)...)
	if code, out, _ := muCLIRun(append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", muGrantSpecMap(issuer, subject))}, foreign...)...); code != 1 || out != "" {
		t.Fatal("foreign-root attestations admitted", code)
	}
	// The two attestations swapped between the flags do not bind.
	swapped := []string{"--subject-attestation", attest[3], "--publisher-attestation", attest[1]}
	swapped = append(swapped, muPrepareOwnerArgs(t, ik)...)
	if code, out, _ := muCLIRun(append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", muGrantSpecMap(issuer, subject))}, swapped...)...); code != 1 || out != "" {
		t.Fatal("swapped attestations admitted", code)
	}
	// A grant starting before the attestation window is not covered by it.
	early := muGrantSpecMap(issuer, subject)
	early["not_before"], early["expires"] = "2026-11-05T16:59:59Z", "2027-11-05T16:59:59Z"
	if code, out, _ := muCLIRun(append([]string{"grants", "mu-grant-prepare", "--spec", muCLIWrite(t, "s.json", early)}, attest...)...); code != 1 || out != "" {
		t.Fatal("grant outside the attestation window admitted", code)
	}
	for name, args := range map[string][]string{
		"no-spec":         append([]string{"grants", "mu-grant-prepare"}, attest...),
		"stdin-spec":      append([]string{"grants", "mu-grant-prepare", "--spec", "-"}, attest...),
		"repeated-spec":   append([]string{"grants", "mu-grant-prepare", "--spec", "a", "--spec", "b"}, attest...),
		"no-attestations": {"grants", "mu-grant-prepare", "--spec", "a"},
		"no-publisher":    {"grants", "mu-grant-prepare", "--spec", "a", attest[0], attest[1]},
		"bad-kind":        {"grants", "mu-assemble", "--kind", "operator-act/1", "--body", "b", "--key", "k", "--signature", "s"},
	} {
		if code, out, _ := muCLIRun(args...); code != 2 || out != "" {
			t.Fatal("usage not refused", name, code, out)
		}
	}
}
