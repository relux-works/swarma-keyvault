package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

const muAttestMXID = "@agent:example.invalid"

func muSPKI(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func muAttestSpec(kind, issuer string) map[string]any {
	m := map[string]any{"kind": kind, "issuer": issuer, "not_before": "2026-11-05T17:00:00Z", "expires": "2027-11-06T17:00:00Z"}
	if kind == "mac-agent" {
		m["mxid"], m["generation"] = muAttestMXID, 1
	}
	return m
}

func muAttestPrepare(t *testing.T, spec map[string]any, spki []byte, owner *ecdsa.PrivateKey) (int, map[string]string, string) {
	t.Helper()
	code, out, errText := muCLIRun(append([]string{"grants", "mu-attestation-prepare", "--spec", muCLIWrite(t, "spec.json", spec), "--subject-spki-der", muCLIWrite(t, "subject.der", spki)}, muPrepareOwnerArgs(t, owner)...)...)
	var p map[string]string
	if code == 0 {
		if err := json.Unmarshal([]byte(out), &p); err != nil {
			t.Fatal(err, out)
		}
	}
	return code, p, errText
}

// Claim: for both kinds, mu-attestation-prepare emits exactly the body of the
// mugrant builder that the docking tests verify through the platform verifier
// (builders take no nonce, so equal inputs give equal bytes), reports the
// subject key id of the given SPKI, and assembles under the owner root into a
// record whose signature verifies under that root; a foreign signature does
// not assemble.
func TestMUCLIAttestationRoundTrip(t *testing.T) {
	rk, root := muCLIKey(t)
	sk, _ := muCLIKey(t)
	spki := muSPKI(t, sk)
	wantSubject, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	nb, ex := time.Date(2026, 11, 5, 17, 0, 0, 0, time.UTC), time.Date(2027, 11, 6, 17, 0, 0, 0, time.UTC)
	agentPlan, _, err := mugrant.BuildMacAgentAttestation(root, spki, muAttestMXID, 1, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	pubPlan, _, err := mugrant.BuildPublisherAttestation(root, spki, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[string]*mugrant.Plan{"mac-agent": agentPlan, "publisher": pubPlan} {
		code, p, errText := muAttestPrepare(t, muAttestSpec(kind, root), spki, rk)
		if code != 0 || p["type"] != "mu-attestation-prepared-1" || p["kind"] != "attestation/1" || p["key"] != root || p["subject_key"] != wantSubject {
			t.Fatal("prepare", kind, code, errText, p)
		}
		body, _ := base64.RawURLEncoding.DecodeString(p["body"])
		if !bytes.Equal(body, want.Body()) || p["content_id"] != want.ContentID() {
			t.Fatal("body differs from the docked builder", kind)
		}
		if !strings.Contains(p["rendering"], "subject key: "+wantSubject) || !strings.Contains(p["rendering"], p["digest_sha256"]) ||
			!strings.Contains(p["rendering"], "subject key fingerprint (as mac-keyvault prints it): "+signerclient.Fingerprint(spki)) ||
			!strings.Contains(p["rendering"], "window MSK: 05.11.2026 20:00–06.11.2027 20:00 MSK") {
			t.Fatal("rendering", kind, p["rendering"])
		}
		code, wire, errText := muSignAndAssemble(t, p, rk)
		if code != 0 {
			t.Fatal("assemble", kind, code, errText)
		}
		parsed, err := record.Parse([]byte(wire), mugrant.MaxEnvelopeBytes, 16)
		if err != nil {
			t.Fatal(err)
		}
		e := parsed.(map[string]any)
		sig := e["signatures"].([]any)[0].(map[string]any)
		raw64, err := record.DecodeBase64(sig["sig"].(string), 64)
		if err != nil {
			t.Fatal(err)
		}
		pre, err := record.SigningPreimage("attestation/1", root, "author", e["body"].(map[string]any))
		if err != nil || record.VerifySignature(root, raw64, pre) != nil || e["id"] != p["content_id"] {
			t.Fatal("assembled attestation does not verify under the root", kind, err)
		}
		other, _ := muCLIKey(t)
		if code, _, _ := muSignAndAssemble(t, p, other); code == 0 {
			t.Fatal("foreign signature assembled", kind)
		}
	}
}

// Claim: every malformed attestation request refuses with exit 1 and no
// output, beside valid controls for both kinds; usage errors exit 2.
func TestMUCLIAttestationRefusals(t *testing.T) {
	rk, root := muCLIKey(t)
	sk, subject := muCLIKey(t)
	spki := muSPKI(t, sk)
	for _, kind := range []string{"mac-agent", "publisher"} {
		if code, _, errText := muAttestPrepare(t, muAttestSpec(kind, root), spki, rk); code != 0 {
			t.Fatal("valid control refused", kind, errText)
		}
	}
	cases := map[string]func(m map[string]any){
		"unknown-field":       func(m map[string]any) { m["max_uses"] = 3 },
		"unknown-kind":        func(m map[string]any) { m["kind"] = "operator" },
		"window-367d":         func(m map[string]any) { m["expires"] = "2027-11-07T17:00:00Z" },
		"inverted-window":     func(m map[string]any) { m["expires"] = "2026-11-05T16:00:00Z" },
		"non-exact-time":      func(m map[string]any) { m["not_before"] = "2026-11-05T17:00:00+00:00" },
		"bad-mxid":            func(m map[string]any) { m["mxid"] = "invalid-principal" },
		"generation-zero":     func(m map[string]any) { m["generation"] = 0 },
		"bad-issuer":          func(m map[string]any) { m["issuer"] = "p256:AAAA" },
		"issuer-is-subject":   func(m map[string]any) { m["issuer"] = subject },
		"publisher-with-mxid": func(m map[string]any) { m["kind"] = "publisher" },
	}
	for name, mutate := range cases {
		m := muAttestSpec("mac-agent", root)
		mutate(m)
		code, out, _ := muCLIRun(append([]string{"grants", "mu-attestation-prepare", "--spec", muCLIWrite(t, "spec.json", m), "--subject-spki-der", muCLIWrite(t, "s.der", spki)}, muPrepareOwnerArgs(t, rk)...)...)
		if code != 1 || out != "" {
			t.Error("refusal expected", name, code)
		}
	}
	for name, key := range map[string][]byte{"garbage": []byte("not a key"), "truncated": spki[:40], "oversize": bytes.Repeat([]byte{1}, muSPKIMax+1)} {
		if code, _, _ := muAttestPrepare(t, muAttestSpec("mac-agent", root), key, rk); code != 1 {
			t.Error("bad subject key admitted", name)
		}
	}
	for _, args := range [][]string{
		{"--spec", muCLIWrite(t, "s.json", muAttestSpec("publisher", root))},
		{"--subject-spki-der", muCLIWrite(t, "k.der", spki)},
		{"--spec", "-", "--subject-spki-der", muCLIWrite(t, "k.der", spki)},
	} {
		if code, _, _ := muCLIRun(append([]string{"grants", "mu-attestation-prepare"}, args...)...); code != 2 {
			t.Error("usage error not exit 2", args)
		}
	}
}

// Claim: mu-key-id reports the same p256 id as the builders for an SPKI DER
// key and refuses anything else.
func TestMUCLIKeyID(t *testing.T) {
	k, id := muCLIKey(t)
	code, out, errText := muCLIRun("grants", "mu-key-id", "--subject-spki-der", muCLIWrite(t, "k.der", muSPKI(t, k)))
	if code != 0 || out != `{"key":"`+id+`","type":"mu-key-id-1"}`+"\n" {
		t.Fatal(code, out, errText)
	}
	if code, out, _ := muCLIRun("grants", "mu-key-id", "--subject-spki-der", muCLIWrite(t, "k.der", []byte("x"))); code != 1 || out != "" {
		t.Fatal("garbage key admitted", code)
	}
	for name, args := range map[string][]string{
		"no-flag":    {},
		"stdin":      {"--subject-spki-der", "-"},
		"positional": {"--subject-spki-der", muCLIWrite(t, "k.der", muSPKI(t, k)), "extra"},
		"repeated":   {"--subject-spki-der", "a", "--subject-spki-der", "b"},
	} {
		if code, out, _ := muCLIRun(append([]string{"grants", "mu-key-id"}, args...)...); code != 2 || out != "" {
			t.Error("usage not exit 2", name, code)
		}
	}
}
