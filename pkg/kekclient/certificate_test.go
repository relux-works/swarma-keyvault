package kekclient

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const certificatePin = "0123456789abcdef0123456789abcdef01234567"

func certificateForm(identifier, pin string) string {
	return `certificate leaf = H"` + pin + `" and identifier "` + identifier + `"`
}

// The agreed serialized form admits every supported identifier shape and only
// lowercase full fingerprints. Nearby malformed or broader expressions refuse.
// These are grammar tests; they do not attest a caller's native code signature.
func TestCertificateRequirementAdmission(t *testing.T) {
	for _, id := range []string{
		"works.relux.network-proxy", "works.relux.mac-infra.keyvault-kek",
		"works.relux.mac-infra.mac-firewall", "works.relux.mac-infra.safari-session",
		"works.relux.mac-infra.browser-session", "A", "1", "A_B.C-d",
		strings.Repeat("a", 255),
	} {
		req := certificateForm(id, certificatePin)
		if !ValidRequirement(req) {
			t.Errorf("valid identifier %q refused", id)
		}
		if hash, ok := RequirementCDHash(req); ok || hash != "" {
			t.Errorf("certificate form invented a cdhash: %q, %v", hash, ok)
		}
		gotID, gotPin, ok := RequirementCertificate(req)
		if !ok || gotID != id || gotPin != certificatePin {
			t.Errorf("parse %q = %q, %q, %v", id, gotID, gotPin, ok)
		}
		built, err := RequirementForCertificate(id, strings.ToUpper(certificatePin))
		if err != nil || built != req {
			t.Errorf("build %q = %q, %v", id, built, err)
		}
	}
	for _, id := range []string{"", "_a", ".a", "-a", strings.Repeat("a", 256), "a/b", "a b", "a\tb", "a\nb", "a\x00b", "a\"b", "a\\b", "a*", "é"} {
		if ValidRequirement(certificateForm(id, certificatePin)) {
			t.Errorf("invalid identifier %q accepted", id)
		}
		if req, err := RequirementForCertificate(id, certificatePin); err == nil || req != "" {
			t.Errorf("constructor accepted invalid identifier %q", id)
		}
	}
	base := certificateForm("works.relux.network-proxy", certificatePin)
	for _, req := range []string{
		certificateForm("a", strings.ToUpper(certificatePin)),
		certificateForm("a", certificatePin[:39]),
		certificateForm("a", certificatePin+"0"),
		certificateForm("a", strings.Repeat("g", 40)),
		certificateForm("a", " "+certificatePin),
		base + "\n", " " + base, base + " ",
		strings.Replace(base, "leaf", "0", 1),
		strings.Replace(base, " = ", "=", 1),
		strings.Replace(base, " and ", " or ", 1),
		strings.Replace(base, " and ", "  and ", 1),
		strings.Replace(base, `H"`, `h"`, 1),
		base + " and anchor trusted", base + " or anchor apple",
		`identifier "works.relux.network-proxy"`,
		`certificate leaf = H"` + certificatePin + `"`,
	} {
		if ValidRequirement(req) {
			t.Errorf("noncanonical requirement %q accepted", req)
		}
		if id, pin, ok := RequirementCertificate(req); ok || id != "" || pin != "" {
			t.Errorf("parser returned fields for invalid form %q", req)
		}
	}
}

// The new form preserves the existing encryption/header/KCV contract and
// requires an independently valid requirement on both provisioning and parse.
// All keys here are ephemeral Go fixtures, without Security.framework access.
func TestCertificatePayloadRoundtrip(t *testing.T) {
	k := newTestKey(t)
	spec := testSpec(k)
	spec.Requirement = certificateForm("works.relux.network-proxy", certificatePin)
	sealed, err := Wrap(spec, testKEK())
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope(sealed)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := k.open(env.ECIES)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	payload, err := ParsePayload(plain, env)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload.KEK)
	if payload.Requirement != spec.Requirement || !bytes.Equal(payload.KEK, testKEK()) || !MatchesKCV(payload.KEK, env.KCV) {
		t.Fatal("certificate payload lost its binding or KEK")
	}
	for _, bad := range []string{certificateForm("a/b", certificatePin), spec.Requirement + " or anchor apple"} {
		spec.Requirement = bad
		if out, err := Wrap(spec, testKEK()); err == nil || out != nil {
			t.Fatal("provisioned a malformed certificate binding")
		}
		payload.Requirement = bad
		altered, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePayload(altered, env)
		clear(altered)
		// ParsePayload's existing API returns partially decoded data on error;
		// its caller owns clearing it and must never publish a rejected result.
		clear(got.KEK)
		if err == nil {
			t.Fatal("parse accepted a malformed binding")
		}
	}
}

// The certificate parser cannot reinterpret an existing legacy binding, and
// the constructor cannot admit extra syntax through its fingerprint argument.
func TestCertificateConstructorRefusalsAndLegacy(t *testing.T) {
	legacy, err := RequirementForCDHash(testCDHash)
	if err != nil {
		t.Fatal(err)
	}
	if id, pin, ok := RequirementCertificate(legacy); ok || id != "" || pin != "" {
		t.Fatal("legacy binding became certificate mode")
	}
	for _, pin := range []string{"", certificatePin[:39], certificatePin + "0", strings.Repeat("g", 40), " " + certificatePin, certificatePin + "\n", certificatePin + `" and identifier "other`} {
		if req, err := RequirementForCertificate("valid.identifier", pin); err == nil || req != "" {
			t.Errorf("bad fingerprint accepted: %q", pin)
		}
	}
}
