package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

func muEd25519SPKI(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

// Claim: mu-attestation-prepare with kind publisher-ed25519 emits exactly the
// mugrant grant-revocation-2 body for an Ed25519 SPKI, with the Ed25519 key id
// as subject key. The rendering names the profile, the signing service and
// the SPKI fingerprint without claiming mac-keyvault printed it. The record
// assembled under the owner root verifies as a publisher attestation.
// Refused (exit 1, no output): an Ed25519 SPKI under kind publisher, a P-256
// SPKI under kind publisher-ed25519, and an mxid in a publisher-ed25519 spec.
func TestMUCLIEd25519PublisherAttestation(t *testing.T) {
	rk, root := muCLIKey(t)
	edSPKI := muEd25519SPKI(t)
	nb, ex := time.Date(2026, 11, 5, 17, 0, 0, 0, time.UTC), time.Date(2027, 11, 6, 17, 0, 0, 0, time.UTC)
	want, subject, err := mugrant.BuildEd25519PublisherAttestation(root, edSPKI, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	code, p, errText := muAttestPrepare(t, muAttestSpec("publisher-ed25519", root), edSPKI, rk)
	if code != 0 || p["kind"] != "attestation/1" || p["key"] != root || p["subject_key"] != subject || !strings.HasPrefix(subject, "ed25519:") {
		t.Fatal("prepare", code, errText, p)
	}
	body, _ := base64.RawURLEncoding.DecodeString(p["body"])
	if !bytes.Equal(body, want.Body()) || p["content_id"] != want.ContentID() {
		t.Fatal("body differs from the mugrant builder")
	}
	for _, line := range []string{
		"Ed25519 grant revocation publisher key (profile grant-revocation-2), held by a signing service",
		"subject key fingerprint (SHA-256 of the Ed25519 SPKI DER): " + mugrant.Fingerprint(edSPKI),
		"subject key: " + subject,
	} {
		if !strings.Contains(p["rendering"], line) {
			t.Fatal("rendering lacks", line, p["rendering"])
		}
	}
	if strings.Contains(p["rendering"], "as mac-keyvault prints it") {
		t.Fatal("rendering claims a mac-keyvault fingerprint for an Ed25519 key")
	}
	code, wire, errText := muSignAndAssemble(t, p, rk)
	if code != 0 {
		t.Fatal("assemble", code, errText)
	}
	if a, err := mugrant.VerifyPublisherAttestation([]byte(wire), root); err != nil || a.Key != subject {
		t.Fatal("assembled attestation is not a publisher attestation of the root", err)
	}

	sk, _ := muCLIKey(t)
	p256 := muSPKI(t, sk)
	withMXID := muAttestSpec("publisher-ed25519", root)
	withMXID["mxid"] = muAttestMXID
	for name, c := range map[string]struct {
		spec map[string]any
		spki []byte
	}{
		"ed25519-under-publisher":   {muAttestSpec("publisher", root), edSPKI},
		"p256-under-ed25519-kind":   {muAttestSpec("publisher-ed25519", root), p256},
		"mxid-in-ed25519-publisher": {withMXID, edSPKI},
	} {
		if code, out, _ := muAttestPrepare(t, c.spec, c.spki, rk); code != 1 || out != nil {
			t.Error("refusal expected", name, code, out)
		}
	}
}
