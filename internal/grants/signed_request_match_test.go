package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// Process-local software fixture signatures and all eight declared uses pass
// the composed check. No actual enrollment, receiver, lifecycle, receipt or
// provider effect is exercised; context/time are explicit unauthenticated inputs.
func TestSignedRequestMatchFourCycles(t *testing.T) {
	key, spki, issuerFixture := certificateSignatureFixture(t)
	pin := publicIssuerPin{ownerMXID: "@owner:example.invalid", spkiDER: spki}
	for _, runtime := range []string{"claude", "codex"} {
		for _, channel := range []string{"dm", "group"} {
			for _, action := range []string{"repository.create", "repository.delete"} {
				t.Run(runtime+"/"+channel+"/"+action, func(t *testing.T) {
					certificate, request := declaredMatchFixture(action, runtime+"-"+channel)
					certificate["issuer"] = issuerFixture["issuer"]
					envelope := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
					if err := checkSignedRequestMatch(envelope, requestTestBytes(t, request), pin, runtime, "encrypted-"+channel, declaredMatchTime()); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

// Crypto, schema and request predicates all remain necessary when composed.
// Every refusal has its intended class and valid before/after controls; exact
// input and pin bytes stay unchanged. Signing uses only ephemeral test keys.
func TestSignedRequestMatchRefusals(t *testing.T) {
	key, spki, certificate := certificateSignatureFixture(t)
	_, request := declaredMatchFixture("repository.create", "claude-dm")
	valid := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	goodRequest := requestTestBytes(t, request)
	pin := publicIssuerPin{ownerMXID: "@owner:example.invalid", spkiDER: spki}
	beforeValid, beforeGoodRequest, beforeSPKI := bytes.Clone(valid), bytes.Clone(goodRequest), bytes.Clone(spki)
	other, otherSPKI, _ := certificateSignatureFixture(t)
	requestWith := func(field string, value any) []byte {
		_, r := declaredMatchFixture("repository.create", "claude-dm")
		r[field] = value
		return requestTestBytes(t, r)
	}
	var unsigned map[string]any
	if err := json.Unmarshal(valid, &unsigned); err != nil {
		t.Fatal(err)
	}
	delete(unsigned, "signature")
	for _, test := range []struct {
		name              string
		envelope, request []byte
		pin               publicIssuerPin
		runtime, channel  string
		want              error
	}{
		{"wrong-signing-key", signedCertificateFixture(t, other, certificate, "swarma-grants/certificate/1"), goodRequest, pin, "claude", "encrypted-dm", errSignatureInvalid},
		{"wrong-domain", signedCertificateFixture(t, key, certificate, "swarma-grants/revocation/1"), goodRequest, pin, "claude", "encrypted-dm", errSignatureInvalid},
		{"wrong-pin", valid, goodRequest, publicIssuerPin{pin.ownerMXID, otherSPKI}, "claude", "encrypted-dm", errIssuerUntrusted},
		{"wrong-owner", valid, goodRequest, publicIssuerPin{"@other:example.invalid", spki}, "claude", "encrypted-dm", errIssuerUntrusted},
		{"unsigned", requestTestBytes(t, unsigned), goodRequest, pin, "claude", "encrypted-dm", errBadSchema},
		{"noncanonical-envelope", append(bytes.Clone(valid), '\n'), goodRequest, pin, "claude", "encrypted-dm", errBadEncoding},
		{"noncanonical-request", valid, append(bytes.Clone(goodRequest), '\n'), pin, "claude", "encrypted-dm", errBadEncoding},
		{"certificate-id", valid, requestWith("certificate_id", "other-certificate"), pin, "claude", "encrypted-dm", errScheduleMismatch},
		{"subject", valid, requestWith("subject", map[string]any{"account_mxid": "@other:example.invalid", "device_id": "DEVICE-A", "device_ed25519": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}), pin, "claude", "encrypted-dm", errSubjectMismatch},
		{"audience", valid, requestWith("audience", map[string]any{"deployment_id": "other", "executor_id": "executor-A"}), pin, "claude", "encrypted-dm", errAudienceMismatch},
		{"repository", valid, requestWith("target", map[string]any{"organization": "ExampleOrg", "name": "other-repository", "visibility": "private"}), pin, "claude", "encrypted-dm", errResourceMismatch},
		{"runtime", valid, goodRequest, pin, "codex", "encrypted-dm", errScheduleMismatch},
		{"channel", valid, goodRequest, pin, "claude", "encrypted-group", errScheduleMismatch},
		{"request-expired", valid, requestWith("expires_at", "2026-11-02T11:00:00Z"), pin, "claude", "encrypted-dm", ErrExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			good := func() {
				t.Helper()
				if err := checkSignedRequestMatch(valid, goodRequest, pin, "claude", "encrypted-dm", declaredMatchTime()); err != nil {
					t.Fatal("valid neighbor", err)
				}
			}
			good()
			beforeEnvelope, beforeRequest, beforePin := bytes.Clone(test.envelope), bytes.Clone(test.request), bytes.Clone(test.pin.spkiDER)
			if err := checkSignedRequestMatch(test.envelope, test.request, test.pin, test.runtime, test.channel, declaredMatchTime()); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if !bytes.Equal(test.envelope, beforeEnvelope) || !bytes.Equal(test.request, beforeRequest) || !bytes.Equal(test.pin.spkiDER, beforePin) {
				t.Fatal("refused input changed")
			}
			good()
		})
	}
	if !bytes.Equal(valid, beforeValid) || !bytes.Equal(goodRequest, beforeGoodRequest) || !bytes.Equal(spki, beforeSPKI) {
		t.Fatal("valid input changed")
	}
}

// A changed canonical certificate cannot retain the old signature even when
// the request matches the changed fields. Conversely a valid signed different
// target cannot be replaced by an unsigned matching payload at this interface.
func TestSignedRequestMatchExactVerifiedPayload(t *testing.T) {
	key, spki, certificate := certificateSignatureFixture(t)
	_, request := declaredMatchFixture("repository.create", "claude-dm")
	valid := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	pin := publicIssuerPin{"@owner:example.invalid", spki}
	var envelope map[string]any
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	certificate["entries"].([]any)[0].(map[string]any)["target"].(map[string]any)["name"] = "other-repository"
	certificate["entries"].([]any)[1].(map[string]any)["target"].(map[string]any)["name"] = "other-repository"
	request["target"].(map[string]any)["name"] = "other-repository"
	matchingRequest := requestTestBytes(t, request)
	if err := checkDeclaredRequestMatch(requestTestBytes(t, certificate), matchingRequest, "claude", "encrypted-dm", declaredMatchTime()); err != nil {
		t.Fatal("changed declarations match", err)
	}
	envelope["payload"] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, certificate))
	if err := checkSignedRequestMatch(requestTestBytes(t, envelope), matchingRequest, pin, "claude", "encrypted-dm", declaredMatchTime()); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("altered payload retained signature", err)
	}
	if err := checkSignedRequestMatch(valid, matchingRequest, pin, "claude", "encrypted-dm", declaredMatchTime()); !errors.Is(err, errResourceMismatch) {
		t.Fatal("matching must use signed target", err)
	}
	newSigned := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	if err := checkSignedRequestMatch(newSigned, matchingRequest, pin, "claude", "encrypted-dm", declaredMatchTime()); err != nil {
		t.Fatal("fresh valid signature control", err)
	}
}

// Exercise the paired-entry predicate below the decoder so an absent entry
// cannot silently pass even if upstream representation invariants change.
// The complete signed entry path independently rejects an absent pair today.
func TestPairedCreateDeclaresUse(t *testing.T) {
	certificate, _ := declaredMatchFixture("repository.delete", "claude-dm")
	parsed, err := parseCertificateProjection(requestTestBytes(t, certificate))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, entry, cycle, use string
		want                    bool
	}{
		{"valid", "repo-create", "claude-dm", "claude-dm/create", true},
		{"missing-entry", "missing", "claude-dm", "claude-dm/create", false},
		{"wrong-cycle", "repo-create", "codex-dm", "claude-dm/create", false},
		{"wrong-use", "repo-create", "claude-dm", "missing", false},
		{"delete-entry", "repo-delete", "claude-dm", "claude-dm/delete", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pairedCreateDeclaresUse(parsed.entries, test.entry, test.cycle, test.use); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
	if pairedCreateDeclaresUse(nil, "repo-create", "claude-dm", "claude-dm/create") {
		t.Fatal("empty entries accepted")
	}
	key, spki, signedCertificate := certificateSignatureFixture(t)
	signedCertificate["entries"] = signedCertificate["entries"].([]any)[1:]
	_, request := declaredMatchFixture("repository.delete", "claude-dm")
	if err := checkSignedRequestMatch(signedCertificateFixture(t, key, signedCertificate, "swarma-grants/certificate/1"), requestTestBytes(t, request), publicIssuerPin{"@owner:example.invalid", spki}, "claude", "encrypted-dm", declaredMatchTime()); !errors.Is(err, errBadSchema) {
		t.Fatal("signed missing pair", err)
	}
}
