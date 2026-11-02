package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// Fixture keys exist only in this test process, never in a vault, file, output,
// registry or real deployment. They are not owner/agent credentials. Expected
// digest bytes are built independently of the production domainDigest helper.
func certificateSignatureFixture(t *testing.T) (*ecdsa.PrivateKey, []byte, map[string]any) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture key setup failed")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("fixture public key setup failed")
	}
	certificate, _ := declaredMatchFixture("repository.create", "claude-dm")
	pin := sha256.Sum256(spki)
	certificate["issuer"].(map[string]any)["key_id"] = "sha256:" + hex.EncodeToString(pin[:])
	return key, spki, certificate
}

func signedCertificateFixture(t *testing.T, key *ecdsa.PrivateKey, certificate map[string]any, domain string) []byte {
	t.Helper()
	payload := requestTestBytes(t, certificate)
	digest := sha256.Sum256(append([]byte(domain+"\n"), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal("fixture signing setup failed")
	}
	half := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Curve.Params().N, s)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal("fixture signature encoding failed")
	}
	return requestTestBytes(t, map[string]any{"type": "grants-signed-certificate-1", "payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}

// A complete canonical fixture verifies with its explicit exact owner/SPKI;
// wrong owner/pin, another signing key, altered signed payload and wrong domain
// refuse at the intended gate. This is component crypto evidence, not actual
// protected enrollment, revocation, receiver or effect qualification.
func TestCertificateSignatureWithPin(t *testing.T) {
	key, spki, certificate := certificateSignatureFixture(t)
	valid := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	checkGood := func() {
		t.Helper()
		if err := checkCertificateSignatureWithPin(valid, "@owner:example.invalid", spki); err != nil {
			t.Fatal("valid explicit-pin control", err)
		}
	}
	checkGood()
	other, otherSPKI, _ := certificateSignatureFixture(t)
	for _, test := range []struct {
		name, owner string
		raw, pin    []byte
		want        error
	}{
		{"wrong-owner", "@other:example.invalid", valid, spki, errIssuerUntrusted},
		{"owner-case", "@Owner:example.invalid", valid, spki, errIssuerUntrusted},
		{"wrong-public-pin", "@owner:example.invalid", valid, otherSPKI, errIssuerUntrusted},
		{"wrong-signing-key", "@owner:example.invalid", signedCertificateFixture(t, other, certificate, "swarma-grants/certificate/1"), spki, errSignatureInvalid},
		{"wrong-domain", "@owner:example.invalid", signedCertificateFixture(t, key, certificate, "swarma-grants/revocation/1"), spki, errSignatureInvalid},
		{"missing-owner", "", valid, spki, errIssuerUntrusted},
		{"missing-pin", "@owner:example.invalid", valid, nil, errIssuerUntrusted},
		{"oversized-pin", "@owner:example.invalid", valid, bytes.Repeat([]byte{1}, 1025), errIssuerUntrusted},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkGood()
			if err := checkCertificateSignatureWithPin(test.raw, test.owner, test.pin); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			checkGood()
		})
	}
	// Keep the old signature while changing a still-valid typed payload.
	var envelope map[string]any
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	certificate["certificate_id"] = "certificate-B"
	envelope["payload"] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, certificate))
	if err := checkCertificateSignatureWithPin(requestTestBytes(t, envelope), "@owner:example.invalid", spki); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("changed exact payload", err)
	}
	checkGood()
}

// Complete shape checks are mandatory even for correctly signed payload bytes;
// unsigned, incomplete, purpose-substituted and noncanonical documents cannot
// become accepted certificates by satisfying only the mathematical relation.
func TestCertificateSignatureRequiresCompleteCertificate(t *testing.T) {
	key, spki, certificate := certificateSignatureFixture(t)
	valid := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	var envelope map[string]any
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	delete(envelope, "signature")
	if err := checkCertificateSignatureWithPin(requestTestBytes(t, envelope), "@owner:example.invalid", spki); !errors.Is(err, errBadSchema) {
		t.Fatal("unsigned envelope", err)
	}
	delete(certificate, "entries")
	if err := checkCertificateSignatureWithPin(signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1"), "@owner:example.invalid", spki); !errors.Is(err, errBadSchema) {
		t.Fatal("signed incomplete payload", err)
	}
	_, _, certificate = certificateSignatureFixture(t)
	pin := sha256.Sum256(spki)
	certificate["issuer"].(map[string]any)["key_id"] = "sha256:" + hex.EncodeToString(pin[:])
	certificate["issuer"].(map[string]any)["purpose"] = "git-signing"
	if err := checkCertificateSignatureWithPin(signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1"), "@owner:example.invalid", spki); !errors.Is(err, errBadSchema) {
		t.Fatal("purpose substitution", err)
	}
	if err := checkCertificateSignatureWithPin(append(bytes.Clone(valid), '\n'), "@owner:example.invalid", spki); !errors.Is(err, errBadEncoding) {
		t.Fatal("noncanonical envelope", err)
	}
	if err := checkCertificateSignatureWithPin(valid, "@owner:example.invalid", spki); err != nil {
		t.Fatal("valid neighbor", err)
	}
}

// A key-ID matching the exact supplied bytes is insufficient when those bytes
// are malformed SPKI, another algorithm or another curve. No fallback is used.
func TestCertificateSignaturePublicKeyAllowlist(t *testing.T) {
	key, goodSPKI, certificate := certificateSignatureFixture(t)
	goodRaw := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("public fixture setup failed")
	}
	edSPKI, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatal("public fixture encoding failed")
	}
	curve := elliptic.P384()
	x, y := curve.ScalarBaseMult([]byte{1})
	p384SPKI, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y})
	if err != nil {
		t.Fatal("public curve fixture encoding failed")
	}
	for _, badSPKI := range [][]byte{[]byte("not DER"), edSPKI, p384SPKI, append(bytes.Clone(goodSPKI), 0)} {
		pin := sha256.Sum256(badSPKI)
		certificate["issuer"].(map[string]any)["key_id"] = "sha256:" + hex.EncodeToString(pin[:])
		raw := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
		if err := checkCertificateSignatureWithPin(raw, "@owner:example.invalid", badSPKI); !errors.Is(err, errIssuerUntrusted) {
			t.Fatal("unsupported exact-pin public key", err)
		}
		if err := checkCertificateSignatureWithPin(goodRaw, "@owner:example.invalid", goodSPKI); err != nil {
			t.Fatal("valid public-key neighbor", err)
		}
	}
}

// Verification retains no caller-owned mutable object and does not change any
// supplied envelope/public-key bytes on valid or rejected-pin paths.
func TestCertificateSignatureInputOwnership(t *testing.T) {
	key, spki, certificate := certificateSignatureFixture(t)
	raw := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	beforeRaw, beforeSPKI := bytes.Clone(raw), bytes.Clone(spki)
	for _, owner := range []string{"@owner:example.invalid", "@other:example.invalid"} {
		_ = checkCertificateSignatureWithPin(raw, owner, spki)
	}
	if !bytes.Equal(raw, beforeRaw) || !bytes.Equal(spki, beforeSPKI) {
		t.Fatal("input changed")
	}
}
