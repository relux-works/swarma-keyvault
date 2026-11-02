package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

func publicLifecycleFixture(t *testing.T) (*ecdsa.PrivateKey, publicIssuerPin, []byte, map[string]any) {
	t.Helper()
	key, spki, certificate := certificateSignatureFixture(t)
	raw := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	revocation := revocationTestObject()
	revocation["issuer"] = subobjectCopy(certificate["issuer"].(map[string]any))
	revocation["effective_at"] = "2026-11-02T11:00:00Z"
	return key, publicIssuerPin{ownerMXID: "@owner:example.invalid", spkiDER: spki}, raw, revocation
}

func signedRevocationFixture(t *testing.T, key *ecdsa.PrivateKey, revocation map[string]any) []byte {
	t.Helper()
	payload := requestTestBytes(t, revocation)
	digest := sha256.Sum256(append([]byte("swarma-grants/revocation/1\n"), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal("fixture signature setup failed")
	}
	half := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Curve.Params().N, s)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal("fixture signature encoding failed")
	}
	return requestTestBytes(t, map[string]any{"type": "grants-signed-revocation-1", "payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}

// A correctly signed revocation must name the retained signed certificate
// and its exact lifecycle authority, even if a different key is independently
// accepted by its supplied pin. No lifecycle write, current state or trusted
// clock is established by these public component checks.
func TestPublicRevocationRetainedAuthority(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	valid := signedRevocationFixture(t, key, revocation)
	checkGood := func() {
		t.Helper()
		if err := checkRevocationAgainstCertificate(valid, certificate, pin, pin, declaredMatchTime()); err != nil {
			t.Fatal("valid retained-authority control", err)
		}
	}
	checkGood()
	otherKey, otherPin, _, otherRevocation := publicLifecycleFixture(t)
	if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, otherKey, otherRevocation), certificate, otherPin, pin, declaredMatchTime()); !errors.Is(err, errIssuerUntrusted) {
		t.Fatal("globally pinned different key cannot revoke target", err)
	}
	checkGood()
	for _, test := range []struct {
		name string
		edit func(map[string]any)
		at   time.Time
		want error
	}{
		{"wrong-target", func(r map[string]any) { r["certificate_id"] = "certificate-B" }, declaredMatchTime(), errBadLifecycleReference},
		{"future-effective", func(r map[string]any) { r["effective_at"] = "2026-11-02T11:00:01Z" }, declaredMatchTime(), errBadSchema},
		{"invalid-clock-sample", func(map[string]any) {}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), ErrInvalidObservation},
		{"extra-field", func(r map[string]any) { r["extra"] = true }, declaredMatchTime(), errBadSchema},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := subobjectCopy(revocation)
			test.edit(copy)
			if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, key, copy), certificate, pin, pin, test.at); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			checkGood()
		})
	}
	// Changing the signing key while retaining the target's issuer declaration
	// is a mathematical signature failure, not a new lifecycle authority.
	if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, otherKey, revocation), certificate, pin, pin, declaredMatchTime()); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("wrong revocation signing key", err)
	}
	for _, reason := range []string{"owner-revoked", "superseded", "compromised"} {
		copy := subobjectCopy(revocation)
		copy["reason_code"] = reason
		if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, key, copy), certificate, pin, pin, declaredMatchTime().Add(time.Second)); err != nil {
			t.Fatal("supported reason and past effective instant", err)
		}
	}
	checkGood()
}

// Exact signed bytes replay without reading time or reactivating anything;
// another valid signature over the same payload is an immutable-ID collision,
// as are changed payload/issuer bytes. Different IDs indicate a wrong retained
// lookup and never silently compare as an exact replay.
func TestPublicImmutableCertificateReplay(t *testing.T) {
	key, pin, retained, _ := publicLifecycleFixture(t)
	if err := checkImmutableSignedReplay(retained, bytes.Clone(retained), certificateEnvelopeWire, pin, pin); err != nil {
		t.Fatal("exact certificate replay", err)
	}
	_, _, certificate := certificateSignatureFixture(t)
	digest := sha256.Sum256(pin.spkiDER)
	certificate["issuer"].(map[string]any)["key_id"] = "sha256:" + hex.EncodeToString(digest[:])
	resigned := signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1")
	if bytes.Equal(resigned, retained) {
		t.Fatal("control requires a different valid signature")
	}
	if err := checkImmutableSignedReplay(resigned, retained, certificateEnvelopeWire, pin, pin); !errors.Is(err, errCertificateIDCollision) {
		t.Fatal("re-signing an immutable ID", err)
	}
	certificate["expires_at"] = "2026-11-02T12:00:01Z"
	if err := checkImmutableSignedReplay(signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1"), retained, certificateEnvelopeWire, pin, pin); !errors.Is(err, errCertificateIDCollision) {
		t.Fatal("changed valid payload under same ID", err)
	}
	otherKey, otherSPKI, otherCertificate := certificateSignatureFixture(t)
	otherPin := publicIssuerPin{ownerMXID: "@owner:example.invalid", spkiDER: otherSPKI}
	if err := checkImmutableSignedReplay(signedCertificateFixture(t, otherKey, otherCertificate, "swarma-grants/certificate/1"), retained, certificateEnvelopeWire, otherPin, pin); !errors.Is(err, errCertificateIDCollision) {
		t.Fatal("different independently pinned issuer under same ID", err)
	}
	certificate["certificate_id"] = "certificate-B"
	if err := checkImmutableSignedReplay(signedCertificateFixture(t, key, certificate, "swarma-grants/certificate/1"), retained, certificateEnvelopeWire, pin, pin); !errors.Is(err, errRequiredStateUnavailable) {
		t.Fatal("retained lookup is for another ID", err)
	}
	if err := checkImmutableSignedReplay(retained, retained, certificateEnvelopeWire, pin, pin); err != nil {
		t.Fatal("valid neighbor after collisions", err)
	}
}

// Certificate and revocation IDs occupy distinct typed namespaces. An exact
// revocation replay succeeds; changed signed reason or signature collides only
// in that namespace. No import, revocation or audit transition is performed.
func TestPublicImmutableRevocationReplay(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	revocation["revocation_id"] = "certificate-A" // same text, different record kind
	raw := signedRevocationFixture(t, key, revocation)
	if err := checkImmutableSignedReplay(raw, raw, revocationEnvelopeWire, pin, pin); err != nil {
		t.Fatal("exact revocation replay", err)
	}
	resigned := signedRevocationFixture(t, key, revocation)
	if bytes.Equal(raw, resigned) {
		t.Fatal("control requires a different valid revocation signature")
	}
	if err := checkImmutableSignedReplay(resigned, raw, revocationEnvelopeWire, pin, pin); !errors.Is(err, errRevocationIDCollision) {
		t.Fatal("new signature is not exact revocation replay", err)
	}
	revocation["reason_code"] = "compromised"
	if err := checkImmutableSignedReplay(signedRevocationFixture(t, key, revocation), raw, revocationEnvelopeWire, pin, pin); !errors.Is(err, errRevocationIDCollision) {
		t.Fatal("changed revocation reason", err)
	}
	if err := checkImmutableSignedReplay(certificate, raw, certificateEnvelopeWire, pin, pin); !errors.Is(err, errBadSchema) {
		t.Fatal("revocation substituted for certificate record", err)
	}
	if err := checkImmutableSignedReplay(raw, raw, requestWire, pin, pin); !errors.Is(err, errBadSchema) {
		t.Fatal("unsupported record profile", err)
	}
	if err := checkImmutableSignedReplay(raw, raw, revocationEnvelopeWire, pin, pin); err != nil {
		t.Fatal("exact replay after collisions", err)
	}
}

// Malformed or untrusted retained data cannot be used as a replay witness;
// inputs remain unchanged on valid and refusing paths. Missing retained bytes
// do not establish absence or permission to insert a record.
func TestPublicLifecycleRetainedInputAndOwnership(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	raw := signedRevocationFixture(t, key, revocation)
	beforeCert, beforeRevoke, beforeSPKI := bytes.Clone(certificate), bytes.Clone(raw), bytes.Clone(pin.spkiDER)
	if err := checkImmutableSignedReplay(certificate, nil, certificateEnvelopeWire, pin, pin); !errors.Is(err, errBadEncoding) {
		t.Fatal("missing retained data", err)
	}
	if err := checkRevocationAgainstCertificate(raw, append(bytes.Clone(certificate), '\n'), pin, pin, declaredMatchTime()); !errors.Is(err, errBadEncoding) {
		t.Fatal("malformed retained certificate", err)
	}
	wrongPin := publicIssuerPin{ownerMXID: "@other:example.invalid", spkiDER: pin.spkiDER}
	if err := checkImmutableSignedReplay(certificate, certificate, certificateEnvelopeWire, pin, wrongPin); !errors.Is(err, errIssuerUntrusted) {
		t.Fatal("untrusted retained data", err)
	}
	if err := checkRevocationAgainstCertificate(raw, certificate, pin, pin, declaredMatchTime()); err != nil {
		t.Fatal("valid control", err)
	}
	if !bytes.Equal(certificate, beforeCert) || !bytes.Equal(raw, beforeRevoke) || !bytes.Equal(pin.spkiDER, beforeSPKI) {
		t.Fatal("input mutated")
	}
}
