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
// and its exact lifecycle authority. A different key of the same owner cannot
// supply a second revocation pin. No lifecycle write, current state or trusted
// clock is established by these public component checks.
func TestPublicRevocationRetainedAuthority(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	valid := signedRevocationFixture(t, key, revocation)
	checkGood := func() {
		t.Helper()
		if err := checkRevocationAgainstCertificate(valid, certificate, pin, declaredMatchTime()); err != nil {
			t.Fatal("valid retained-authority control", err)
		}
	}
	checkGood()
	otherKey, _, _, otherRevocation := publicLifecycleFixture(t)
	if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, otherKey, otherRevocation), certificate, pin, declaredMatchTime()); !errors.Is(err, errIssuerUntrusted) {
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
		{"future-effective", func(r map[string]any) { r["effective_at"] = "2026-11-02T11:00:01Z" }, declaredMatchTime(), errFutureRevocationUnsupported},
		{"invalid-clock-sample", func(map[string]any) {}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), ErrInvalidObservation},
		{"extra-field", func(r map[string]any) { r["extra"] = true }, declaredMatchTime(), errBadSchema},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := subobjectCopy(revocation)
			test.edit(copy)
			if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, key, copy), certificate, pin, test.at); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			checkGood()
		})
	}
	// Changing the signing key while retaining the target's issuer declaration
	// is a mathematical signature failure, not a new lifecycle authority.
	if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, otherKey, revocation), certificate, pin, declaredMatchTime()); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("wrong revocation signing key", err)
	}
	for _, reason := range []string{"owner-revoked", "superseded", "compromised"} {
		copy := subobjectCopy(revocation)
		copy["reason_code"] = reason
		if err := checkRevocationAgainstCertificate(signedRevocationFixture(t, key, copy), certificate, pin, declaredMatchTime().Add(time.Second)); err != nil {
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
	if err := checkRevocationAgainstCertificate(raw, append(bytes.Clone(certificate), '\n'), pin, declaredMatchTime()); !errors.Is(err, errBadEncoding) {
		t.Fatal("malformed retained certificate", err)
	}
	wrongPin := publicIssuerPin{ownerMXID: "@other:example.invalid", spkiDER: pin.spkiDER}
	if err := checkImmutableSignedReplay(certificate, certificate, certificateEnvelopeWire, pin, wrongPin); !errors.Is(err, errIssuerUntrusted) {
		t.Fatal("untrusted retained data", err)
	}
	if err := checkRevocationAgainstCertificate(raw, certificate, pin, declaredMatchTime()); err != nil {
		t.Fatal("valid control", err)
	}
	if !bytes.Equal(certificate, beforeCert) || !bytes.Equal(raw, beforeRevoke) || !bytes.Equal(pin.spkiDER, beforeSPKI) {
		t.Fatal("input mutated")
	}
}

// The single pin must verify both mathematical signatures independently.
// Choosing a different valid pin cannot authorize a different key of the same
// owner to revoke this retained certificate. Valid neighbors exclude reject-all.
func TestPublicRevocationSinglePinVerifiesBothRecords(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	valid := signedRevocationFixture(t, key, revocation)
	otherKey, otherPin, _, otherRevocation := publicLifecycleFixture(t)
	otherSigned := signedRevocationFixture(t, otherKey, otherRevocation)
	certificatePayload, _ := declaredMatchFixture("repository.create", "claude-dm")
	certificatePayload["issuer"] = subobjectCopy(revocation["issuer"].(map[string]any))
	wrongCertificateSignature := signedCertificateFixture(t, otherKey, certificatePayload, "swarma-grants/certificate/1")
	for _, test := range []struct {
		name                    string
		revocation, certificate []byte
		pin                     publicIssuerPin
		want                    error
	}{
		{"retained-signature", valid, wrongCertificateSignature, pin, errSignatureInvalid},
		{"revocation-signature", signedRevocationFixture(t, otherKey, revocation), certificate, pin, errSignatureInvalid},
		{"other-key-retained-pin", otherSigned, certificate, pin, errIssuerUntrusted},
		{"other-key-revoker-pin", otherSigned, certificate, otherPin, errIssuerUntrusted},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkGood := func() {
				t.Helper()
				if err := checkRevocationAgainstCertificate(valid, certificate, pin, declaredMatchTime()); err != nil {
					t.Fatal("valid same-pin neighbor", err)
				}
			}
			checkGood()
			if err := checkRevocationAgainstCertificate(test.revocation, test.certificate, test.pin, declaredMatchTime()); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			checkGood()
		})
	}
}

// Exact effective time is supported and any future instant is refused without
// rounding/skew. Nanosecond neighbors and another zone for the same supplied
// instant exercise comparison only; no trusted clock or revocation is created.
func TestPublicRevocationEffectiveAtBoundary(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	raw := signedRevocationFixture(t, key, revocation)
	at := declaredMatchTime()
	for _, test := range []struct {
		name string
		at   time.Time
		want error
	}{
		{"one-nanosecond-future", at.Add(-time.Nanosecond), errFutureRevocationUnsupported},
		{"exact", at, nil},
		{"one-nanosecond-past", at.Add(time.Nanosecond), nil},
		{"equivalent-zone", at.In(time.FixedZone("test-offset", 2*60*60)), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkRevocationAgainstCertificate(raw, certificate, pin, test.at); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

// A complete signed future declaration has a dedicated internal reason,
// distinct from malformed representation. Valid/future checks leave all input
// bytes unchanged and perform no lifecycle, audit or use transition.
func TestPublicRevocationFutureRefusalAndOwnership(t *testing.T) {
	key, pin, certificate, revocation := publicLifecycleFixture(t)
	valid := signedRevocationFixture(t, key, revocation)
	revocation["effective_at"] = "2026-11-02T11:00:01Z"
	future := signedRevocationFixture(t, key, revocation)
	for _, test := range []struct {
		raw  []byte
		want error
	}{{valid, nil}, {future, errFutureRevocationUnsupported}} {
		beforeRaw, beforeCert, beforePin := bytes.Clone(test.raw), bytes.Clone(certificate), bytes.Clone(pin.spkiDER)
		err := checkRevocationAgainstCertificate(test.raw, certificate, pin, declaredMatchTime())
		if !errors.Is(err, test.want) {
			t.Fatalf("got %v, want %v", err, test.want)
		}
		if test.want != nil && errors.Is(err, errBadSchema) {
			t.Fatal("future reason conflated with malformed schema")
		}
		if !bytes.Equal(test.raw, beforeRaw) || !bytes.Equal(certificate, beforeCert) || !bytes.Equal(pin.spkiDER, beforePin) {
			t.Fatal("input changed")
		}
	}
	for _, malformed := range []string{"2026-11-02T11:00:01.0Z", "not-a-time"} {
		revocation["effective_at"] = malformed
		err := checkRevocationAgainstCertificate(signedRevocationFixture(t, key, revocation), certificate, pin, declaredMatchTime())
		if !errors.Is(err, errBadSchema) || errors.Is(err, errFutureRevocationUnsupported) {
			t.Fatal("malformed time must keep its schema refusal", err)
		}
	}
	if err := checkRevocationAgainstCertificate(valid, certificate, pin, declaredMatchTime()); err != nil {
		t.Fatal("valid neighbor after refusals", err)
	}
}
