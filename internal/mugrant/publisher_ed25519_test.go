package mugrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

func ed25519TestKey(t *testing.T) (ed25519.PrivateKey, string, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Ed25519KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, id, spki
}

// rootSignedBody signs an arbitrary attestation body as the P-256 test key id.
func rootSignedBody(t *testing.T, signer string, body map[string]any) []byte {
	t.Helper()
	raw, err := record.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare("attestation/1", signer, raw)
	if err != nil {
		t.Fatal(err)
	}
	return signWire(t, testPrivate(t, signer), p)
}

// Claim: an Ed25519 publisher attestation built for grant-revocation-2 and
// signed by the owner grant root verifies, with the Ed25519 key id and the
// SPKI fingerprint; the P-256 grant-revocation-1 path still verifies beside
// it (positive controls). Refused, each under the same root:
//   - grant-revocation-2 with a P-256 subject, and grant-revocation-1 with an
//     Ed25519 subject (profile and algorithm are bound);
//   - the valid root-named envelope whose signature is not the root's (only
//     the root's signature appoints);
//   - a grant-revocation-2 attestation issued and signed by an Ed25519
//     service key (a signing service cannot appoint a publisher);
//   - an unknown profile.
//
// The Ed25519 builder refuses a P-256 SPKI and a window over 366 days, and
// the P-256 builder refuses an Ed25519 SPKI.
func TestEd25519PublisherAttestation(t *testing.T) {
	_, root := testKey(t)
	_, p256Publisher := testKey(t)
	_, edPublisher, edSPKI := ed25519TestKey(t)
	nb := time.Date(2026, 11, 5, 20, 0, 0, 0, time.UTC)
	ex := nb.Add(MaxAttestationWindow)

	p, id, err := BuildEd25519PublisherAttestation(root, edSPKI, nb, ex)
	if err != nil || id != edPublisher {
		t.Fatal("build", id, err)
	}
	wire := signWire(t, testPrivate(t, root), p)
	a, err := VerifyPublisherAttestation(wire, root)
	if err != nil || a.Key != edPublisher || a.Fingerprint != Fingerprint(edSPKI) || !a.NotBefore.Equal(nb) || !a.Expires.Equal(ex) {
		t.Fatal("Ed25519 publisher attestation refused", a, err)
	}
	if r, err := Ed25519PublisherAttestationReason(p, nb, ex); err != nil || r == "" {
		t.Fatal("reason", err)
	}
	if a, err := VerifyPublisherAttestation(publisherAttestation(t, root, p256Publisher, nb, ex), root); err != nil || a.Key != p256Publisher {
		t.Fatal("P-256 publisher attestation refused", err)
	}

	var body map[string]any
	if err := json.Unmarshal(p.Body(), &body); err != nil {
		t.Fatal(err)
	}
	p256SPKI := spkiOf(t, testPrivate(t, p256Publisher))
	p1, _, err := BuildPublisherAttestation(root, p256SPKI, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	var p256Body map[string]any
	if err := json.Unmarshal(p1.Body(), &p256Body); err != nil {
		t.Fatal(err)
	}
	clone := func(m map[string]any) map[string]any {
		raw, _ := json.Marshal(m)
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		return c
	}
	profile2P256 := clone(p256Body)
	profile2P256["binding"] = map[string]any{"profile": "grant-revocation-2", "domain": root}
	profile1Ed := clone(body)
	profile1Ed["binding"] = map[string]any{"profile": "grant-revocation-1", "domain": root}
	unknown := clone(body)
	unknown["binding"] = map[string]any{"profile": "grant-revocation-3", "domain": root}
	refused := map[string][]byte{
		"profile-2-with-p256":    rootSignedBody(t, root, profile2P256),
		"profile-1-with-ed25519": rootSignedBody(t, root, profile1Ed),
		"unknown-profile":        rootSignedBody(t, root, unknown),
	}
	// The root-named envelope with a signature that is not the root's: the
	// valid wire with one signature bit flipped.
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		t.Fatal(err)
	}
	env := parsed.(map[string]any)
	sig := env["signatures"].([]any)[0].(map[string]any)
	rawSig, err := record.DecodeBase64(sig["sig"].(string), 64)
	if err != nil {
		t.Fatal(err)
	}
	rawSig[10] ^= 1
	sig["sig"] = base64.RawURLEncoding.EncodeToString(rawSig)
	forged, err := record.Canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	refused["not-root-signature"] = forged
	// A signing service issues and signs it with its own Ed25519 key.
	serviceKey, serviceID, _ := ed25519TestKey(t)
	service := clone(body)
	service["issuer"] = serviceID
	service["binding"] = map[string]any{"profile": "grant-revocation-2", "domain": root}
	serviceRaw, _ := record.Canonical(service)
	sp, err := PrepareEd25519("attestation/1", serviceID, serviceRaw)
	if err != nil {
		t.Fatal(err)
	}
	serviceWire, err := AssembleEd25519(sp, ed25519.Sign(serviceKey, sp.Preimage()))
	if err != nil {
		t.Fatal(err)
	}
	refused["issued-by-service-key"] = serviceWire
	for name, w := range refused {
		if a, err := VerifyPublisherAttestation(w, root); !errors.Is(err, ErrAttestation) {
			t.Error("publisher attestation admitted", name, a, err)
		}
	}

	if _, _, err := BuildEd25519PublisherAttestation(root, p256SPKI, nb, ex); !errors.Is(err, ErrAttestationSpec) {
		t.Error("P-256 SPKI accepted as an Ed25519 publisher", err)
	}
	if _, _, err := BuildEd25519PublisherAttestation(root, edSPKI, nb, ex.Add(time.Second)); !errors.Is(err, ErrAttestationSpec) {
		t.Error("window over 366 days accepted", err)
	}
	if _, _, err := BuildPublisherAttestation(root, edSPKI, nb, ex); !errors.Is(err, ErrAttestationSpec) {
		t.Error("Ed25519 SPKI accepted as a P-256 publisher", err)
	}
}
