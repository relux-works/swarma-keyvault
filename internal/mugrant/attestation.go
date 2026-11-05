package mugrant

import (
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrAttestationSpec refuses an attestation that cannot be built.
var ErrAttestationSpec = errors.New("mugrant-attestation-spec-invalid")

// MaxAttestationWindow is the platform bound for Mac agent and publisher
// attestations (366 days).
const MaxAttestationWindow = 366 * 24 * time.Hour

func attestationSubject(spki []byte) (map[string]any, string, error) {
	pub, err := parseP256SPKI(spki)
	if err != nil {
		return nil, "", ErrAttestationSpec
	}
	raw := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
	id := "p256:" + base64.RawURLEncoding.EncodeToString(raw)
	if record.ValidateKey(id) != nil {
		return nil, "", ErrAttestationSpec
	}
	return map[string]any{"algorithm": "P-256", "key_id": id, "public_bytes": base64.RawURLEncoding.EncodeToString(raw)}, id, nil
}

// ed25519AttestationSubject is the subject of an Ed25519 key given as its
// canonical PKIX DER.
func ed25519AttestationSubject(spki []byte) (map[string]any, string, error) {
	pub, err := parseEd25519SPKI(spki)
	if err != nil {
		return nil, "", ErrAttestationSpec
	}
	id, err := Ed25519KeyID(pub)
	if err != nil {
		return nil, "", ErrAttestationSpec
	}
	return map[string]any{"algorithm": "Ed25519", "key_id": id, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)}, id, nil
}

func attestationWindow(nb, ex time.Time) bool {
	return nb.Location() == time.UTC && ex.Location() == time.UTC && nb.Nanosecond() == 0 && ex.Nanosecond() == 0 && ex.After(nb) && ex.Sub(nb) <= MaxAttestationWindow
}

func buildAttestation(root string, spki []byte, nb, ex time.Time, class, purpose string, actions []any, binding map[string]any) (*Plan, string, error) {
	return buildAttestationWith(attestationSubject, root, spki, nb, ex, class, purpose, actions, binding)
}

func buildAttestationWith(subjectOf func([]byte) (map[string]any, string, error), root string, spki []byte, nb, ex time.Time, class, purpose string, actions []any, binding map[string]any) (*Plan, string, error) {
	if record.ValidateKey(root) != nil || !attestationWindow(nb, ex) {
		return nil, "", ErrAttestationSpec
	}
	subject, id, err := subjectOf(spki)
	if err != nil || id == root {
		return nil, "", ErrAttestationSpec
	}
	body, err := record.Canonical(map[string]any{"type": "attestation/1", "issuer": root, "subject": subject,
		"key_class": class, "purpose": purpose, "roles": []any{"author"}, "actions": actions,
		"iat": wireTime(nb), "exp": wireTime(ex), "binding": binding})
	if err != nil {
		return nil, "", ErrAttestationSpec
	}
	p, err := Prepare("attestation/1", root, body)
	return p, id, err
}

// BuildMacAgentAttestation prepares the owner-root attestation of a Mac agent
// key (contract X9): binding {profile:"mac-se-1", mxid, generation}. Its
// window must cover every grant naming the key.
func BuildMacAgentAttestation(root string, agentSPKI []byte, mxid string, generation int64, nb, ex time.Time) (*Plan, string, error) {
	if !validMXID(mxid) || generation < 1 {
		return nil, "", ErrAttestationSpec
	}
	return buildAttestation(root, agentSPKI, nb, ex, "agent", "swarma-msg", []any{"message.sign"},
		map[string]any{"profile": "mac-se-1", "mxid": mxid, "generation": generation})
}

// BuildPublisherAttestation prepares the owner-root attestation of the grant
// revocation publisher key (contract r5): binding {profile:
// "grant-revocation-1", domain: root}.
func BuildPublisherAttestation(root string, publisherSPKI []byte, nb, ex time.Time) (*Plan, string, error) {
	return buildAttestation(root, publisherSPKI, nb, ex, "revocation-publisher", "grant-revocation", []any{"revocation.sign"},
		map[string]any{"profile": "grant-revocation-1", "domain": root})
}

// BuildEd25519PublisherAttestation prepares the owner-root attestation of an
// Ed25519 grant revocation publisher (profile grant-revocation-2), for a
// publisher key held by a signing service. Only the owner grant root signs it.
func BuildEd25519PublisherAttestation(root string, publisherSPKI []byte, nb, ex time.Time) (*Plan, string, error) {
	return buildAttestationWith(ed25519AttestationSubject, root, publisherSPKI, nb, ex, "revocation-publisher", "grant-revocation", []any{"revocation.sign"},
		map[string]any{"profile": "grant-revocation-2", "domain": root})
}

// MacAgentAttestationReason is the Touch ID reason for the owner-root
// signature of a Mac agent attestation (decision 154 applied to X9): agent
// MXID, generation, window in MSK and the digest tail. It refuses instead of
// truncating.
func MacAgentAttestationReason(p *Plan, mxid string, generation int64, nb, ex time.Time) (string, error) {
	d := p.Digest()
	return checkReason(fmt.Sprintf("ключ агента · %s · поколение %d · %s · SHA256 %x", mxid, generation, mskInterval(nb, ex), d[26:]))
}

// Ed25519PublisherAttestationReason is the Touch ID reason for the owner-root
// signature of an Ed25519 publisher attestation; it names the algorithm so the
// owner can tell it from the Mac publisher.
func Ed25519PublisherAttestationReason(p *Plan, nb, ex time.Time) (string, error) {
	d := p.Digest()
	return checkReason(fmt.Sprintf("ключ отзыва грантов Ed25519 · %s · SHA256 %x", mskInterval(nb, ex), d[26:]))
}

// PublisherAttestationReason is the Touch ID reason for the owner-root
// signature of the grant revocation publisher attestation (r5).
func PublisherAttestationReason(p *Plan, nb, ex time.Time) (string, error) {
	d := p.Digest()
	return checkReason(fmt.Sprintf("ключ отзыва грантов · %s · SHA256 %x", mskInterval(nb, ex), d[26:]))
}
