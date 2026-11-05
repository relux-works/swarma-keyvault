package mugrant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrAttestation refuses an owner-root attestation that is not exactly what
// this issuer builds, signed by the given root.
var ErrAttestation = errors.New("mugrant-attestation-invalid")

// AttestedKey is a verified owner-root attestation of one key.
type AttestedKey struct {
	Key, ContentID     string
	MXID               string // Mac agent attestations only
	Generation         int64  // Mac agent attestations only
	NotBefore, Expires time.Time
	SPKISHA256         [32]byte // fingerprint of the key as SPKI DER
}

func (a *AttestedKey) covers(nb, ex time.Time) bool {
	return !nb.Before(a.NotBefore) && !ex.After(a.Expires)
}

// VerifyMacAgentAttestation admits a swarm-envelope/2 attestation/1 of a Mac
// agent key (binding mac-se-1) only when its body is byte-identical to the one
// BuildMacAgentAttestation produces for the same values and its single author
// signature verifies under root. The MXID and generation come from that
// verified body.
func VerifyMacAgentAttestation(wire []byte, root string) (*AttestedKey, error) {
	return verifyAttestation(wire, root, "mac-se-1")
}

// VerifyPublisherAttestation admits the grant revocation publisher attestation
// (binding grant-revocation-1 with domain root) under the same rules.
func VerifyPublisherAttestation(wire []byte, root string) (*AttestedKey, error) {
	return verifyAttestation(wire, root, "grant-revocation-1")
}

func verifyAttestation(wire []byte, root, profile string) (*AttestedKey, error) {
	if record.ValidateKey(root) != nil {
		return nil, ErrAttestation
	}
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, ErrAttestation
	}
	e, ok := parsed.(map[string]any)
	if !ok || len(e) != 4 || e["version"] != "swarm-envelope/2" {
		return nil, ErrAttestation
	}
	body, ok := e["body"].(map[string]any)
	sigs, _ := e["signatures"].([]any)
	if !ok || len(sigs) != 1 || body["type"] != "attestation/1" || body["issuer"] != root {
		return nil, ErrAttestation
	}
	subject, _ := body["subject"].(map[string]any)
	binding, _ := body["binding"].(map[string]any)
	publicText, _ := subject["public_bytes"].(string)
	iat, _ := body["iat"].(string)
	exp, _ := body["exp"].(string)
	if subject == nil || binding == nil || binding["profile"] != profile {
		return nil, ErrAttestation
	}
	compressed, err := record.DecodeBase64(publicText, 33)
	if err != nil {
		return nil, ErrAttestation
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, ErrAttestation
	}
	spki, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		return nil, ErrAttestation
	}
	nb, err1 := time.Parse("2006-01-02T15:04:05Z", iat)
	ex, err2 := time.Parse("2006-01-02T15:04:05Z", exp)
	if err1 != nil || err2 != nil {
		return nil, ErrAttestation
	}
	nb, ex = nb.UTC(), ex.UTC()
	a := &AttestedKey{NotBefore: nb, Expires: ex, SPKISHA256: sha256.Sum256(spki)}
	var plan *Plan
	switch profile {
	case "mac-se-1":
		a.MXID, _ = binding["mxid"].(string)
		a.Generation, _ = binding["generation"].(int64)
		plan, a.Key, err = BuildMacAgentAttestation(root, spki, a.MXID, a.Generation, nb, ex)
	default:
		plan, a.Key, err = BuildPublisherAttestation(root, spki, nb, ex)
	}
	if err != nil {
		return nil, ErrAttestation
	}
	canonical, err := record.Canonical(body)
	if err != nil || string(canonical) != string(plan.Body()) || e["id"] != plan.ContentID() {
		return nil, ErrAttestation
	}
	sig, _ := sigs[0].(map[string]any)
	sigText, _ := sig["sig"].(string)
	raw64, err := record.DecodeBase64(sigText, 64)
	if err != nil || len(sig) != 3 || sig["key"] != root || sig["role"] != "author" {
		return nil, ErrAttestation
	}
	pre, err := record.SigningPreimage("attestation/1", root, "author", body)
	if err != nil || record.VerifySignature(root, raw64, pre) != nil {
		return nil, ErrAttestation
	}
	a.ContentID = plan.ContentID()
	return a, nil
}
