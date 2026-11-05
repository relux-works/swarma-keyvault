package mugrant

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// MaxKeymakerWindow is the platform bound for a Keymaker v0 agent attestation
// (spec: agent windows at most 86 400 seconds).
const MaxKeymakerWindow = 86400 * time.Second

// ErrKeymaker refuses a Keymaker agent attestation or registry identity.
var ErrKeymaker = errors.New("mugrant-keymaker-attestation-invalid")

// KeymakerBinding is the exact v0 agent binding and active-generation
// evidence (without "active").
type KeymakerBinding struct {
	UID                int64
	Generation         string
	RegistrationNumber int64
	MasterEpoch        string
	Owner              string
	Path               string
}

func (b KeymakerBinding) valid() bool {
	text := func(s string) bool { return s != "" && len(s) <= 255 }
	return b.UID >= 0 && b.UID <= 4294967294 && b.RegistrationNumber >= 1 && b.RegistrationNumber <= 9007199254740991 &&
		text(b.Generation) && text(b.MasterEpoch) && text(b.Owner) && text(b.Path)
}

// Map returns the binding as the platform evidence object.
func (b KeymakerBinding) Map() map[string]any {
	return map[string]any{"uid": b.UID, "generation": b.Generation, "registration_number": b.RegistrationNumber,
		"master_epoch": b.MasterEpoch, "owner": b.Owner, "path": b.Path}
}

// Ed25519KeyID is the platform key id of a raw Ed25519 public key.
func Ed25519KeyID(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", ErrKeymaker
	}
	id := "ed25519:" + base64.RawURLEncoding.EncodeToString(pub)
	if record.ValidateKey(id) != nil {
		return "", ErrKeymaker
	}
	return id, nil
}

// BuildKeymakerAgentAttestation prepares the exact body a Keymaker signing
// service (service root, purpose 5) signs for an Ed25519 agent key. The
// receiver and the issuer compare received attestations against it byte for
// byte; KV never signs one outside test vectors.
func BuildKeymakerAgentAttestation(serviceRoot string, agent ed25519.PublicKey, b KeymakerBinding, nb, ex time.Time) (*Plan, string, error) {
	id, err := Ed25519KeyID(agent)
	if err != nil || record.ValidateKey(serviceRoot) != nil || id == serviceRoot || !b.valid() {
		return nil, "", ErrKeymaker
	}
	if nb.Location() != time.UTC || ex.Location() != time.UTC || nb.Nanosecond() != 0 || ex.Nanosecond() != 0 || !ex.After(nb) || ex.Sub(nb) > MaxKeymakerWindow {
		return nil, "", ErrKeymaker
	}
	body, err := record.Canonical(map[string]any{"type": "attestation/1", "issuer": serviceRoot,
		"subject":   map[string]any{"algorithm": "Ed25519", "key_id": id, "public_bytes": base64.RawURLEncoding.EncodeToString(agent)},
		"key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"},
		"iat": wireTime(nb), "exp": wireTime(ex), "binding": b.Map()})
	if err != nil {
		return nil, "", ErrKeymaker
	}
	alg, _, err := record.KeyBytes(serviceRoot)
	if err != nil {
		return nil, "", ErrKeymaker
	}
	var p *Plan
	if alg == "ed25519" {
		p, err = PrepareEd25519("attestation/1", serviceRoot, body)
	} else {
		p, err = Prepare("attestation/1", serviceRoot, body)
	}
	if err != nil {
		return nil, "", ErrKeymaker
	}
	return p, id, nil
}

// KeymakerAgent is a verified Keymaker agent attestation.
type KeymakerAgent struct {
	Key, ContentID     string
	Binding            KeymakerBinding
	NotBefore, Expires time.Time
	Fingerprint        string // SHA-256 of the raw public key, base64url
}

// VerifyKeymakerAttestation admits a swarm-envelope/2 Keymaker v0 agent
// attestation only when its body is byte-identical to the
// BuildKeymakerAgentAttestation output for the same values and its single
// author signature verifies under serviceRoot.
func VerifyKeymakerAttestation(wire []byte, serviceRoot string) (*KeymakerAgent, error) {
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, ErrKeymaker
	}
	e, ok := parsed.(map[string]any)
	if !ok || len(e) != 4 || e["version"] != "swarm-envelope/2" {
		return nil, ErrKeymaker
	}
	body, _ := e["body"].(map[string]any)
	sigs, _ := e["signatures"].([]any)
	if body == nil || len(sigs) != 1 || body["issuer"] != serviceRoot {
		return nil, ErrKeymaker
	}
	subject, _ := body["subject"].(map[string]any)
	bind, _ := body["binding"].(map[string]any)
	public, _ := subject["public_bytes"].(string)
	raw, err := record.DecodeBase64(public, 32)
	if err != nil || bind == nil {
		return nil, ErrKeymaker
	}
	var b KeymakerBinding
	b.UID, _ = bind["uid"].(int64)
	b.RegistrationNumber, _ = bind["registration_number"].(int64)
	b.Generation, _ = bind["generation"].(string)
	b.MasterEpoch, _ = bind["master_epoch"].(string)
	b.Owner, _ = bind["owner"].(string)
	b.Path, _ = bind["path"].(string)
	iat, _ := body["iat"].(string)
	exp, _ := body["exp"].(string)
	nb, err1 := time.Parse("2006-01-02T15:04:05Z", iat)
	ex, err2 := time.Parse("2006-01-02T15:04:05Z", exp)
	if err1 != nil || err2 != nil {
		return nil, ErrKeymaker
	}
	plan, key, err := BuildKeymakerAgentAttestation(serviceRoot, ed25519.PublicKey(raw), b, nb.UTC(), ex.UTC())
	if err != nil {
		return nil, ErrKeymaker
	}
	canonical, err := record.Canonical(body)
	if err != nil || string(canonical) != string(plan.Body()) || e["id"] != plan.ContentID() {
		return nil, ErrKeymaker
	}
	sig, _ := sigs[0].(map[string]any)
	sigText, _ := sig["sig"].(string)
	sigRaw, err := record.DecodeBase64(sigText, 64)
	if err != nil || len(sig) != 3 || sig["key"] != serviceRoot || sig["role"] != "author" || record.VerifySignature(serviceRoot, sigRaw, plan.Preimage()) != nil {
		return nil, ErrKeymaker
	}
	sum := sha256.Sum256(raw)
	return &KeymakerAgent{Key: key, ContentID: plan.ContentID(), Binding: b, NotBefore: nb.UTC(), Expires: ex.UTC(),
		Fingerprint: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// RegistryIdentity is the registry record of a Linux agent the owner grants
// to: its MXID and the identity fields its Keymaker attestation must carry.
type RegistryIdentity struct {
	MXID               string
	UID                int64
	RegistrationNumber int64
}
