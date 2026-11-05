// Package mugrant prepares and assembles swarm-envelope/2 records for
// multi-use owner grants on macOS. Canonical bytes, content ids, signing
// preimages and signature checks all come from the pinned platform library
// (github.com/relux-works/swarma-envelope/record); this package only binds a
// native Secure Enclave P-256 DER signature to a prepared plan. It performs no
// I/O, signing, authorization or effect, and confers no authority by itself.
package mugrant

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrPlan refuses a body, key, role or kind that cannot be signed as given.
var ErrPlan = errors.New("mugrant-plan-invalid")

// ErrAssembly refuses a signature that does not bind the prepared plan.
var ErrAssembly = errors.New("mugrant-assembly-invalid")

// MaxEnvelopeBytes is the platform per-envelope bound (ENV §2).
const MaxEnvelopeBytes = 65536

// roles fixes the only signer role each kind admits here.
var roles = map[string]string{
	"grant/1":       "author",
	"message/1":     "author",
	"attestation/1": "author",
	"revocation/1":  "author",
}

// Plan is an immutable signing plan for one record. Digest is the 32-byte
// SHA-256 of the signing preimage, which is what the Secure Enclave signs.
type Plan struct {
	kind, key, role string
	body            []byte
	contentID       string
	preimage        []byte
	digest          [32]byte
}

// Prepare checks that body is already canonical CCJ-1, that its type matches
// kind, that key is a valid p256 key id, and derives the content id, signing
// preimage and digest through the platform library.
func Prepare(kind, key string, body []byte) (*Plan, error) {
	role, ok := roles[kind]
	if !ok || len(body) == 0 || len(body) > MaxEnvelopeBytes {
		return nil, ErrPlan
	}
	if alg, _, err := record.KeyBytes(key); err != nil || alg != "p256" || record.ValidateKey(key) != nil {
		return nil, ErrPlan
	}
	parsed, err := record.Parse(body, MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, ErrPlan
	}
	b, ok := parsed.(map[string]any)
	if !ok || b["type"] != kind {
		return nil, ErrPlan
	}
	canonical, err := record.Canonical(b)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrPlan
	}
	id, err := record.ContentID(kind, b)
	if err != nil {
		return nil, ErrPlan
	}
	pre, err := record.SigningPreimage(kind, key, role, b)
	if err != nil {
		return nil, ErrPlan
	}
	return &Plan{kind: kind, key: key, role: role, body: bytes.Clone(body), contentID: id, preimage: pre, digest: sha256.Sum256(pre)}, nil
}

// Digest returns the SHA-256 digest of the signing preimage.
func (p *Plan) Digest() [32]byte { return p.digest }

// Preimage returns a copy of the exact signing preimage (tag, LF, CCJ-1).
func (p *Plan) Preimage() []byte { return bytes.Clone(p.preimage) }

// ContentID returns the platform content id of the body.
func (p *Plan) ContentID() string { return p.contentID }

// Body returns a copy of the canonical body bytes.
func (p *Plan) Body() []byte { return bytes.Clone(p.body) }

// AssembleNative converts a native DER P-256 signature over Digest() to raw64
// low-S, verifies it against the plan's key and preimage with the platform
// library, and returns the canonical swarm-envelope/2 wire bytes. It re-parses
// its own output and rechecks id, body and signature before returning.
func AssembleNative(p *Plan, der []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrAssembly
	}
	raw, ok := NativeP256Raw(der)
	if !ok {
		return nil, ErrAssembly
	}
	if record.VerifySignature(p.key, raw[:], p.preimage) != nil {
		return nil, ErrAssembly
	}
	parsed, err := record.Parse(p.body, MaxEnvelopeBytes, 16)
	if err != nil {
		return nil, ErrAssembly
	}
	wire, err := record.Canonical(map[string]any{
		"body": parsed, "id": p.contentID, "version": "swarm-envelope/2",
		"signatures": []any{map[string]any{"key": p.key, "role": p.role, "sig": base64.RawURLEncoding.EncodeToString(raw[:])}},
	})
	if err != nil || len(wire) > MaxEnvelopeBytes {
		return nil, ErrAssembly
	}
	if err := recheck(p, wire); err != nil {
		return nil, ErrAssembly
	}
	return wire, nil
}

func recheck(p *Plan, wire []byte) error {
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		return err
	}
	e, ok := parsed.(map[string]any)
	if !ok || len(e) != 4 || e["version"] != "swarm-envelope/2" || e["id"] != p.contentID {
		return ErrAssembly
	}
	body, ok := e["body"].(map[string]any)
	if !ok {
		return ErrAssembly
	}
	canonical, err := record.Canonical(body)
	if err != nil || !bytes.Equal(canonical, p.body) {
		return ErrAssembly
	}
	if id, err := record.ContentID(p.kind, body); err != nil || id != p.contentID {
		return ErrAssembly
	}
	sigs, ok := e["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return ErrAssembly
	}
	s, ok := sigs[0].(map[string]any)
	if !ok || len(s) != 3 || s["key"] != p.key || s["role"] != p.role {
		return ErrAssembly
	}
	text, ok := s["sig"].(string)
	if !ok {
		return ErrAssembly
	}
	sig, err := record.DecodeBase64(text, 64)
	if err != nil {
		return ErrAssembly
	}
	pre, err := record.SigningPreimage(p.kind, p.key, p.role, body)
	if err != nil || !bytes.Equal(pre, p.preimage) {
		return ErrAssembly
	}
	return record.VerifySignature(p.key, sig, pre)
}

// NativeP256Raw converts one strict DER ECDSA-Sig-Value to raw r||s with s
// normalized to the low half of the group order. It refuses non-canonical DER,
// trailing bytes, extra members and out-of-range scalars.
func NativeP256Raw(der []byte) ([64]byte, bool) {
	var raw [64]byte
	if len(der) < 8 || len(der) > 72 {
		return raw, false
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		return raw, false
	}
	canonical, err := asn1.Marshal(pair)
	if err != nil || !bytes.Equal(canonical, der) {
		return raw, false
	}
	n := elliptic.P256().Params().N
	if pair.R.Sign() <= 0 || pair.S.Sign() <= 0 || pair.R.Cmp(n) >= 0 || pair.S.Cmp(n) >= 0 {
		return raw, false
	}
	if other := new(big.Int).Sub(n, pair.S); other.Cmp(pair.S) < 0 {
		pair.S = other
	}
	pair.R.FillBytes(raw[:32])
	pair.S.FillBytes(raw[32:])
	return raw, true
}

// KeyIDFromSPKI derives the platform p256 key id (compressed SEC1 point) from
// a PKIX SubjectPublicKeyInfo DER, as the installed keyvault exports it.
func KeyIDFromSPKI(spki []byte) (string, error) {
	pub, err := parseP256SPKI(spki)
	if err != nil {
		return "", ErrPlan
	}
	id := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y))
	if record.ValidateKey(id) != nil {
		return "", ErrPlan
	}
	return id, nil
}
