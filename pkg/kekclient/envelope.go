// Package kekclient is the consumer side of KEK contract 1: a service keeps a
// key-encryption key (KEK) wrapped to a non-extractable keyvault key and gets
// it back at start from mac-keyvault-kek, which answers only the code the
// envelope is bound to.
//
// Wrapping needs only the key's public half and is done here in pure Go.
// Unwrapping runs the broker as a child and talks to it over a fresh Unix
// socket, so the broker can check the caller's code identity.
package kekclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Contract names the wire and envelope contract this package speaks.
const Contract = "kek-1"

// EnvelopeFormat is the envelope file's format name.
const EnvelopeFormat = "mac-keyvault-kek-envelope"

// KEKLen is the only KEK length the contract carries.
const KEKLen = 32

// maxEnvelopeBytes bounds an envelope file and a request line.
const maxEnvelopeBytes = 16 << 10

// Envelope is the file a service keeps: who it is for, in the clear, and the
// ECIES ciphertext of the Payload. The header fields are repeated inside the
// ciphertext and the broker refuses any difference, because the ECIES
// variant takes no associated data.
type Envelope struct {
	Format      string `json:"format"`
	Version     int    `json:"v"`
	Address     string `json:"address"`
	Generation  int    `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	// KCV is the KEK's check value (KeyCheckValue). The client refuses a
	// returned KEK that does not match it, so a broker that is not the real
	// one cannot hand the service a KEK of its own choosing for this
	// envelope. The clear KCV is not authenticated: someone who can rewrite
	// the envelope file and replace the broker can pair a chosen KEK with its
	// own KCV; the service's store check is the backstop for that.
	KCV   []byte `json:"kcv"`
	ECIES []byte `json:"ecies"`
}

// Payload is the plaintext inside an envelope. Requirement binds the KEK to
// one caller's code; InstallPath is where that caller is installed, the only
// file a rebind may bind to.
type Payload struct {
	Version     int    `json:"v"`
	Address     string `json:"address"`
	Generation  int    `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Requirement string `json:"requirement"`
	InstallPath string `json:"install_path"`
	KCV         []byte `json:"kcv"`
	KEK         []byte `json:"kek"`
}

// payloadHeader is Payload without its KEK, which MarshalWithSecret adds.
type payloadHeader struct {
	Version     int    `json:"v"`
	Address     string `json:"address"`
	Generation  int    `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Requirement string `json:"requirement"`
	InstallPath string `json:"install_path"`
	KCV         []byte `json:"kcv"`
}

// kcvLabel separates the check value from any other use of the KEK.
const kcvLabel = "mac-keyvault-kek kcv 1"

// KeyCheckValue is HMAC-SHA256(kek, kcvLabel). It identifies a KEK without
// revealing anything usable about it.
func KeyCheckValue(kek []byte) []byte {
	mac := hmac.New(sha256.New, kek)
	mac.Write([]byte(kcvLabel))
	return mac.Sum(nil)
}

// MatchesKCV reports whether kek has the check value kcv, in constant time.
func MatchesKCV(kek, kcv []byte) bool {
	return len(kcv) == sha256.Size && hmac.Equal(KeyCheckValue(kek), kcv)
}

var component = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidAddress reports whether address is service/purpose with each part a
// lowercase keyvault name component.
func ValidAddress(address string) bool {
	service, purpose, ok := strings.Cut(address, "/")
	return ok && component.MatchString(service) && component.MatchString(purpose)
}

var cdhashRequirement = regexp.MustCompile(`^cdhash H"([0-9a-f]{40})"$`)
var certificateRequirement = regexp.MustCompile(`^certificate leaf = H"([0-9a-f]{40})" and identifier "([A-Za-z0-9][A-Za-z0-9._-]{0,254})"$`)

// RequirementForCDHash is the interim binding: exactly one code directory
// hash (SHA-1 truncated form, 40 hex digits, as codesign prints it).
func RequirementForCDHash(cdhash string) (string, error) {
	req := `cdhash H"` + strings.ToLower(cdhash) + `"`
	if !ValidRequirement(req) {
		return "", fmt.Errorf("cdhash %q is not 40 hex digits", cdhash)
	}
	return req, nil
}

// RequirementForCertificate binds to an explicit leaf-certificate DER SHA-1
// and signed identifier. Fingerprint input is case-insensitive; identifiers
// preserve their exact case. The serialized form has one canonical spelling.
func RequirementForCertificate(identifier, certificateSHA1 string) (string, error) {
	req := `certificate leaf = H"` + strings.ToLower(certificateSHA1) + `" and identifier "` + identifier + `"`
	if !certificateRequirement.MatchString(req) {
		return "", fmt.Errorf("certificate fingerprint or identifier is not an admitted form")
	}
	return req, nil
}

// ValidRequirement admits only the canonical cdhash and leaf-certificate plus
// identifier forms. It does not parse general code-requirement expressions.
func ValidRequirement(req string) bool {
	return cdhashRequirement.MatchString(req) || certificateRequirement.MatchString(req)
}

// RequirementCertificate returns both pinned fields only for the exact
// canonical certificate form; cdhash and malformed forms return false.
func RequirementCertificate(req string) (identifier, certificateSHA1 string, ok bool) {
	m := certificateRequirement.FindStringSubmatch(req)
	if m == nil {
		return "", "", false
	}
	return m[2], m[1], true
}

// RequirementCDHash returns the cdhash a valid requirement binds.
func RequirementCDHash(req string) (string, bool) {
	m := cdhashRequirement.FindStringSubmatch(req)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Fingerprint is base64url(SHA-256(DER SPKI)) without padding, as keyvault
// prints it.
func Fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// WrapSpec is what Wrap binds into a new envelope.
type WrapSpec struct {
	// SPKI is the DER SubjectPublicKeyInfo of the keyvault key, as `pub`
	// prints it. Fingerprint must match it: the caller pins the fingerprint
	// it read in the provisioning window.
	SPKI        []byte
	Fingerprint string
	Address     string
	Generation  int
	Requirement string
	InstallPath string
}

// Wrap seals kek for spec. It needs no Security.framework call and no
// broker.
func Wrap(spec WrapSpec, kek []byte) ([]byte, error) {
	if len(kek) != KEKLen {
		return nil, fmt.Errorf("kek must be %d bytes, not %d", KEKLen, len(kek))
	}
	if err := spec.check(); err != nil {
		return nil, err
	}
	point, err := p256Point(spec.SPKI)
	if err != nil {
		return nil, err
	}
	kcv := KeyCheckValue(kek)
	plain, err := MarshalWithSecret(payloadHeader{Version: 1, Address: spec.Address, Generation: spec.Generation, Fingerprint: spec.Fingerprint, Requirement: spec.Requirement, InstallPath: spec.InstallPath, KCV: kcv}, "kek", kek)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	sealed, err := seal(point, plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Format: EnvelopeFormat, Version: 1, Address: spec.Address, Generation: spec.Generation, Fingerprint: spec.Fingerprint, KCV: kcv, ECIES: sealed})
}

func (spec WrapSpec) check() error {
	switch {
	case !ValidAddress(spec.Address):
		return fmt.Errorf("address %q is not service/purpose", spec.Address)
	case spec.Generation < 1:
		return fmt.Errorf("generation must be at least 1")
	case Fingerprint(spec.SPKI) != spec.Fingerprint:
		return errors.New("the public key does not have the pinned fingerprint")
	case !ValidRequirement(spec.Requirement):
		return fmt.Errorf("requirement %q is not an admitted form", spec.Requirement)
	case !filepath.IsAbs(spec.InstallPath) || filepath.Clean(spec.InstallPath) != spec.InstallPath:
		return fmt.Errorf("install path %q is not a clean absolute path", spec.InstallPath)
	}
	return nil
}

func p256Point(spki []byte) (*ecdh.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	point, err := pub.ECDH()
	if err != nil || point.Curve() != ecdh.P256() {
		return nil, errors.New("public key is not P-256")
	}
	return point, nil
}

// seal is Security.framework's
// kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM for a
// P-256 key: an ephemeral key, the X9.63 KDF over the shared secret with the
// ephemeral point as shared info, 16 bytes of AES key and 16 bytes of GCM
// IV, output ephemeral point || ciphertext || tag. P-256's cofactor is 1.
func seal(peer *ecdh.PublicKey, plain []byte) ([]byte, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	z, err := eph.ECDH(peer)
	if err != nil {
		return nil, err
	}
	defer clear(z)
	ephPoint := eph.PublicKey().Bytes()
	derived := x963KDF(z, ephPoint, 32)
	defer clear(derived)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(bytes.Clone(ephPoint), derived[16:32], plain, nil), nil
}

func x963KDF(z, info []byte, n int) []byte {
	var out []byte
	for counter := uint32(1); len(out) < n; counter++ {
		h := sha256.New()
		h.Write(z)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])
		h.Write(info)
		out = h.Sum(out)
	}
	return out[:n]
}

// ParseEnvelope reads an envelope file strictly: exactly the contract's
// members with their types, nothing repeated or after the object, the known
// format and version, a valid address and generation.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if len(data) > maxEnvelopeBytes {
		return env, errors.New("envelope is too large")
	}
	if _, err := decodeStrict(data, envelopeShape, &env); err != nil {
		return env, fmt.Errorf("envelope: %w", err)
	}
	switch {
	case env.Format != EnvelopeFormat || env.Version != 1:
		return env, fmt.Errorf("envelope is %q v%d, not %s v1", env.Format, env.Version, EnvelopeFormat)
	case !ValidAddress(env.Address) || env.Generation < 1:
		return env, errors.New("envelope address or generation is invalid")
	case env.Fingerprint == "" || len(env.ECIES) == 0:
		return env, errors.New("envelope has no fingerprint or ciphertext")
	case len(env.KCV) != sha256.Size:
		return env, errors.New("envelope has no key check value")
	}
	return env, nil
}

// ParsePayload reads a decrypted payload strictly and checks it against the
// envelope header it came in.
func ParsePayload(plain []byte, env Envelope) (Payload, error) {
	var p Payload
	if _, err := decodeStrict(plain, payloadShape, &p); err != nil {
		return p, fmt.Errorf("payload: %w", err)
	}
	switch {
	case p.Version != 1:
		return p, fmt.Errorf("payload version %d is not 1", p.Version)
	case p.Address != env.Address || p.Generation != env.Generation || p.Fingerprint != env.Fingerprint || !hmac.Equal(p.KCV, env.KCV):
		return p, errors.New("payload does not match its envelope header")
	case !ValidRequirement(p.Requirement):
		return p, errors.New("payload requirement is not an admitted form")
	case !filepath.IsAbs(p.InstallPath) || filepath.Clean(p.InstallPath) != p.InstallPath:
		return p, errors.New("payload install path is not a clean absolute path")
	case len(p.KEK) != KEKLen:
		return p, errors.New("payload KEK has the wrong length")
	case !MatchesKCV(p.KEK, p.KCV):
		return p, errors.New("payload KEK does not match its check value")
	}
	return p, nil
}
