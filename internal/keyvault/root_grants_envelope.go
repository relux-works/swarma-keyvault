package keyvault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// RootGrantsEnvelope is a device-local SEALED representation. Shape validation
// does not establish authentic ciphertext, matching private material, a correct
// seal, biometric policy or qualified code. It is not a public export receipt.
// The algorithm is the existing qualified recovery ECIES constant, unchanged.
type RootGrantsEnvelope struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	EnclaveBlob []byte `json:"enclave_blob"`
	Point       []byte `json:"point"`
	Fingerprint string `json:"fingerprint"`
	Ciphertext  []byte `json:"ciphertext"`
}

func validateRootGrantsEnvelope(e RootGrantsEnvelope, r RootGrantsRecord) error {
	if validateRootGrantsRecord(r) != nil || e.Schema != "keyvault-root-grants-ciphertext/1" || e.Algorithm != recoveryAlgorithm ||
		len(e.EnclaveBlob) < 1 || len(e.EnclaveBlob) > 16384 || len(e.Ciphertext) != 149 ||
		!bytes.Equal(e.Point, r.WrappingPoint) || e.Fingerprint != r.WrappingFingerprint {
		return recoveryRefuse("invalid_envelope")
	}
	if _, err := ecdh.P256().NewPublicKey(e.Ciphertext[:65]); err != nil {
		return recoveryRefuse("invalid_envelope")
	}
	return nil
}

func CanonicalRootGrantsEnvelope(e RootGrantsEnvelope, r RootGrantsRecord) ([]byte, error) {
	if err := validateRootGrantsEnvelope(e, r); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > recoveryMaxCiphertext {
		return nil, recoveryRefuse("invalid_envelope")
	}
	return raw, nil
}

func ParseRootGrantsEnvelope(raw []byte, r RootGrantsRecord) (RootGrantsEnvelope, error) {
	var e RootGrantsEnvelope
	if len(raw) == 0 || len(raw) > recoveryMaxCiphertext || DecodeSingleJSON(raw, &e) != nil {
		return RootGrantsEnvelope{}, recoveryRefuse("invalid_envelope")
	}
	canonical, err := CanonicalRootGrantsEnvelope(e, r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return RootGrantsEnvelope{}, recoveryRefuse("invalid_envelope")
	}
	return e, nil
}

// rootGrantsPlaintext owns one private buffer; value copies share its lifetime.
// There is deliberately no exported constructor, bytes getter, marshaling or
// scalar/plaintext callback. Only qualified engine code may use this material.
// The creating engine owns it exclusively and must defer clear through sealing,
// cancellation and refusal; it must also clear its original prepared material.
type rootGrantsPlaintext struct{ buffer *[68]byte }

func (rootGrantsPlaintext) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<private-root-grants-plaintext>")
}
func (rootGrantsPlaintext) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}
func (p *rootGrantsPlaintext) clear() {
	if p != nil && p.buffer != nil {
		clear(p.buffer[:])
	}
}

func rootGrantsPlaintextBinding(r RootGrantsRecord) ([32]byte, error) {
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("keyvault-root-grants/plaintext/1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(metadata)
	var binding [32]byte
	copy(binding[:], h.Sum(nil))
	return binding, nil
}

func (p *rootGrantsPrepared) rootGrantsPlaintext(r RootGrantsRecord) (*rootGrantsPlaintext, error) {
	if p == nil || p.state == nil {
		return nil, recoveryRefuse("private_protocol_error")
	}
	binding, err := rootGrantsPlaintextBinding(r)
	if err != nil {
		return nil, err
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if !p.state.ready || p.state.public.Root != r.publicRoot() || p.state.public.Pair != r.Pair {
		return nil, recoveryRefuse("public_pin_mismatch")
	}
	plain := &rootGrantsPlaintext{buffer: new([68]byte)}
	copy(plain.buffer[:4], "KVG1")
	copy(plain.buffer[4:36], binding[:])
	copy(plain.buffer[36:], p.state.scalar[:])
	if err := plain.validate(r); err != nil {
		plain.clear()
		return nil, err
	}
	return plain, nil
}

// validate runs inside the private package after an eventual qualified unwrap.
// It returns no plaintext/scalar; it is not a decrypt or signature operation.
func (p *rootGrantsPlaintext) validate(r RootGrantsRecord) error {
	binding, err := rootGrantsPlaintextBinding(r)
	if err != nil || p == nil || p.buffer == nil || !bytes.Equal(p.buffer[:4], []byte("KVG1")) ||
		!bytes.Equal(p.buffer[4:36], binding[:]) {
		return recoveryRefuse("binding_mismatch")
	}
	key, err := nostrPrivate(p.buffer[36:])
	if err != nil {
		return recoveryRefuse("invalid_derivation")
	}
	defer key.Zero()
	public := key.PubKey().SerializeCompressed()
	if public[0] != 2 || hex.EncodeToString(public) != r.SealPublicKey {
		return recoveryRefuse("public_pin_mismatch")
	}
	return nil
}
