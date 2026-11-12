package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
)

var rootGrantsEnvelopeOrder13 = []string{"schema", "algorithm", "enclave_blob", "point", "fingerprint", "ciphertext"}

// Intentionally reuses an OLD Nostr ciphertext under NEW root metadata/point.
// It has a real P256 ephemeral prefix and149-byte shape, but CANNOT be a correct
// root seal. Acceptance by structural parsing is NOT seal authenticity evidence.
func rootGrantsEnvelopeFixture13(t *testing.T, r RootGrantsRecord) RootGrantsEnvelope {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery/v1-public-ciphertext.json")
	var old recoveryCiphertext
	if err != nil || json.Unmarshal(raw, &old) != nil {
		t.Fatal("public ciphertext fixture unavailable")
	}
	return RootGrantsEnvelope{Schema: "keyvault-root-grants-ciphertext/1", Algorithm: "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM",
		EnclaveBlob: bytes.Clone(old.Nostr.EnclaveBlob), Point: bytes.Clone(r.WrappingPoint), Fingerprint: r.WrappingFingerprint, Ciphertext: bytes.Clone(old.Nostr.Ciphertext)}
}

func rootGrantsCloneEnvelope13(t *testing.T, e RootGrantsEnvelope) RootGrantsEnvelope {
	t.Helper()
	var copy RootGrantsEnvelope
	if json.Unmarshal(rootGrantsRaw13(t, e), &copy) != nil {
		t.Fatal("envelope fixture copy failed")
	}
	return copy
}

// Claim: exact root envelope order/algorithm, valid P256 point prefix and device
// blob boundaries1..16384 pass. An intentionally WRONG-seal fixture passes
// SHAPE checks, explicitly demonstrating the limit of this parser.
// Limits: no encryption/decryption, helper qualification, correct sealing or ACL.
func TestRootGrantsEnvelope13ShapeAndLimits(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	e := rootGrantsEnvelopeFixture13(t, r)
	for _, size := range []int{1, 16384} {
		e.EnclaveBlob = bytes.Repeat([]byte{1}, size)
		raw, err := CanonicalRootGrantsEnvelope(e, r)
		if err != nil || !bytes.Equal(raw, rootGrantsOrderedJSON13(t, raw, rootGrantsEnvelopeOrder13)) {
			t.Fatal("valid envelope shape/size/order rejected")
		}
		parsed, err := ParseRootGrantsEnvelope(raw, r)
		if err != nil || !bytes.Equal(parsed.Ciphertext, e.Ciphertext) || len(parsed.EnclaveBlob) != size {
			t.Fatal("envelope shape round trip failed")
		}
	}
}

// Claim: each envelope shape/binding/algorithm/point/bound and each canonical
// encoding is enforced before any native operation. NULL/aliases never become
// missing-field defaults. Limits: rejection/shape controls do not authenticate
// ciphertext, wrapping-key policy or native private material.
func TestRootGrantsEnvelope13Refusals(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/1")
	e := rootGrantsEnvelopeFixture13(t, r)
	for i, mutate := range []func(*RootGrantsEnvelope){
		func(e *RootGrantsEnvelope) { e.Schema = "keyvault-enclave/1" },
		func(e *RootGrantsEnvelope) { e.Algorithm = "other" },
		func(e *RootGrantsEnvelope) { e.EnclaveBlob = nil },
		func(e *RootGrantsEnvelope) { e.EnclaveBlob = make([]byte, 16385) },
		func(e *RootGrantsEnvelope) { e.Point = nil },
		func(e *RootGrantsEnvelope) { e.Point[1] ^= 1 },
		func(e *RootGrantsEnvelope) { e.Fingerprint = strings.Repeat("0", 64) },
		func(e *RootGrantsEnvelope) { e.Ciphertext = e.Ciphertext[:148] },
		func(e *RootGrantsEnvelope) { e.Ciphertext = append(e.Ciphertext, 0) },
		func(e *RootGrantsEnvelope) { clear(e.Ciphertext[:65]) },
		func(e *RootGrantsEnvelope) { clear(e.Ciphertext[:65]); e.Ciphertext[0] = 4 },
	} {
		bad := rootGrantsCloneEnvelope13(t, e)
		mutate(&bad)
		if _, err := CanonicalRootGrantsEnvelope(bad, r); err == nil {
			t.Fatalf("invalid envelope invariant %d accepted", i)
		}
		if _, err := ParseRootGrantsEnvelope(rootGrantsRaw13(t, bad), r); err == nil {
			t.Fatalf("invalid serialized envelope %d accepted", i)
		}
	}
	raw, err := CanonicalRootGrantsEnvelope(e, r)
	if err != nil {
		t.Fatal(err)
	}
	variants := rootGrantsNullVariants13(t, raw)
	order := append([]string(nil), rootGrantsEnvelopeOrder13...)
	order[0], order[1] = order[1], order[0]
	blob := base64.StdEncoding.EncodeToString(e.EnclaveBlob)
	variants = append(variants, nil, make([]byte, recoveryMaxCiphertext+1), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), []byte("{}")...),
		rootGrantsOrderedJSON13(t, raw, order),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"keyvault-root-grants-ciphertext/1","schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"\u0073chema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"\u0073chema":"keyvault-root-grants-ciphertext/1","schema":`), 1),
		bytes.Replace(raw, []byte(blob), []byte(strings.TrimRight(blob, "=")), 1),
		bytes.Replace(raw, []byte(blob), []byte(blob+`\n`), 1))
	for i, bad := range variants {
		if _, err := ParseRootGrantsEnvelope(bad, r); err == nil {
			t.Fatalf("noncanonical envelope encoding %d accepted", i)
		}
	}
}

func rootGrantsPrivateFixture13(t *testing.T, r RootGrantsRecord) *rootGrantsPrepared {
	t.Helper()
	p := newRootGrantsPrepared()
	var entropy [64]byte
	entropy[31] = 3 // published BIP340 test authority; NOT a BIP85 index7 vector
	if err := p.state.setBIP85Entropy(&entropy); err != nil {
		t.Fatal(err)
	}
	clear(entropy[:])
	p.state.public.Pair = r.Pair // binding-only fixture, not enrollment evidence
	return p
}

// Claim: private KVG1 is68 bytes with independently constructed FULL-metadata
// domain hash; address/metadata tampering fails binding, zero/n fails scalar
// range, n-3 fails even parity while retaining the same x-only K. Alias clear,
// fixed formatting and JSON refusal prevent ordinary private-buffer export.
// Limits: no encryption/decryption/ABI; compiler/runtime erasure is not proven.
func TestRootGrantsEnvelope13PrivateBinding(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	p := rootGrantsPrivateFixture13(t, r)
	defer p.clear()
	plain, err := p.rootGrantsPlaintext(r)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.clear()
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("keyvault-root-grants/plaintext/1\x00"), metadata...)
	h := sha256.Sum256(input)
	if string(plain.buffer[:4]) != "KVG1" || !bytes.Equal(plain.buffer[4:36], h[:]) || plain.buffer[67] != 3 || plain.validate(r) != nil {
		t.Fatal("private KVG1 layout/domain mismatch")
	}
	for _, value := range []any{plain, *plain} {
		if fmt.Sprintf("%#v", value) != "<private-root-grants-plaintext>" {
			t.Fatal("private plaintext formatted")
		}
		if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
			t.Fatal("private plaintext serialization admitted")
		}
	}
	changed := rootGrantsCloneRecord13(t, r)
	changed.Version++
	rootGrantsWantRefusal(t, plain.validate(changed), "binding_mismatch")
	for _, offset := range []int{0, 4} {
		copy := &rootGrantsPlaintext{buffer: new([68]byte)}
		*copy.buffer = *plain.buffer
		copy.buffer[offset] ^= 1
		rootGrantsWantRefusal(t, copy.validate(r), "binding_mismatch")
		copy.clear()
	}
	n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
	for _, scalar := range []*big.Int{big.NewInt(0), n} {
		copy := &rootGrantsPlaintext{buffer: new([68]byte)}
		*copy.buffer = *plain.buffer
		scalar.FillBytes(copy.buffer[36:])
		rootGrantsWantRefusal(t, copy.validate(r), "invalid_derivation")
		copy.clear()
	}
	odd := &rootGrantsPlaintext{buffer: new([68]byte)}
	*odd.buffer = *plain.buffer
	new(big.Int).Sub(n, big.NewInt(3)).FillBytes(odd.buffer[36:])
	rootGrantsWantRefusal(t, odd.validate(r), "public_pin_mismatch")
	odd.clear()
	wrongKey := &rootGrantsPlaintext{buffer: new([68]byte)}
	*wrongKey.buffer = *plain.buffer
	clear(wrongKey.buffer[36:])
	wrongKey.buffer[67] = 1 // valid even-Y scalar1, but not the pinned scalar3 K
	rootGrantsWantRefusal(t, wrongKey.validate(r), "public_pin_mismatch")
	wrongKey.clear()
	alias := *plain
	plain.clear()
	if *alias.buffer != [68]byte{} {
		t.Fatal("private plaintext alias survived clear")
	}
	rootGrantsWantRefusal(t, alias.validate(r), "binding_mismatch")
	p.clear()
	if got, err := p.rootGrantsPlaintext(r); err == nil || got != nil {
		t.Fatal("cleared preparation produced plaintext")
	}
}
