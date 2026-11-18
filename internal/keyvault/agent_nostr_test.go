package keyvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const agentNostrTestScalarOrderHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

type agentNostrFixtureDocument struct {
	MetadataJSON      string `json:"metadata_json"`
	RecordFingerprint string `json:"record_fingerprint"`
	KeySHA256         string `json:"key_sha256"`
	EnrollmentJSON    string `json:"enrollment_json"`
	EnvelopeJSON      string `json:"envelope_json"`
	PlaintextHex      string `json:"plaintext_hex"`
}

type agentNostrFrozenMutantDocument struct {
	Name                 string `json:"name"`
	ExpectedFirstFailure string `json:"expected_first_failure"`
	MetadataJSON         string `json:"metadata_json"`
	RecordFingerprint    string `json:"record_fingerprint"`
	KeySHA256            string `json:"key_sha256"`
	EnrollmentJSON       string `json:"enrollment_json"`
	EnvelopeJSON         string `json:"envelope_json"`
	PlaintextHex         string `json:"plaintext_hex"`
}

func readAgentNostrFixture(t *testing.T, name string) agentNostrFixtureDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "agent-nostr", name))
	if err != nil {
		t.Fatal("public agent Nostr fixture unavailable")
	}
	var fixture agentNostrFixtureDocument
	if json.Unmarshal(raw, &fixture) != nil || fixture.MetadataJSON == "" || fixture.EnrollmentJSON == "" || fixture.EnvelopeJSON == "" {
		t.Fatal("public agent Nostr fixture is malformed")
	}
	return fixture
}

func readAgentNostrFrozenMutant(t *testing.T, name string) (agentNostrFrozenMutantDocument, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "agent-nostr", name))
	if err != nil {
		t.Fatal("frozen agent Nostr mutant unavailable")
	}
	var mutant agentNostrFrozenMutantDocument
	if json.Unmarshal(raw, &mutant) != nil || mutant.Name == "" || mutant.ExpectedFirstFailure == "" || mutant.PlaintextHex == "" {
		t.Fatal("frozen agent Nostr mutant is malformed")
	}
	plaintext, err := hex.DecodeString(mutant.PlaintextHex)
	if err != nil || len(plaintext) != AgentNostrPlaintextSize {
		t.Fatal("frozen agent Nostr mutant plaintext is malformed")
	}
	return mutant, plaintext
}

type agentNostrSignFixture struct {
	store      *agentNostrFakeStore
	private    *agentNostrFakePrivate
	manager    *AgentNostrManager
	record     AgentNostrRecord
	receipt    AgentNostrEnrollment
	receiptRaw []byte
	metadata   []byte
	envelope   []byte
	plaintext  []byte
}

func newAgentNostrSignFixture(t *testing.T, service string, version int, identity string, blobSize int) agentNostrSignFixture {
	t.Helper()
	a := readAgentNostrFixture(t, "fixture-a.json")
	record, _, err := ParseAgentNostrRecord([]byte(a.MetadataJSON))
	if err != nil {
		t.Fatal("fixture A metadata unavailable")
	}
	record.Service, record.Version = service, version
	metadata, err := MarshalAgentNostrRecord(record)
	if err != nil {
		t.Fatal("endpoint metadata could not be canonicalized")
	}
	public := AgentNostrPublicResult(record, metadata)
	receipt := AgentNostrEnrollment{
		Schema: AgentNostrReceiptSchema, OwnerMXID: identity, Service: service, Purpose: "nostr", Version: version,
		PublicKey: record.PublicKey, KeySHA256: public.KeySHA256, RecordFingerprint: public.RecordFingerprint,
	}
	receiptRaw, err := MarshalAgentNostrEnrollment(receipt)
	if err != nil {
		t.Fatal("endpoint receipt could not be canonicalized")
	}
	if _, err := ParseAgentNostrEnrollment(receiptRaw); err != nil {
		t.Fatal("canonical endpoint receipt did not round-trip")
	}
	var envelope AgentNostrEnvelope
	if json.Unmarshal([]byte(a.EnvelopeJSON), &envelope) != nil {
		t.Fatal("fixture A envelope unavailable")
	}
	if blobSize >= 0 {
		envelope.EnclaveBlob = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, blobSize))
	}
	var envelopeRaw []byte
	if blobSize < 0 || blobSize <= AgentNostrMaxBlob {
		envelopeRaw, err = MarshalAgentNostrEnvelope(envelope, record)
	} else {
		envelopeRaw, err = json.Marshal(envelope)
	}
	if err != nil {
		t.Fatal("endpoint envelope could not be encoded")
	}
	plaintext := mustAgentNostrFixturePlaintext(t, a)
	metadataHash := sha256.Sum256(metadata)
	copy(plaintext[5:37], metadataHash[:])
	store := newAgentNostrFakeStore()
	store.items[AgentNostrAccount(service, version)] = agentNostrFakeItem{metadata: metadata, envelope: envelopeRaw}
	private := &agentNostrFakePrivate{plaintext: [][]byte{bytes.Clone(plaintext)}}
	return agentNostrSignFixture{
		store: store, private: private, manager: newAgentNostrTestManager(store, private), record: record,
		receipt: receipt, receiptRaw: receiptRaw, metadata: metadata, envelope: envelopeRaw, plaintext: plaintext,
	}
}

// Claim: only the exact contract-derived service/version forms are admitted;
// limit: actor authority remains an external trusted operating policy.
func TestAgentNostrServiceAndVersionAllowlist(t *testing.T) {
	for _, service := range []string{"agent-a", "agent-0", "agent-" + strings.Repeat("a", 34)} {
		if err := ValidateAgentNostrService(service); err != nil {
			t.Fatalf("valid service %q refused", service)
		}
	}
	for _, service := range []string{"agent-", "agent--a", "agent-_a", "agent-A", "agent-a_", "agent-" + strings.Repeat("a", 35), "other-a", "agent-a/nostr", "agent-a\n"} {
		if err := ValidateAgentNostrService(service); err == nil {
			t.Fatalf("forbidden service %q accepted", service)
		}
	}
	for _, version := range []int{1, 2147483647} {
		if err := ValidateAgentNostrVersion(version); err != nil {
			t.Fatalf("valid version %d refused", version)
		}
	}
	for _, version := range []int{-1, 0, 2147483648} {
		if err := ValidateAgentNostrVersion(version); err == nil {
			t.Fatalf("forbidden version %d accepted", version)
		}
	}
}

// Claim: public-store errors cannot invent post-dispatch UNKNOWN or input/receipt
// failures; limit: this checks the shared mapping, not native OS status evidence.
func TestAgentNostrPublicStoreErrorMapIsClosed(t *testing.T) {
	for _, code := range []string{AgentNostrCodeUnknown, AgentNostrCodeInvalidInput, AgentNostrCodeInvalidEnrollment, AgentNostrCodeEnrollmentMismatch} {
		if got := agentNostrMapStoreError(&AgentNostrFailure{Code: code}); got.Code != AgentNostrCodeUnavailable {
			t.Fatalf("read-only store error %q escaped as %q", code, got.Code)
		}
	}
	for _, code := range []string{AgentNostrCodeDuplicate, AgentNostrCodeNotFound, AgentNostrCodeCorruptRecord, AgentNostrCodeUnavailable, AgentNostrCodeUntrusted} {
		if got := agentNostrMapStoreError(&AgentNostrFailure{Code: code}); got.Code != code {
			t.Fatalf("known store status %q changed to %q", code, got.Code)
		}
	}
}

// Claim: public metadata and enrollment are exact canonical documents with
// pinned hashes; limit: file provenance is checked at the CLI boundary.
func TestAgentNostrPublicFixturesAndStrictCanonicalDocuments(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	b := readAgentNostrFixture(t, "fixture-b.json")
	recordA, fingerprintA, err := ParseAgentNostrRecord([]byte(a.MetadataJSON))
	if err != nil || fingerprintA != a.RecordFingerprint {
		t.Fatal("fixture A metadata or fingerprint changed")
	}
	recordB, fingerprintB, err := ParseAgentNostrRecord([]byte(b.MetadataJSON))
	if err != nil || fingerprintB != b.RecordFingerprint {
		t.Fatal("fixture B metadata or fingerprint changed")
	}
	if recordA.Service != recordB.Service || recordA.Version != recordB.Version || recordA.PublicKey == recordB.PublicKey || recordA.WrappingPoint == recordB.WrappingPoint {
		t.Fatal("B is not a complete distinct replacement at A's selector")
	}
	receiptA, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil || receiptA.RecordFingerprint != fingerprintA || receiptA.KeySHA256 != a.KeySHA256 {
		t.Fatal("fixture A enrollment does not pin its public record")
	}
	if _, err := ParseAgentNostrEnvelope([]byte(a.EnvelopeJSON), recordA); err != nil {
		t.Fatal("fixture A envelope rejected")
	}
	if _, err := ParseAgentNostrEnvelope([]byte(b.EnvelopeJSON), recordB); err != nil {
		t.Fatal("fixture B envelope rejected")
	}
	if got, err := MarshalAgentNostrRecord(recordA); err != nil || !bytes.Equal(got, []byte(a.MetadataJSON)) {
		t.Fatal("metadata canonical encoding changed")
	}
	if got, err := MarshalAgentNostrEnrollment(receiptA); err != nil || !bytes.Equal(got, []byte(a.EnrollmentJSON)) {
		t.Fatal("enrollment canonical encoding changed")
	}

	badMetadata := [][]byte{
		append(append([]byte(nil), []byte(a.MetadataJSON[:len(a.MetadataJSON)-1])...), []byte(`,"unknown":true}`)...),
		bytes.Replace([]byte(a.MetadataJSON), []byte(`"presence":false`), []byte(`"presence":false,"presence":false`), 1),
		append([]byte(a.MetadataJSON), ' '),
		[]byte(strings.Replace(a.MetadataJSON, `"service":"agent-fixture"`, `"service":"agent-fixture","schema":"agent-nostr-key/1"`, 1)),
	}
	for i, raw := range badMetadata {
		if _, _, err := ParseAgentNostrRecord(raw); err == nil {
			t.Fatalf("malformed metadata control %d accepted", i)
		}
	}
	badReceipt := [][]byte{
		bytes.Replace([]byte(a.EnrollmentJSON), []byte(`"owner_mxid"`), []byte(`"unexpected"`), 1),
		bytes.Replace([]byte(a.EnrollmentJSON), []byte(`"owner_mxid":"@agent-fixture:example.invalid"`), []byte(`"owner_mxid":"@agent-fixture:example.invalid","owner_mxid":"@other:example.invalid"`), 1),
		append([]byte(a.EnrollmentJSON), []byte(`{}`)...),
		[]byte(strings.Replace(a.EnrollmentJSON, `"schema":"agent-nostr-enrollment/1"`, `"owner_mxid":"@agent-fixture:example.invalid","schema":"agent-nostr-enrollment/1"`, 1)),
	}
	for i, raw := range badReceipt {
		if _, err := ParseAgentNostrEnrollment(raw); err == nil {
			t.Fatalf("malformed enrollment control %d accepted", i)
		}
	}
}

// Claim: ECDH transcript construction allocates its full secret-bearing buffer
// once and clears that buffer and the derived key after use; limit: Go cannot
// promise erasure of compiler, register, or library-owned copies.
func TestAgentNostrDerivedTranscriptAndKeyAreCleared(t *testing.T) {
	shared := []byte("fixture-shared-secret")
	point := []byte("fixture-public-point")
	expected := make([]byte, len(shared)+4+len(point))
	copy(expected, shared)
	copy(expected[len(shared):], []byte{0, 0, 0, 1})
	copy(expected[len(shared)+4:], point)
	var transcript, derived []byte
	expectedDerived := sha256.Sum256(expected)
	err := agentNostrWithDerived(shared, point, func(input []byte) [32]byte {
		transcript = input
		if len(input) != len(expected) || cap(input) != len(input) || !bytes.Equal(input, expected) {
			t.Fatal("ECDH transcript was not one complete preallocated buffer")
		}
		return sha256.Sum256(input)
	}, func(input []byte) error {
		derived = input
		if !bytes.Equal(input, expectedDerived[:]) {
			t.Fatal("derived key did not match the frozen transcript")
		}
		return nil
	})
	if err != nil || !allZeroAgentNostrBytes(transcript) || !allZeroAgentNostrBytes(derived) {
		t.Fatal("owned ECDH transcript or derived key remained after use")
	}
}

func allZeroAgentNostrBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// Claim: A/E_A is a valid full-path signing sibling, while a valid B at the
// same selector cannot be substituted under E_A; limit: the fake private
// helper does not prove reciprocal native process admission.
func TestAgentNostrSignRequiresExternalReceiptBeforeEnvelopeLoad(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	b := readAgentNostrFixture(t, "fixture-b.json")
	receiptA, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt A unavailable")
	}
	store := newAgentNostrFakeStore()
	store.putFixture(t, b)
	private := &agentNostrFakePrivate{plaintext: [][]byte{mustAgentNostrFixturePlaintext(t, b)}}
	manager := newAgentNostrTestManager(store, private)
	_, err = manager.Sign(receiptA.OwnerMXID, receiptA, receiptA.Service, receiptA.Version, bytes.Repeat([]byte{0}, 32))
	if agentNostrFailureCode(err) != AgentNostrCodeEnrollmentMismatch || store.selects != 1 || store.loads != 0 || private.unwraps != 0 {
		t.Fatal("valid replacement B escaped E_A pin checks or ciphertext was loaded too early")
	}

	receiptB, err := ParseAgentNostrEnrollment([]byte(b.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt B unavailable")
	}
	private.plaintext = [][]byte{mustAgentNostrFixturePlaintext(t, b)}
	result, err := manager.Sign(receiptB.OwnerMXID, receiptB, receiptB.Service, receiptB.Version, bytes.Repeat([]byte{0}, 32))
	if err != nil || len(result.Signature) != 128 || result.RecordFingerprint != b.RecordFingerprint || result.KeySHA256 != b.KeySHA256 || store.loads != 1 || private.unwraps != 1 {
		t.Fatal("B/E_B positive signing control failed")
	}
}

// Claim: a retained A selection cannot release a replacement B envelope after
// selection; limit: the fake demonstrates the Go metadata recheck, not native
// Keychain item identity or ACL behavior.
func TestAgentNostrSelectedItemReplacementIsRefused(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	b := readAgentNostrFixture(t, "fixture-b.json")
	receipt, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt A unavailable")
	}
	store := newAgentNostrFakeStore()
	store.putFixture(t, a)
	account := AgentNostrAccount(receipt.Service, receipt.Version)
	_, bFingerprint, err := ParseAgentNostrRecord([]byte(b.MetadataJSON))
	if err != nil || bFingerprint == receipt.RecordFingerprint {
		t.Fatal("replacement B is not a distinct canonical item")
	}
	private := &agentNostrFakePrivate{plaintext: [][]byte{mustAgentNostrFixturePlaintext(t, a)}}
	manager := newAgentNostrTestManager(store, private)
	store.onSelect = func(s *agentNostrFakeStore, selected string) {
		if selected == account {
			s.items[selected] = agentNostrFakeItem{metadata: []byte(b.MetadataJSON), envelope: []byte(b.EnvelopeJSON)}
			s.onSelect = nil
		}
	}
	_, err = manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, bytes.Repeat([]byte{0x3a}, 32))
	if agentNostrFailureCode(err) != AgentNostrCodeEnrollmentMismatch || store.selects != 1 || store.loads != 1 || private.unwraps != 0 || store.adds != 0 {
		t.Fatal("replacement item reached private release, signing, mutation, or fallback")
	}
	if !bytes.Equal(store.items[account].metadata, []byte(b.MetadataJSON)) || !bytes.Equal(store.items[account].envelope, []byte(b.EnvelopeJSON)) {
		t.Fatal("replacement item was overwritten while refusing the selection race")
	}

	positiveStore := newAgentNostrFakeStore()
	positiveStore.putFixture(t, a)
	positivePrivate := &agentNostrFakePrivate{plaintext: [][]byte{mustAgentNostrFixturePlaintext(t, a)}}
	positiveManager := newAgentNostrTestManager(positiveStore, positivePrivate)
	result, err := positiveManager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, bytes.Repeat([]byte{0x3a}, 32))
	if err != nil || len(result.Signature) != 128 || positivePrivate.unwraps != 1 || positiveStore.adds != 0 {
		t.Fatal("unchanged selected A positive control did not sign")
	}
}

// Claim: frozen valid-AEAD domain, binding, scalar and public-key mutants reach
// the production Sign guard named by their fixture, with A usable on both sides;
// limit: private unwrap is a typed test seam, while the oracle package checks
// fixture AEAD independently and this does not qualify native custody.
func TestAgentNostrFrozenSignMutantsPreserveAAndReachFirstGuard(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	receipt, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt A unavailable")
	}
	aPlaintext := mustAgentNostrFixturePlaintext(t, a)
	digest := bytes.Repeat([]byte{0x3a}, 32)
	for _, tc := range []struct {
		file, failure, guard string
	}{
		{"mutant-domain-kvax1.json", "domain", "domain"},
		{"mutant-binding.json", "metadata-binding", "metadata-binding"},
		{"mutant-scalar-zero.json", "scalar-range", "scalar-range"},
		{"mutant-scalar-order.json", "scalar-range", "scalar-range"},
		{"mutant-scalar-n-plus-3.json", "scalar-range-before-reduction", "scalar-range"},
		{"mutant-scalar-key-mismatch.json", "public-key-match", "public-key-match"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			mutant, mutantPlaintext := readAgentNostrFrozenMutant(t, tc.file)
			if mutant.ExpectedFirstFailure != tc.failure || mutant.MetadataJSON != a.MetadataJSON ||
				mutant.RecordFingerprint != a.RecordFingerprint || mutant.KeySHA256 != a.KeySHA256 || mutant.EnrollmentJSON != a.EnrollmentJSON {
				t.Fatal("frozen mutant changed A/E_A instead of only its private plaintext")
			}
			record, _, err := ParseAgentNostrRecord([]byte(a.MetadataJSON))
			if err != nil {
				t.Fatal("A metadata unavailable")
			}
			if _, err := ParseAgentNostrEnvelope([]byte(mutant.EnvelopeJSON), record); err != nil {
				t.Fatal("frozen mutant envelope is not a canonical A envelope")
			}

			store := newAgentNostrFakeStore()
			store.putFixture(t, a)
			account := AgentNostrAccount(receipt.Service, receipt.Version)
			original := store.items[account]
			private := &agentNostrFakePrivate{plaintext: [][]byte{aPlaintext, mutantPlaintext, aPlaintext}}
			manager := newAgentNostrTestManager(store, private)
			signCalls, publicCalls := 0, 0
			lastGuard := ""
			realPublicFromSecret := manager.publicFromSecret
			manager.publicFromSecret = func(secret []byte) ([]byte, error) {
				publicCalls++
				return realPublicFromSecret(secret)
			}
			manager.signGuardObserved = func(guard string) { lastGuard = guard }
			manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
				signCalls++
				return signNostrWithAux(secret, digest, aux)
			}

			if result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); err != nil || len(result.Signature) != 128 {
				t.Fatal("A did not sign before the frozen mutant")
			}
			lastGuard = ""
			item := store.items[account]
			item.envelope = []byte(mutant.EnvelopeJSON)
			store.items[account] = item
			if result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord || result.Signature != "" || lastGuard != tc.guard {
				t.Fatalf("mutant did not stop at its first production guard: result=%+v failure=%s guard=%q want=%q", result, agentNostrFailureCode(err), lastGuard, tc.guard)
			}
			wantPublicCalls := 1
			if tc.guard == "public-key-match" {
				wantPublicCalls = 2
			}
			if publicCalls != wantPublicCalls || signCalls != 1 {
				t.Fatal("mutant reached scalar construction/signing beyond its intended first guard")
			}
			lastGuard = ""
			item = store.items[account]
			item.envelope = bytes.Clone(original.envelope)
			store.items[account] = item
			if result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); err != nil || len(result.Signature) != 128 {
				t.Fatal("A did not sign after the frozen mutant")
			}
			if store.selects != 3 || store.loads != 3 || private.unwraps != 3 || signCalls != 2 || store.adds != 0 ||
				!bytes.Equal(store.items[account].metadata, original.metadata) || !bytes.Equal(store.items[account].envelope, original.envelope) {
				t.Fatal("A/mutant/A changed persisted state or crossed an unintended effect")
			}
		})
	}
}

// Claim: an isolated override that accepts only n+3 passes the bytes to scalar
// construction and is visible as the wrong first guard; limit: the override is
// test-local and the production manager retains the contract range predicate.
func TestAgentNostrNPlusThreeGuardRemovalInstrumentIsObserved(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	mutant, mutantPlaintext := readAgentNostrFrozenMutant(t, "mutant-scalar-n-plus-3.json")
	receipt, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil || mutant.ExpectedFirstFailure != "scalar-range-before-reduction" {
		t.Fatal("A receipt or n+3 frozen vector unavailable")
	}
	store := newAgentNostrFakeStore()
	store.putFixture(t, a)
	private := &agentNostrFakePrivate{plaintext: [][]byte{mutantPlaintext}}
	manager := newAgentNostrTestManager(store, private)
	constructorCalls := 0
	manager.scalarInRange = func(secret []byte) bool {
		if bytes.Equal(secret, mutantPlaintext[37:]) {
			return true // isolate removal of only the frozen n+3 range rejection
		}
		return agentNostrScalarInRange(secret)
	}
	realPublicFromSecret := manager.publicFromSecret
	manager.publicFromSecret = func(secret []byte) ([]byte, error) {
		constructorCalls++
		return realPublicFromSecret(secret)
	}
	lastGuard := ""
	manager.signGuardObserved = func(guard string) { lastGuard = guard }
	result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, bytes.Repeat([]byte{0x3a}, 32))
	if agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord || result.Signature != "" || constructorCalls != 1 || lastGuard != "private-scalar-construction" || store.adds != 0 {
		t.Fatal("overflow-only removal was not detected at the later scalar-construction guard")
	}
}

// Claim: unreduced n+3 is refused before signing, then the valid A sibling
// still signs; limit: scalar interpretation is checked in software fixtures.
func TestAgentNostrRejectsNonzeroScalarOverflowAndPreservesA(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	receipt, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt A unavailable")
	}
	plain := mustAgentNostrFixturePlaintext(t, a)
	order, ok := new(big.Int).SetString(agentNostrTestScalarOrderHex, 16)
	if !ok {
		t.Fatal("scalar order unavailable")
	}
	nPlusThree := new(big.Int).Add(order, big.NewInt(3)).FillBytes(make([]byte, 32))
	copy(plain[37:], nPlusThree)
	store := newAgentNostrFakeStore()
	store.putFixture(t, a)
	private := &agentNostrFakePrivate{plaintext: [][]byte{plain, mustAgentNostrFixturePlaintext(t, a)}}
	manager := newAgentNostrTestManager(store, private)
	signCalls := 0
	manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
		signCalls++
		return signNostrWithAux(secret, digest, aux)
	}
	_, err = manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, bytes.Repeat([]byte{0}, 32))
	if agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord || store.loads != 1 || private.unwraps != 1 || signCalls != 0 {
		t.Fatal("n+3 reached key construction/signing or used an unrelated guard")
	}
	res, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, bytes.Repeat([]byte{0}, 32))
	if err != nil || len(res.Signature) != 128 || store.adds != 0 || signCalls != 1 {
		t.Fatal("valid A did not remain usable after the overflow refusal")
	}
}

// Claim: the scalar predicate accepts the exact positive range and rejects
// zero, n, n+3, and wrong lengths before curve construction; limit: this is a
// software boundary check, not a hardware key-origin claim.
func TestAgentNostrScalarRangeStrictBounds(t *testing.T) {
	order, ok := new(big.Int).SetString(agentNostrTestScalarOrderHex, 16)
	if !ok {
		t.Fatal("scalar order unavailable")
	}
	zero := make([]byte, 32)
	one := make([]byte, 32)
	one[31] = 1
	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1)).FillBytes(make([]byte, 32))
	orderBytes := order.FillBytes(make([]byte, 32))
	orderPlusThree := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(3)).FillBytes(make([]byte, 32))
	for name, input := range map[string][]byte{
		"zero":         zero,
		"n":            orderBytes,
		"n-plus-three": orderPlusThree,
		"empty":        nil,
		"short":        one[1:],
		"long":         append(bytes.Clone(one), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if agentNostrScalarInRange(input) {
				t.Fatal("out-of-range scalar accepted")
			}
		})
	}
	for name, input := range map[string][]byte{"one": one, "n-minus-one": orderMinusOne} {
		t.Run(name, func(t *testing.T) {
			if !agentNostrScalarInRange(input) {
				t.Fatal("valid scalar refused")
			}
		})
	}
}

// Claim: creation uses a fresh key, fixed P-256 test wrapper, canonical
// metadata/envelope and one exclusive add; limit: test entropy is not a
// production randomness qualification.
func TestAgentNostrGenerateUsesExactAccountAndAtomicCreate(t *testing.T) {
	store := newAgentNostrFakeStore()
	private := &agentNostrFakePrivate{wrapScalar: 1}
	manager := newAgentNostrTestManager(store, private)
	randomBytes := append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 31)...)
	randomBytes = append(randomBytes, 3)
	randomBytes = append(randomBytes, bytes.Repeat([]byte{0x42}, 64)...)
	manager.random = bytes.NewReader(randomBytes)
	manager.now = func() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 123, time.FixedZone("offset", 3600)) }
	result, err := manager.Generate("agent-a", 1)
	if err != nil || result.Record.Service != "agent-a" || result.Record.Purpose != "nostr" || result.Record.Version != 1 || result.Record.Presence || result.Record.PrivateExport || result.Record.Storage != "enclave-wrapped-keychain" {
		t.Fatal("generate failed or emitted a noncontract record")
	}
	if result.Record.Created != "2026-11-16T23:00:00Z" || store.adds != 1 || private.wraps != 1 || store.lastAccount != "agent-a/nostr@1" {
		t.Fatal("generate did not use one exact account/add and canonical UTC seconds")
	}
	if store.selects != 1 || store.loads != 1 {
		t.Fatal("generation did not validate the exact post-add item readback")
	}
	stored := store.items[store.lastAccount]
	parsed, fingerprint, err := ParseAgentNostrRecord(stored.metadata)
	if err != nil || fingerprint != result.RecordFingerprint || parsed.PublicKey != result.Record.PublicKey {
		t.Fatal("stored metadata differs from returned record pin")
	}
	envelope, err := ParseAgentNostrEnvelope(stored.envelope, parsed)
	if err != nil || len(mustDecodeAgentNostrBase64(t, envelope.Ciphertext)) != 150 {
		t.Fatal("stored envelope does not carry exact ciphertext")
	}
	private.wrapScalar = 1
	plain, err := openAgentNostrForTest(t, envelope)
	if err != nil || len(plain) != 69 || string(plain[:5]) != "KVAN1" || !bytes.Equal(plain[5:37], mustHexDigest(t, fingerprint)) {
		t.Fatal("generated fixture cannot be independently opened or bound")
	}
	if _, err := manager.Generate("agent-a", 1); agentNostrFailureCode(err) != AgentNostrCodeDuplicate || store.adds != 1 || private.wraps != 1 {
		t.Fatal("duplicate did not refuse before entropy/wrap/add")
	}
}

// Claim: an attempted add followed by an unavailable exact readback is
// UNKNOWN with its candidate pin; limit: the fake does not model Keychain
// commit durability after process loss.
func TestAgentNostrGenerateReadbackFailureIsUnknownWithoutRetry(t *testing.T) {
	store := newAgentNostrFakeStore()
	store.readbackErr = errors.New("fixture readback unavailable")
	private := &agentNostrFakePrivate{wrapScalar: 1}
	manager := newAgentNostrTestManager(store, private)
	manager.random = bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x42}, 128)...))
	_, err := manager.Generate("agent-a", 1)
	var failure *AgentNostrFailure
	if !errors.As(err, &failure) || failure.Code != AgentNostrCodeUnknown || failure.Operation != "generate" || failure.Outcome != "unknown" || failure.PublicKey == "" || failure.KeySHA256 == "" || failure.RecordFingerprint == "" {
		t.Fatal("post-add readback failure did not return the exact public candidate as unknown")
	}
	if store.adds != 1 || store.selects != 1 || store.loads != 0 || private.wraps != 1 {
		t.Fatal("generation retried, selected an unrelated item, or bypassed the failed readback")
	}
}

// Claim: invalid/short entropy refuses before helper dispatch or persistence;
// limit: the injected reader does not qualify the operating-system RNG.
func TestAgentNostrGenerateEntropyFailureHasNoPersistentEffect(t *testing.T) {
	for _, source := range [][]byte{bytes.Repeat([]byte{0}, 32*128), {1, 2, 3}} {
		store := newAgentNostrFakeStore()
		private := &agentNostrFakePrivate{wrapScalar: 1}
		manager := newAgentNostrTestManager(store, private)
		manager.random = bytes.NewReader(source)
		_, err := manager.Generate("agent-a", 1)
		if agentNostrFailureCode(err) != AgentNostrCodeUnavailable || store.adds != 0 || private.wraps != 0 || len(store.items) != 0 {
			t.Fatal("entropy failure crossed the private-wrap or persistence boundary")
		}
	}
}

// Claim: generation cannot replace a row inserted in the check/add race;
// limit: the fake models atomic duplicate preservation, not Keychain locking.
func TestAgentNostrGenerateRacingDuplicatePreservesOriginal(t *testing.T) {
	fixture := readAgentNostrFixture(t, "fixture-a.json")
	record, _, err := ParseAgentNostrRecord([]byte(fixture.MetadataJSON))
	if err != nil {
		t.Fatal("race fixture record unavailable")
	}
	record.Service, record.Version = "agent-a", 1
	account := AgentNostrAccount("agent-a", 1)
	original, err := MarshalAgentNostrRecord(record)
	if err != nil {
		t.Fatal("race fixture metadata unavailable")
	}
	store := newAgentNostrFakeStore()
	store.onAdd = func(s *agentNostrFakeStore, account string) {
		s.items[account] = agentNostrFakeItem{metadata: bytes.Clone(original)}
		s.addErr = &AgentNostrFailure{Code: AgentNostrCodeDuplicate}
	}
	private := &agentNostrFakePrivate{wrapScalar: 1}
	manager := newAgentNostrTestManager(store, private)
	_, err = manager.Generate("agent-a", 1)
	if agentNostrFailureCode(err) != AgentNostrCodeDuplicate || store.adds != 1 || private.wraps != 1 || !bytes.Equal(store.items[account].metadata, original) || len(store.items) != 1 {
		t.Fatal("racing duplicate replaced or expanded the original item")
	}
}

// Claim: an exact native add refusal remains a definite no-effect outcome
// even though the atomic call was entered; limit: fake statuses do not prove
// Security.framework status guarantees on a live Keychain.
func TestAgentNostrGeneratePreservesKnownAddRefusals(t *testing.T) {
	for _, code := range []string{AgentNostrCodeUntrusted, AgentNostrCodeCorruptRecord, AgentNostrCodeUnavailable} {
		t.Run(code, func(t *testing.T) {
			store := newAgentNostrFakeStore()
			store.addAttempt = true
			store.addErr = &AgentNostrFailure{Code: code}
			private := &agentNostrFakePrivate{wrapScalar: 1}
			manager := newAgentNostrTestManager(store, private)
			_, err := manager.Generate("agent-fixture", 1)
			if agentNostrFailureCode(err) != code || store.adds != 1 || len(store.items) != 0 || private.wraps != 1 {
				t.Fatalf("known atomic refusal lost its no-effect code: code=%s adds=%d items=%d wraps=%d", agentNostrFailureCode(err), store.adds, len(store.items), private.wraps)
			}
		})
	}
}

// Claim: an unclassified error after entering the atomic add is UNKNOWN and is
// never retried; limit: the fake cannot witness a real Keychain commit race.
func TestAgentNostrGenerateAtomicAddAmbiguityIsUnknown(t *testing.T) {
	store := newAgentNostrFakeStore()
	store.addAttempt = true
	store.addErr = errors.New("ambiguous add result")
	manager := newAgentNostrTestManager(store, &agentNostrFakePrivate{wrapScalar: 1})
	_, err := manager.Generate("agent-fixture", 1)
	var failure *AgentNostrFailure
	if !errors.As(err, &failure) || failure.Code != AgentNostrCodeUnknown || failure.Outcome != "unknown" ||
		failure.PublicKey == "" || failure.KeySHA256 == "" || failure.RecordFingerprint == "" || store.adds != 1 {
		t.Fatalf("ambiguous atomic add was retried or lost its public candidate: failure=%+v adds=%d", failure, store.adds)
	}
}

// Claim: separate explicit generations receive distinct software key and
// wrapping-point outputs; limit: this fixture does not prove RNG quality or SE origin.
func TestAgentNostrGenerateUsesFreshIndependentKeyMaterial(t *testing.T) {
	store := newAgentNostrFakeStore()
	private := &agentNostrFakePrivate{wrapScalar: 1}
	manager := newAgentNostrTestManager(store, private)
	manager.random = bytes.NewReader(bytes.Join([][]byte{
		append(bytes.Repeat([]byte{0}, 31), 3), bytes.Repeat([]byte{0x42}, 32),
		append(bytes.Repeat([]byte{0}, 31), 4), bytes.Repeat([]byte{0x43}, 32),
	}, nil))
	a, err := manager.Generate("agent-a", 1)
	if err != nil {
		t.Fatal("first generation fixture failed")
	}
	b, err := manager.Generate("agent-a", 2)
	if err != nil {
		t.Fatal("second generation fixture failed")
	}
	if a.Record.PublicKey == b.Record.PublicKey || a.Record.WrappingPoint == b.Record.WrappingPoint || store.adds != 2 || private.wraps != 2 {
		t.Fatal("two explicit generations reused key or wrapping material")
	}
}

// Claim: numeric version ordering and an empty list are valid and confined
// to the agent namespace; limit: native query namespace isolation is a
// separate C backend check.
func TestAgentNostrListNumericVersionOrder(t *testing.T) {
	store := newAgentNostrFakeStore()
	for _, fixtureName := range []string{"fixture-a.json", "fixture-b.json"} {
		fixture := readAgentNostrFixture(t, fixtureName)
		store.putFixture(t, fixture)
	}
	// Change only the service/version and re-canonicalize a second public row.
	fixture := readAgentNostrFixture(t, "fixture-a.json")
	record, _, err := ParseAgentNostrRecord([]byte(fixture.MetadataJSON))
	if err != nil {
		t.Fatal("fixture A record unavailable")
	}
	for _, pair := range []struct {
		service string
		version int
	}{{"agent-z", 10}, {"agent-z", 2}, {"agent-a", 1}} {
		copyRecord := record
		copyRecord.Service, copyRecord.Version = pair.service, pair.version
		raw, err := MarshalAgentNostrRecord(copyRecord)
		if err != nil {
			t.Fatal("canonical test record unavailable")
		}
		store.items[AgentNostrAccount(pair.service, pair.version)] = agentNostrFakeItem{metadata: raw}
	}
	manager := newAgentNostrTestManager(store, &agentNostrFakePrivate{})
	rows, err := manager.List()
	if err != nil || len(rows) != 4 {
		t.Fatal("agent list failed or crossed selector rows")
	}
	if rows[0].Record.Service != "agent-a" || rows[1].Record.Service != "agent-fixture" || rows[2].Record.Version != 2 || rows[3].Record.Version != 10 {
		t.Fatal("agent list did not sort by service then numeric version")
	}
	empty := newAgentNostrTestManager(newAgentNostrFakeStore(), &agentNostrFakePrivate{})
	if rows, err := empty.List(); err != nil || len(rows) != 0 {
		t.Fatal("empty agent list is not valid")
	}
}

// Claim: describe selects one exact public generation without inventory or
// ciphertext access; limit: physical selector and ACL correctness remain in
// the native lane.
func TestAgentNostrDescribeSelectsExactPublicItem(t *testing.T) {
	fixture := readAgentNostrFixture(t, "fixture-a.json")
	store := newAgentNostrFakeStore()
	store.putFixture(t, fixture)
	manager := newAgentNostrTestManager(store, &agentNostrFakePrivate{})
	public, err := manager.Describe("agent-fixture", 1)
	if err != nil || public.Record.Service != "agent-fixture" || public.Record.Version != 1 || store.listCalls != 0 || store.selects != 1 || store.loads != 0 {
		t.Fatal("describe read unrelated inventory or loaded a private envelope")
	}
	if _, err := manager.Describe("agent-fixture", 2); agentNostrFailureCode(err) != AgentNostrCodeNotFound || store.loads != 0 {
		t.Fatal("describe did not refuse an absent exact generation without fallback")
	}
}

// Claim: a valid retained E_A never falls back when only the exact standalone
// row is absent, and A works again when restored; limit: legacy/recovery rows
// are inert fixture neighbors, not real namespace or native-store probes.
func TestAgentNostrSignExactAbsenceDoesNotFallbackAndPreservesReceipt(t *testing.T) {
	a := readAgentNostrFixture(t, "fixture-a.json")
	receipt, err := ParseAgentNostrEnrollment([]byte(a.EnrollmentJSON))
	if err != nil {
		t.Fatal("receipt A unavailable")
	}
	store := newAgentNostrFakeStore()
	store.putFixture(t, a)
	store.otherRows = map[string][]byte{
		"legacy/agent-fixture/nostr@1":   []byte("legacy-fixture-row"),
		"recovery/agent-fixture/nostr@1": []byte("recovery-fixture-row"),
	}
	neighbors := map[string][]byte{
		"legacy/agent-fixture/nostr@1":   bytes.Clone(store.otherRows["legacy/agent-fixture/nostr@1"]),
		"recovery/agent-fixture/nostr@1": bytes.Clone(store.otherRows["recovery/agent-fixture/nostr@1"]),
	}
	private := &agentNostrFakePrivate{plaintext: [][]byte{mustAgentNostrFixturePlaintext(t, a), mustAgentNostrFixturePlaintext(t, a)}}
	manager := newAgentNostrTestManager(store, private)
	signCalls := 0
	manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
		signCalls++
		return signNostrWithAux(secret, digest, aux)
	}
	digest := bytes.Repeat([]byte{0x3a}, 32)
	if result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); err != nil || len(result.Signature) != 128 {
		t.Fatal("present A/E_A was not usable before the absence control")
	}
	account := AgentNostrAccount(receipt.Service, receipt.Version)
	original := store.items[account]
	delete(store.items, account)
	privateBefore, signBefore := private.unwraps, signCalls
	if _, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); agentNostrFailureCode(err) != AgentNostrCodeNotFound {
		t.Fatal("absent exact standalone generation did not return not_found")
	}
	if _, err := manager.Describe(receipt.Service, receipt.Version); agentNostrFailureCode(err) != AgentNostrCodeNotFound {
		t.Fatal("absent exact describe did not return not_found")
	}
	if rows, err := manager.List(); err != nil || len(rows) != 0 {
		t.Fatal("an empty standalone namespace was not a valid empty list")
	}
	if private.unwraps != privateBefore || signCalls != signBefore || store.adds != 0 || private.wraps != 0 ||
		!bytes.Equal(store.otherRows["legacy/agent-fixture/nostr@1"], neighbors["legacy/agent-fixture/nostr@1"]) ||
		!bytes.Equal(store.otherRows["recovery/agent-fixture/nostr@1"], neighbors["recovery/agent-fixture/nostr@1"]) {
		t.Fatal("absence caused private work, mutation, receipt rewriting, or neighboring-row change")
	}
	store.items[account] = original
	if result, err := manager.Sign(receipt.OwnerMXID, receipt, receipt.Service, receipt.Version, digest); err != nil || len(result.Signature) != 128 || private.unwraps != privateBefore+1 || signCalls != signBefore+1 {
		t.Fatal("restored A/E_A positive control did not sign")
	}
}

// Claim: maximum legitimate service, version, identity, receipt, metadata and
// decoded-blob forms still sign through the full manager path; limit: the fake
// unwrap does not establish a real Secure Enclave blob or native load.
func TestAgentNostrLargestLegitimateEndpointAndBlobSign(t *testing.T) {
	identity := "@" + strings.Repeat("a", 1024-len("@:example.invalid")) + ":example.invalid"
	service := "agent-" + strings.Repeat("a", 34)
	fixture := newAgentNostrSignFixture(t, service, 2147483647, identity, 16384)
	if len(service) != 40 || len(identity) != 1024 || len(fixture.metadata) > 8192 || len(fixture.receiptRaw) > 8192 || len(fixture.envelope) >= 32768 {
		t.Fatal("largest legitimate semantic sibling exceeded its enclosing raw bound")
	}
	t.Logf("largest legitimate fixture sizes: metadata=%d/8192 bytes (service/version fields), receipt=%d/8192 bytes (owner identity 1024), envelope=%d/32768 bytes (decoded blob 16384)",
		len(fixture.metadata), len(fixture.receiptRaw), len(fixture.envelope))
	if _, _, err := ParseAgentNostrRecord(fixture.metadata); err != nil {
		t.Fatal("largest legitimate metadata sibling was not canonical")
	}
	if _, err := ParseAgentNostrEnrollment(fixture.receiptRaw); err != nil {
		t.Fatal("largest legitimate receipt sibling was not canonical")
	}
	envelope, err := ParseAgentNostrEnvelope(fixture.envelope, fixture.record)
	if err != nil || len(mustDecodeAgentNostrBase64(t, envelope.EnclaveBlob)) != 16384 {
		t.Fatal("largest legitimate decoded blob sibling was refused")
	}
	digest := bytes.Repeat([]byte{0x36}, 32)
	result, err := fixture.manager.Sign(identity, fixture.receipt, service, 2147483647, digest)
	public, _ := hex.DecodeString(fixture.record.PublicKey)
	signature, _ := hex.DecodeString(result.Signature)
	if err != nil || len(signature) != 64 || VerifyNostr(public, digest, signature) != nil || fixture.private.unwraps != 1 || fixture.private.wraps != 0 {
		t.Fatal("largest legitimate endpoint/blob full-path signature failed")
	}
}

// Claim: metadata and envelope cap+1 refuse before private release/signing,
// with A usable before and after; limit: exact-cap raw bytes are intentionally
// malformed component probes, not semantically valid records or envelopes.
func TestAgentNostrMetadataAndEnvelopeRawSizeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		sizes []int
	}{
		{name: "metadata", field: "metadata", sizes: []int{8192, 8193}},
		{name: "envelope", field: "envelope", sizes: []int{32768, 32769}},
	} {
		for _, size := range tc.sizes {
			t.Run(fmt.Sprintf("%s-%d", tc.name, size), func(t *testing.T) {
				fixture := newAgentNostrSignFixture(t, "agent-fixture", 1, "@agent-fixture:example.invalid", -1)
				fixture.private.plaintext = [][]byte{bytes.Clone(fixture.plaintext), bytes.Clone(fixture.plaintext)}
				signCalls := 0
				fixture.manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
					signCalls++
					return signNostrWithAux(secret, digest, aux)
				}
				digest := bytes.Repeat([]byte{0x36}, 32)
				if result, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); err != nil || len(result.Signature) != 128 {
					t.Fatal("A did not sign before raw-size boundary probe")
				}
				account := AgentNostrAccount(fixture.receipt.Service, fixture.receipt.Version)
				original := agentNostrFakeItem{metadata: bytes.Clone(fixture.store.items[account].metadata), envelope: bytes.Clone(fixture.store.items[account].envelope)}
				item := fixture.store.items[account]
				if tc.field == "metadata" {
					item.metadata = bytes.Repeat([]byte{'x'}, size)
				} else {
					item.envelope = bytes.Repeat([]byte{'x'}, size)
				}
				fixture.store.items[account] = item
				if _, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord {
					t.Fatal("raw-size boundary did not return corrupt_record")
				}
				if fixture.private.unwraps != 1 || signCalls != 1 || fixture.store.adds != 0 {
					t.Fatal("oversized stored data crossed private release, signing or mutation")
				}
				fixture.store.items[account] = original
				if result, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); err != nil || len(result.Signature) != 128 || fixture.private.unwraps != 2 || signCalls != 2 {
					t.Fatal("A did not sign after raw-size boundary refusal")
				}
			})
		}
	}
}

// Claim: the decoded blob accepts 16,384 bytes and refuses 16,385 before
// private release, with the valid maximum sibling signing on both sides;
// limit: accepted bytes are a software fixture, not a real native SE object.
func TestAgentNostrDecodedBlobSizeBoundary(t *testing.T) {
	identity := "@agent-fixture:example.invalid"
	fixture := newAgentNostrSignFixture(t, "agent-fixture", 1, identity, 16384)
	overLimit := newAgentNostrSignFixture(t, "agent-fixture", 1, identity, 16385)
	fixture.private.plaintext = [][]byte{bytes.Clone(fixture.plaintext), bytes.Clone(fixture.plaintext)}
	digest := bytes.Repeat([]byte{0x36}, 32)
	signCalls := 0
	fixture.manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
		signCalls++
		return signNostrWithAux(secret, digest, aux)
	}
	if result, err := fixture.manager.Sign(identity, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); err != nil || len(result.Signature) != 128 {
		t.Fatal("16,384-byte decoded blob positive control failed")
	}
	account := AgentNostrAccount(fixture.record.Service, fixture.record.Version)
	item := fixture.store.items[account]
	item.envelope = bytes.Clone(overLimit.envelope)
	fixture.store.items[account] = item
	if _, err := fixture.manager.Sign(identity, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord {
		t.Fatal("16,385-byte decoded blob did not return corrupt_record")
	}
	if fixture.private.unwraps != 1 || signCalls != 1 || fixture.store.adds != 0 {
		t.Fatal("decoded blob cap+1 reached private release, signing or mutation")
	}
	item = fixture.store.items[account]
	item.envelope = bytes.Clone(fixture.envelope)
	fixture.store.items[account] = item
	if result, err := fixture.manager.Sign(identity, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, digest); err != nil || len(result.Signature) != 128 || fixture.private.unwraps != 2 || signCalls != 2 {
		t.Fatal("16,384-byte decoded blob positive control failed after refusal")
	}
}

// Claim: a complete authenticated bad_request refusal maps to corrupt_record
// without plaintext or signing, distinct from ambiguous dispatched UNKNOWN;
// limit: the test injects the already-authenticated typed status at the boundary.
func TestAgentNostrAuthenticatedBadRequestIsCorruptRecord(t *testing.T) {
	fixture := newAgentNostrSignFixture(t, "agent-fixture", 1, "@agent-fixture:example.invalid", -1)
	fixture.private.unwrapErr = &AgentNostrPrivateError{Code: "bad_request", Dispatched: true}
	signCalls := 0
	fixture.manager.sign = func(secret, digest []byte, aux [32]byte) ([]byte, error) {
		signCalls++
		return signNostrWithAux(secret, digest, aux)
	}
	result, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, bytes.Repeat([]byte{0x36}, 32))
	if agentNostrFailureCode(err) != AgentNostrCodeCorruptRecord || result.Signature != "" || fixture.private.unwraps != 1 || signCalls != 0 || fixture.store.adds != 0 {
		t.Fatal("authenticated bad_request was confused with UNKNOWN or released plaintext/signature")
	}
}

// Claim: minimum and maximum permitted service/version endpoints carry matching
// canonical metadata and enrollment pins and both reach real Sign; limit: actor
// authorization and hardware key origin remain external/native evidence.
func TestAgentNostrServiceAndVersionFullPathEndpoints(t *testing.T) {
	maxIdentity := "@" + strings.Repeat("a", 1024-len("@:example.invalid")) + ":example.invalid"
	for _, tc := range []struct {
		service  string
		version  int
		identity string
	}{
		{service: "agent-a", version: 1, identity: "@agent-fixture:example.invalid"},
		{service: "agent-" + strings.Repeat("a", 34), version: 2147483647, identity: maxIdentity},
	} {
		t.Run(fmt.Sprintf("service-%d-version-%d", len(tc.service), tc.version), func(t *testing.T) {
			fixture := newAgentNostrSignFixture(t, tc.service, tc.version, tc.identity, -1)
			if len(fixture.metadata) > 8192 || len(fixture.receiptRaw) > 8192 || fixture.record.Service != tc.service || fixture.record.Version != tc.version ||
				fixture.receipt.Service != tc.service || fixture.receipt.Version != tc.version || fixture.receipt.RecordFingerprint != AgentNostrPublicResult(fixture.record, fixture.metadata).RecordFingerprint {
				t.Fatal("endpoint fixture metadata and receipt pins do not match")
			}
			digest := bytes.Repeat([]byte{0x36}, 32)
			result, err := fixture.manager.Sign(tc.identity, fixture.receipt, tc.service, tc.version, digest)
			public, _ := hex.DecodeString(fixture.record.PublicKey)
			signature, _ := hex.DecodeString(result.Signature)
			if err != nil || VerifyNostr(public, digest, signature) != nil || fixture.private.unwraps != 1 {
				t.Fatal("valid service/version endpoint did not produce a verified signature")
			}
		})
	}
}

// Claim: lower- and uppercase hex encodings of a real a..f digest produce the
// same correctly verified signature under equal aux input; limit: CLI parsing
// is separately witnessed at its command boundary.
func TestAgentNostrDigestHexCaseEquivalenceSignsSameMessage(t *testing.T) {
	fixture := newAgentNostrSignFixture(t, "agent-fixture", 1, "@agent-fixture:example.invalid", -1)
	fixture.private.plaintext = [][]byte{bytes.Clone(fixture.plaintext), bytes.Clone(fixture.plaintext)}
	digestText := strings.Repeat("abcdef0123456789", 4)
	lower, err := hex.DecodeString(digestText)
	if err != nil {
		t.Fatal("lowercase digest fixture invalid")
	}
	upper, err := hex.DecodeString(strings.ToUpper(digestText))
	if err != nil || !bytes.Equal(lower, upper) || !strings.ContainsAny(digestText, "abcdef") {
		t.Fatal("uppercase/lowercase digest compatibility control is not discriminating")
	}
	fixture.manager.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64))
	first, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, lower)
	if err != nil {
		t.Fatal("lowercase digest signature failed")
	}
	second, err := fixture.manager.Sign(fixture.receipt.OwnerMXID, fixture.receipt, fixture.receipt.Service, fixture.receipt.Version, upper)
	if err != nil || first.Signature != second.Signature {
		t.Fatal("uppercase digest did not preserve equivalent deterministic signing behavior")
	}
	public, _ := hex.DecodeString(fixture.record.PublicKey)
	signature, _ := hex.DecodeString(first.Signature)
	if VerifyNostr(public, lower, signature) != nil || fixture.private.unwraps != 2 {
		t.Fatal("equivalent digest signature did not verify through two full Sign calls")
	}
}

type agentNostrFakeItem struct{ metadata, envelope []byte }

type agentNostrFakeStore struct {
	items       map[string]agentNostrFakeItem
	otherRows   map[string][]byte
	listCalls   int
	selects     int
	loads       int
	adds        int
	lastAccount string
	addAttempt  bool
	addErr      error
	readbackErr error
	onSelect    func(*agentNostrFakeStore, string)
	onAdd       func(*agentNostrFakeStore, string)
}

func newAgentNostrFakeStore() *agentNostrFakeStore {
	return &agentNostrFakeStore{items: make(map[string]agentNostrFakeItem)}
}

func (s *agentNostrFakeStore) putFixture(t *testing.T, fixture agentNostrFixtureDocument) {
	t.Helper()
	record, _, err := ParseAgentNostrRecord([]byte(fixture.MetadataJSON))
	if err != nil {
		t.Fatal("fixture metadata rejected")
	}
	s.items[AgentNostrAccount(record.Service, record.Version)] = agentNostrFakeItem{metadata: []byte(fixture.MetadataJSON), envelope: []byte(fixture.EnvelopeJSON)}
}

func (s *agentNostrFakeStore) ListAgentNostr() ([]AgentNostrItem, error) {
	s.listCalls++
	rows := make([]AgentNostrItem, 0, len(s.items))
	for account, item := range s.items {
		rows = append(rows, AgentNostrItem{Account: account, Metadata: bytes.Clone(item.metadata)})
	}
	return rows, nil
}

func (s *agentNostrFakeStore) SelectAgentNostr(account string) (AgentNostrSelection, error) {
	s.selects++
	if s.adds > 0 && s.readbackErr != nil {
		return nil, s.readbackErr
	}
	item, ok := s.items[account]
	if !ok {
		return nil, ErrNotFound
	}
	selection := &agentNostrFakeSelection{store: s, account: account, item: item}
	if s.onSelect != nil {
		s.onSelect(s, account)
	}
	return selection, nil
}

func (s *agentNostrFakeStore) AddAgentNostr(account string, metadata, envelope []byte) (bool, error) {
	s.adds++
	s.lastAccount = account
	if s.onAdd != nil {
		s.onAdd(s, account)
	}
	if s.addErr != nil {
		return s.addAttempt, s.addErr
	}
	if _, exists := s.items[account]; exists {
		return true, &AgentNostrFailure{Code: AgentNostrCodeDuplicate}
	}
	s.items[account] = agentNostrFakeItem{metadata: bytes.Clone(metadata), envelope: bytes.Clone(envelope)}
	return true, nil
}

type agentNostrFakeSelection struct {
	store   *agentNostrFakeStore
	account string
	item    agentNostrFakeItem
}

func (s *agentNostrFakeSelection) Metadata() []byte { return bytes.Clone(s.item.metadata) }
func (s *agentNostrFakeSelection) LoadEnvelope() ([]byte, []byte, error) {
	s.store.loads++
	current, ok := s.store.items[s.account]
	if !ok {
		return nil, nil, ErrNotFound
	}
	return bytes.Clone(current.metadata), bytes.Clone(current.envelope), nil
}
func (*agentNostrFakeSelection) Close() {}

type agentNostrFakePrivate struct {
	wrapScalar   byte
	plaintext    [][]byte
	lastEnvelope AgentNostrEnvelope
	wraps        int
	unwraps      int
	signs        int
	wrapErr      error
	unwrapErr    error
}

func (p *agentNostrFakePrivate) CreateWrap() (AgentNostrWrap, error) {
	p.wraps++
	if p.wrapErr != nil {
		return AgentNostrWrap{}, p.wrapErr
	}
	if p.wrapScalar == 0 {
		p.wrapScalar = 1
	}
	scalar := p.wrapScalar
	p.wrapScalar++
	point, err := testP256Point(scalar)
	if err != nil {
		return AgentNostrWrap{}, err
	}
	return AgentNostrWrap{Blob: []byte("synthetic-public-blob"), Point: point, Fingerprint: sha256String(point), Policy: "none", SilentRefused: false}, nil
}

func (p *agentNostrFakePrivate) UnwrapAgentNostr(envelope AgentNostrEnvelope) ([]byte, error) {
	p.unwraps++
	p.lastEnvelope = envelope
	if p.unwrapErr != nil {
		return nil, p.unwrapErr
	}
	if len(p.plaintext) == 0 {
		return nil, errors.New("missing test plaintext")
	}
	plain := bytes.Clone(p.plaintext[0])
	p.plaintext = p.plaintext[1:]
	return plain, nil
}

type agentNostrTestLock struct{ locks int }

func (l *agentNostrTestLock) Lock() (func(), error) {
	l.locks++
	return func() {}, nil
}

func newAgentNostrTestManager(store AgentNostrStore, helper AgentNostrPrivate) *AgentNostrManager {
	m := NewAgentNostrManager(store, helper, &agentNostrTestLock{})
	randomBytes := append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 31)...)
	randomBytes = append(randomBytes, 3)
	randomBytes = append(randomBytes, bytes.Repeat([]byte{0x5a}, 512)...)
	m.random = bytes.NewReader(randomBytes)
	m.now = func() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC) }
	return m
}

func agentNostrFailureCode(err error) string {
	var failure *AgentNostrFailure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return ""
}

func mustAgentNostrFixturePlaintext(t *testing.T, fixture agentNostrFixtureDocument) []byte {
	t.Helper()
	value, err := hex.DecodeString(fixture.PlaintextHex)
	if err != nil || len(value) != 69 {
		t.Fatal("fixture plaintext invalid")
	}
	return value
}

func mustDecodeAgentNostrBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatal("fixture base64 invalid")
	}
	return decoded
}

func mustHexDigest(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal("fixture digest invalid")
	}
	return decoded
}

func testP256Point(scalar byte) ([]byte, error) {
	secret := make([]byte, 32)
	secret[31] = scalar
	key, err := ecdh.P256().NewPrivateKey(secret)
	clear(secret)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func sha256String(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func openAgentNostrForTest(t *testing.T, envelope AgentNostrEnvelope) ([]byte, error) {
	t.Helper()
	point, err := base64.StdEncoding.Strict().DecodeString(envelope.Point)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) != 150 {
		return nil, errors.New("invalid test ciphertext")
	}
	wrapSecret := make([]byte, 32)
	wrapSecret[31] = 1
	wrap, err := ecdh.P256().NewPrivateKey(wrapSecret)
	clear(wrapSecret)
	if err != nil || !bytes.Equal(wrap.PublicKey().Bytes(), point) {
		return nil, errors.New("test wrapper point mismatch")
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ciphertext[:65])
	if err != nil {
		return nil, err
	}
	shared, err := wrap.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	transcript := append(bytes.Clone(shared), 0, 0, 0, 1)
	transcript = append(transcript, ciphertext[:65]...)
	derived := sha256.Sum256(transcript)
	defer clear(transcript)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, derived[16:], ciphertext[65:], nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
