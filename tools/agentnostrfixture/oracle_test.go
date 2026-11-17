package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Claim: every official row remains present in the pinned source; limit: the
// existing keyvault test separately exercises the production BIP340 primitives.
func TestAllNineteenOfficialBIP340RowsRemain(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(root, vectorPath))
	if err != nil || sha256Hex(raw) != vectorSHA256 {
		t.Fatal("pinned BIP340 CSV could not be read")
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil || len(rows) != 20 {
		t.Fatalf("expected header and 19 vectors, got %d rows", len(rows))
	}
	var accepted, rejected, variableMessage, signingControls int
	for i, row := range rows[1:] {
		if len(row) != 8 || row[0] != strconv.Itoa(i) {
			t.Fatalf("BIP340 row %d is missing or malformed", i)
		}
		message, err := hex.DecodeString(row[4])
		if err != nil {
			t.Fatalf("BIP340 row %d message is malformed", i)
		}
		if len(message) != 32 {
			variableMessage++
			continue
		}
		if row[1] != "" {
			signingControls++
		}
		if row[6] == "TRUE" {
			accepted++
		} else if row[6] == "FALSE" {
			rejected++
		} else {
			t.Fatalf("BIP340 row %d has no published verdict", i)
		}
	}
	if accepted != 5 || rejected != 10 || variableMessage != 4 || signingControls != 4 {
		t.Fatalf("coverage counts changed: accepted=%d rejected=%d variable=%d sign=%d", accepted, rejected, variableMessage, signingControls)
	}
}

// Claim: this independent NIP-19 encoder retains the published row-0 npub;
// limit: one public encoding anchor does not prove all possible inputs.
func TestNIP19PublishedPublicEncoding(t *testing.T) {
	public, err := hex.DecodeString(knownNIP19PublicKey)
	if err != nil {
		t.Fatal("published public key fixture is malformed")
	}
	got, err := encodeNPub(public)
	if err != nil || got != knownNIP19PublicEncoding {
		t.Fatalf("published NIP-19 result changed: got %q", got)
	}
	if got, err := encodeNPub(make([]byte, 31)); err == nil || got != "" {
		t.Fatal("wrong-length public key was encoded")
	}
}

// Claim: supplied public metadata/receipt bytes retain their exact pinned
// hashes and public-only shape; limit: this fixture contains no ciphertext or
// native custody evidence.
func TestPublicEncodingFixtureIsFrozen(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(root, fixtureDirectory, publicEncodingName))
	if err != nil || len(raw) != publicEncodingBytes || sha256Hex(raw) != publicEncodingSHA256 {
		t.Fatal("public encoding fixture bytes or SHA-256 changed")
	}
	if err := verifyPublicEncoding(raw); err != nil {
		t.Fatal("public encoding fixture validation failed")
	}
}

// Claim: A and B are complete canonical same-selector examples with valid
// 150/69 AEAD bindings and independent official vector inputs; limit: public
// software fixtures do not prove Secure Enclave or Keychain behavior.
func TestFixtureAPositiveAndValidReplacementB(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	rows, _, err := readVectors(filepath.Join(root, vectorPath))
	if err != nil {
		t.Fatal("pinned BIP340 vectors unavailable")
	}
	files, err := generateFiles(root)
	if err != nil {
		t.Fatal("public fixture generation failed")
	}
	var a, b fixtureDocument
	if json.Unmarshal(files["fixture-a.json"], &a) != nil || json.Unmarshal(files["fixture-b.json"], &b) != nil {
		t.Fatal("fixture document is invalid")
	}
	checkPositiveFixture(t, a, rows[0], 1)
	checkPositiveFixture(t, b, rows[1], 3)
	metaA := decodeDocumentMetadata(t, a)
	metaB := decodeDocumentMetadata(t, b)
	if metaA.Service != metaB.Service || metaA.Purpose != metaB.Purpose || metaA.Version != metaB.Version {
		t.Fatal("replacement fixture does not use the same selector")
	}
	if metaA.PublicKey == metaB.PublicKey || metaA.WrappingPoint == metaB.WrappingPoint {
		t.Fatal("replacement fixture does not carry a distinct key and wrapping point")
	}
	if a.EnrollmentJSON == b.EnrollmentJSON || a.RecordFingerprint == b.RecordFingerprint {
		t.Fatal("replacement fixture did not receive its own enrollment and record pins")
	}
}

// Claim: each deep mutant has a valid AEAD tag and satisfies every earlier
// layer before its named predicate fails; limit: the product guards are tested
// by the later integrated implementation, not by this oracle alone.
func TestDeepMutantsAreValidAEADAndReachTheirNamedPredicate(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	rows, _, err := readVectors(filepath.Join(root, vectorPath))
	if err != nil {
		t.Fatal("pinned BIP340 vectors unavailable")
	}
	files, err := generateFiles(root)
	if err != nil {
		t.Fatal("public fixture generation failed")
	}
	var a fixtureDocument
	if json.Unmarshal(files["fixture-a.json"], &a) != nil {
		t.Fatal("fixture A is invalid")
	}
	metadataA := decodeDocumentMetadata(t, a)
	metadataBytesA := []byte(a.MetadataJSON)
	metaHashA := sha256.Sum256(metadataBytesA)
	order, ok := new(big.Int).SetString(secp256k1OrderHex, 16)
	if !ok {
		t.Fatal("secp256k1 order constant is invalid")
	}
	mutants := []struct {
		file            string
		failure         string
		expectedDomain  bool
		expectedBinding bool
		expectedScalar  bool
		vectorIndex     int
	}{
		{"mutant-domain-kvax1.json", "domain", false, true, true, 0},
		{"mutant-binding.json", "metadata-binding", true, false, true, 0},
		{"mutant-scalar-zero.json", "scalar-range", true, true, false, 0},
		{"mutant-scalar-order.json", "scalar-range", true, true, false, 0},
		{"mutant-scalar-n-plus-3.json", "scalar-range-before-reduction", true, true, false, 0},
		{"mutant-scalar-key-mismatch.json", "public-key-match", true, true, true, 1},
	}
	for _, tc := range mutants {
		t.Run(tc.failure+"/"+tc.file, func(t *testing.T) {
			var mutant fixtureDocument
			if json.Unmarshal(files[tc.file], &mutant) != nil || mutant.ExpectedFirstFailure != tc.failure || mutant.SourceVectorIndex != tc.vectorIndex {
				t.Fatal("mutant manifest label changed")
			}
			if mutant.MetadataJSON != a.MetadataJSON || mutant.EnrollmentJSON != a.EnrollmentJSON {
				t.Fatal("mutant changed A's enrolled metadata or receipt")
			}
			mutantMetadata := decodeDocumentMetadata(t, mutant)
			mutantReceipt := decodeDocumentReceipt(t, mutant)
			if mutant.RecordFingerprint != sha256Hex([]byte(mutant.MetadataJSON)) || mutantReceipt.PublicKey != mutantMetadata.PublicKey || mutantReceipt.RecordFingerprint != mutant.RecordFingerprint {
				t.Fatal("mutant does not preserve A's valid metadata and receipt pins")
			}
			plain, ciphertext := openDocument(t, mutant, 1)
			decodedPlain, err := hex.DecodeString(mutant.PlaintextHex)
			if err != nil || !bytes.Equal(plain, decodedPlain) || len(plain) != 69 || len(ciphertext) != 150 {
				t.Fatal("mutant bytes do not match the valid-AEAD golden")
			}
			actualDomain := bytes.Equal(plain[:5], []byte("KVAN1"))
			actualBinding := bytes.Equal(plain[5:37], metaHashA[:])
			secret := new(big.Int).SetBytes(plain[37:])
			actualScalar := secret.Sign() > 0 && secret.Cmp(order) < 0
			if actualDomain != tc.expectedDomain || actualBinding != tc.expectedBinding || actualScalar != tc.expectedScalar {
				t.Fatal("mutant does not fail at its intended first predicate")
			}
			if (tc.file == "mutant-domain-kvax1.json" || tc.file == "mutant-binding.json") && !bytes.Equal(plain[37:], rows[0].secret) {
				t.Fatal("mutant A scalar is not the published row-0 scalar")
			}
			if tc.vectorIndex == 1 {
				if !bytes.Equal(plain[37:], rows[1].secret) || hex.EncodeToString(rows[1].public) == metadataA.PublicKey {
					t.Fatal("key-mismatch mutant is not a different valid published vector")
				}
			}
			if tc.file == "mutant-scalar-zero.json" && !bytes.Equal(plain[37:], make([]byte, 32)) {
				t.Fatal("zero scalar control changed")
			}
			if tc.file == "mutant-scalar-order.json" && !bytes.Equal(plain[37:], order.FillBytes(make([]byte, 32))) {
				t.Fatal("group-order scalar control changed")
			}
			if tc.file == "mutant-scalar-n-plus-3.json" {
				want := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(3))
				if !bytes.Equal(plain[37:], want.FillBytes(make([]byte, 32))) || new(big.Int).Mod(secret, order).Cmp(big.NewInt(3)) != 0 {
					t.Fatal("nonzero scalar-overflow witness changed")
				}
			}
			positivePlain, positiveCiphertext := openDocument(t, a, 1)
			if !bytes.Equal(positivePlain, mustHex(t, a.PlaintextHex)) || len(positiveCiphertext) != 150 {
				t.Fatal("valid A control did not remain usable after the mutant")
			}
		})
	}
	if _, err := hex.DecodeString(a.RecordFingerprint); err != nil || a.RecordFingerprint != sha256Hex(metadataBytesA) {
		t.Fatal("A's valid control no longer follows its mutant siblings")
	}
}

// Claim: generated bytes, hashes, source pins, and generator identity exactly
// match the committed goldens; limit: this verifies deterministic public test
// material, not product persistence or hardware operations.
func TestGeneratedFilesMatchCheckedInGoldens(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	want, err := generateFiles(root)
	if err != nil {
		t.Fatal("fixture oracle refused its pinned inputs")
	}
	directory := filepath.Join(root, fixtureDirectory)
	for name, expected := range want {
		actual, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("golden %s differs from the independent Go generator", name)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("fixture directory unavailable")
	}
	for _, entry := range entries {
		if entry.Name() == "README.md" {
			continue
		}
		if _, ok := want[entry.Name()]; !ok {
			t.Fatalf("unexpected generated fixture file %s", entry.Name())
		}
	}
}

// Claim: the manifest pins every positive fixture and deep mutant at file and
// subobject byte/hash level; limit: it does not attest to a native wrapping key.
func TestManifestCoversEveryFixtureAndSource(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	files, err := generateFiles(root)
	if err != nil {
		t.Fatal("fixture generation failed")
	}
	var got manifest
	if json.Unmarshal(files["manifest.json"], &got) != nil {
		t.Fatal("fixture manifest is invalid")
	}
	if got.Schema != "agent-nostr-test-fixtures/1" || got.Generator != "tools/agentnostrfixture" || got.GeneratorVersion != "1" || got.GeneratorSourceSHA256 == "" || got.RepositoryBase != repositoryBase || got.BIP340Repository != vectorRepository || got.BIP340Revision != vectorRevision || got.BIP340Path != vectorSourcePath || got.BIP340CSVSHA256 != vectorSHA256 || got.PublicEncodingFixture != publicEncodingName || got.PublicEncodingFixtureSHA != publicEncodingSHA256 {
		t.Fatal("fixture manifest provenance changed")
	}
	if len(got.Artifacts) != 9 {
		t.Fatalf("expected nine manifest artifacts, got %d", len(got.Artifacts))
	}
	seen := make(map[string]bool, len(got.Artifacts))
	for _, item := range got.Artifacts {
		if seen[item.File] || len(item.SHA256) != 64 || item.Bytes <= 0 {
			t.Fatalf("invalid or duplicate manifest entry %s", item.File)
		}
		seen[item.File] = true
		if item.File != publicEncodingName && (item.MetadataBytes == 0 || len(item.MetadataSHA256) != 64 || item.ReceiptBytes == 0 || len(item.ReceiptSHA256) != 64 || item.EnvelopeBytes == 0 || len(item.EnvelopeSHA256) != 64 || item.PlaintextBytes != 69 || len(item.PlaintextSHA256) != 64 || item.CiphertextBytes != 150 || len(item.CiphertextSHA256) != 64) {
			t.Fatalf("fixture hashes or byte counts are incomplete for %s", item.File)
		}
		if !bytes.Equal([]byte(item.SHA256), []byte(sha256Hex(files[item.File]))) || item.Bytes != len(files[item.File]) {
			t.Fatalf("manifest file pin does not match %s", item.File)
		}
	}
	for _, name := range []string{"fixture-a.json", "fixture-b.json", "mutant-domain-kvax1.json", "mutant-binding.json", "mutant-scalar-zero.json", "mutant-scalar-order.json", "mutant-scalar-n-plus-3.json", "mutant-scalar-key-mismatch.json", publicEncodingName} {
		if !seen[name] {
			t.Fatalf("manifest omitted %s", name)
		}
	}
}

func checkPositiveFixture(t *testing.T, doc fixtureDocument, source vector, wrappingScalar byte) {
	t.Helper()
	meta := decodeDocumentMetadata(t, doc)
	if meta.Schema != metadataSchema || meta.Namespace != agentNamespace || meta.Service != serviceName || meta.Purpose != "nostr" || meta.Version != 1 || meta.Algorithm != "secp256k1-bip340" || meta.Storage != "enclave-wrapped-keychain" || meta.Presence || meta.PrivateExport {
		t.Fatal("positive fixture metadata differs from the agreed public shape")
	}
	if meta.PublicKey != hex.EncodeToString(source.public) || doc.SourceVectorIndex != source.index {
		t.Fatal("positive fixture is not grounded in its published BIP340 row")
	}
	if doc.RecordFingerprint != sha256Hex([]byte(doc.MetadataJSON)) {
		t.Fatal("positive fixture metadata pin is invalid")
	}
	receipt := decodeDocumentReceipt(t, doc)
	if receipt.OwnerMXID != fixtureOwner || receipt.Service != serviceName || receipt.Purpose != "nostr" || receipt.Version != 1 || receipt.PublicKey != meta.PublicKey || receipt.RecordFingerprint != doc.RecordFingerprint {
		t.Fatal("positive fixture enrollment does not bind the metadata")
	}
	keyHash := sha256.Sum256(source.public)
	if receipt.KeySHA256 != hex.EncodeToString(keyHash[:]) || doc.KeySHA256 != receipt.KeySHA256 {
		t.Fatal("positive fixture public-key hash is invalid")
	}
	plain, ciphertext := openDocument(t, doc, wrappingScalar)
	wantPlain, err := hex.DecodeString(doc.PlaintextHex)
	if err != nil || !bytes.Equal(plain, wantPlain) || len(plain) != 69 || len(ciphertext) != 150 {
		t.Fatal("positive fixture has unexpected plaintext/ciphertext bytes")
	}
	metaHash := sha256.Sum256([]byte(doc.MetadataJSON))
	if !bytes.Equal(plain[:5], []byte("KVAN1")) || !bytes.Equal(plain[5:37], metaHash[:]) || !bytes.Equal(plain[37:], source.secret) {
		t.Fatal("positive fixture has invalid domain, binding, or scalar")
	}
}

func openDocument(t *testing.T, doc fixtureDocument, wrappingScalar byte) ([]byte, []byte) {
	t.Helper()
	var value envelope
	if json.Unmarshal([]byte(doc.EnvelopeJSON), &value) != nil {
		t.Fatal("fixture envelope JSON is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, []byte(doc.EnvelopeJSON)) {
		t.Fatal("fixture envelope is not canonical")
	}
	if value.Schema != envelopeSchema || value.Algorithm != envelopeAlgorithm {
		t.Fatal("fixture envelope header changed")
	}
	var record metadata
	if json.Unmarshal([]byte(doc.MetadataJSON), &record) != nil || value.Point != record.WrappingPoint || value.Fingerprint != record.WrappingFingerprint {
		t.Fatal("fixture envelope does not match its metadata wrapping pin")
	}
	point, err := base64.StdEncoding.Strict().DecodeString(value.Point)
	if err != nil || base64.StdEncoding.EncodeToString(point) != value.Point || len(point) != 65 || sha256Hex(point) != value.Fingerprint {
		t.Fatal("fixture wrapping point or fingerprint is invalid")
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(value.EnclaveBlob)
	if err != nil || len(blob) == 0 || base64.StdEncoding.EncodeToString(blob) != value.EnclaveBlob {
		t.Fatal("fixture blob encoding is invalid")
	}
	plain, ciphertext, err := openFixtureIndependently([]byte(doc.EnvelopeJSON), wrappingScalar)
	if err != nil {
		t.Fatal("independent fixture decoder rejected AEAD", err)
	}
	return plain, ciphertext
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal("fixture hex is invalid")
	}
	return decoded
}

func decodeDocumentMetadata(t *testing.T, doc fixtureDocument) metadata {
	t.Helper()
	var value metadata
	if json.Unmarshal([]byte(doc.MetadataJSON), &value) != nil {
		t.Fatal("fixture metadata JSON is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, []byte(doc.MetadataJSON)) {
		t.Fatal("fixture metadata is not canonical")
	}
	return value
}

func decodeDocumentReceipt(t *testing.T, doc fixtureDocument) enrollment {
	t.Helper()
	var value enrollment
	if json.Unmarshal([]byte(doc.EnrollmentJSON), &value) != nil {
		t.Fatal("fixture enrollment JSON is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, []byte(doc.EnrollmentJSON)) {
		t.Fatal("fixture enrollment is not canonical")
	}
	return value
}
