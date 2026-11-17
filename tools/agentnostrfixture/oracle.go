package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	fixtureDirectory          = "internal/keyvault/testdata/agent-nostr"
	fixtureOwnerPath          = "tools/agentnostrfixture/testdata/enrollment-owner-mxid.txt"
	fixtureOwnerSHA256        = "e6a00086aa8cadc937a20effc8307c26e18f7e888e85652e67e0a2209337284d"
	fixtureServicePath        = "tools/agentnostrfixture/testdata/enrollment-service.txt"
	fixtureServiceSHA256      = "87d922592ed9b53d1ffea905b76ed10bee80e36be91570f8676402201e76993d"
	vectorPath                = "internal/keyvault/testdata/nostr/bip340.csv"
	vectorSHA256              = "01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb"
	vectorRepository          = "bitcoin/bips"
	vectorRevision            = "200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb"
	vectorSourcePath          = "bip-0340/test-vectors.csv"
	publicEncodingName        = "public-encoding.json"
	publicEncodingSHA256      = "05fdeb31bdbd8c4ee5688f7ea3889aad96b45441fb0a82ecf11d03ba74930cf2"
	publicEncodingBytes       = 1806
	repositoryBase            = "1c16bd56bae850a7f4837e55e4a42059cd829912"
	metadataSchema            = "agent-nostr-key/1"
	enrollmentSchema          = "agent-nostr-enrollment/1"
	envelopeSchema            = "keyvault-agent-nostr-envelope/1"
	agentNamespace            = "works.relux.mac-keyvault.agent-nostr.v1"
	envelopeAlgorithm         = "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM"
	createdAt                 = "2026-11-17T00:00:00Z"
	secp256k1OrderHex         = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	knownNIP19PublicKey       = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
	knownNIP19PublicEncoding  = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
	knownP256GeneratorEncoded = "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU="
)

type vector struct {
	index  int
	secret []byte
	public []byte
}

type metadata struct {
	Schema              string `json:"schema"`
	Namespace           string `json:"namespace"`
	Service             string `json:"service"`
	Purpose             string `json:"purpose"`
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
	Storage             string `json:"storage"`
	Presence            bool   `json:"presence"`
	PrivateExport       bool   `json:"private_export"`
	Created             string `json:"created"`
	PublicKey           string `json:"public_key"`
	NPub                string `json:"npub"`
	WrappingPoint       string `json:"wrapping_point"`
	WrappingFingerprint string `json:"wrapping_fingerprint"`
}

type enrollment struct {
	Schema            string `json:"schema"`
	OwnerMXID         string `json:"owner_mxid"`
	Service           string `json:"service"`
	Purpose           string `json:"purpose"`
	Version           int    `json:"version"`
	PublicKey         string `json:"public_key"`
	KeySHA256         string `json:"key_sha256"`
	RecordFingerprint string `json:"record_fingerprint"`
}

type envelope struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	EnclaveBlob string `json:"enclave_blob"`
	Point       string `json:"point"`
	Fingerprint string `json:"fingerprint"`
	Ciphertext  string `json:"ciphertext"`
}

type fixtureDocument struct {
	Schema               string   `json:"schema"`
	Name                 string   `json:"name"`
	SourceVectorIndex    int      `json:"source_vector_index"`
	Controls             []string `json:"controls"`
	ExpectedFirstFailure string   `json:"expected_first_failure,omitempty"`
	MetadataJSON         string   `json:"metadata_json"`
	RecordFingerprint    string   `json:"record_fingerprint"`
	KeySHA256            string   `json:"key_sha256"`
	EnrollmentJSON       string   `json:"enrollment_json"`
	EnvelopeJSON         string   `json:"envelope_json"`
	PlaintextHex         string   `json:"plaintext_hex"`
}

type generatedFixture struct {
	fileName             string
	fileBytes            []byte
	metadata             []byte
	receipt              []byte
	envelope             []byte
	plaintext            []byte
	ciphertext           []byte
	controls             []string
	expectedFirstFailure string
	vectorIndex          int
	wrappingScalar       byte
	ephemeralScalar      byte
}

type artifactManifest struct {
	Name                 string   `json:"name"`
	File                 string   `json:"file"`
	Bytes                int      `json:"bytes"`
	SHA256               string   `json:"sha256"`
	MetadataBytes        int      `json:"metadata_bytes"`
	MetadataSHA256       string   `json:"metadata_sha256"`
	ReceiptBytes         int      `json:"receipt_bytes"`
	ReceiptSHA256        string   `json:"receipt_sha256"`
	EnvelopeBytes        int      `json:"envelope_bytes"`
	EnvelopeSHA256       string   `json:"envelope_sha256"`
	PlaintextBytes       int      `json:"plaintext_bytes"`
	PlaintextSHA256      string   `json:"plaintext_sha256"`
	CiphertextBytes      int      `json:"ciphertext_bytes"`
	CiphertextSHA256     string   `json:"ciphertext_sha256"`
	Controls             []string `json:"controls"`
	ExpectedFirstFailure string   `json:"expected_first_failure,omitempty"`
}

type manifest struct {
	Schema                   string             `json:"schema"`
	Generator                string             `json:"generator"`
	GeneratorVersion         string             `json:"generator_version"`
	GeneratorSourceSHA256    string             `json:"generator_source_sha256"`
	RepositoryBase           string             `json:"repository_base"`
	BIP340Repository         string             `json:"bip340_repository"`
	BIP340Revision           string             `json:"bip340_revision"`
	BIP340Path               string             `json:"bip340_path"`
	BIP340CSVSHA256          string             `json:"bip340_csv_sha256"`
	PublicEncodingFixture    string             `json:"public_encoding_fixture"`
	PublicEncodingFixtureSHA string             `json:"public_encoding_fixture_sha256"`
	Artifacts                []artifactManifest `json:"artifacts"`
}

func findRepositoryRoot() (string, error) {
	starts := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if _, source, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(source))
	}
	for _, start := range starts {
		for dir := filepath.Clean(start); ; dir = filepath.Dir(dir) {
			candidate := filepath.Join(dir, vectorPath)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return "", errors.New("repository root not found")
}

func generateFiles(root string) (map[string][]byte, error) {
	rows, sourceHash, err := readVectors(filepath.Join(root, vectorPath))
	if err != nil {
		return nil, err
	}
	ownerMXID, err := readFixtureOwner(root)
	if err != nil {
		return nil, err
	}
	service, err := readFixtureService(root)
	if err != nil {
		return nil, err
	}
	publicPath := filepath.Join(root, fixtureDirectory, publicEncodingName)
	publicEncoding, err := os.ReadFile(publicPath)
	if err != nil || len(publicEncoding) != publicEncodingBytes || sha256Hex(publicEncoding) != publicEncodingSHA256 {
		return nil, errors.New("public encoding input does not match its pin")
	}
	if err := verifyPublicEncoding(publicEncoding); err != nil {
		return nil, err
	}

	a, err := createPositive("fixture-a.json", "A", rows[0], 1, 2, createdAt, ownerMXID, service)
	if err != nil {
		return nil, err
	}
	b, err := createPositive("fixture-b.json", "B", rows[1], 3, 4, "2026-11-17T00:00:01Z", ownerMXID, service)
	if err != nil {
		return nil, err
	}
	mutants, err := createMutants(a, rows[1])
	if err != nil {
		return nil, err
	}

	fixtures := append([]generatedFixture{a, b}, mutants...)
	files := make(map[string][]byte, len(fixtures)+2)
	files[publicEncodingName] = bytes.Clone(publicEncoding)
	artifacts := make([]artifactManifest, 0, len(fixtures)+1)
	for _, f := range fixtures {
		files[f.fileName] = bytes.Clone(f.fileBytes)
		artifacts = append(artifacts, manifestFor(f))
	}
	artifacts = append(artifacts, artifactManifest{
		Name:           "public-encoding",
		File:           publicEncodingName,
		Bytes:          len(publicEncoding),
		SHA256:         sha256Hex(publicEncoding),
		MetadataBytes:  632,
		MetadataSHA256: "2c4640b7c98308e19a0c4168d58fb532778c8f3b28093db666f4b9c6203970ae",
		ReceiptBytes:   387,
		ReceiptSHA256:  "e785305b862ababd0c94fee6c56769158759d66656b6675f7fa87e83d7a0864d",
		Controls:       []string{"public-encoding-byte-and-hash-baseline"},
	})
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].File < artifacts[j].File })
	toolHash, err := generatorSourceHash(root)
	if err != nil {
		return nil, err
	}
	m := manifest{
		Schema:                   "agent-nostr-test-fixtures/1",
		Generator:                "tools/agentnostrfixture",
		GeneratorVersion:         "1",
		GeneratorSourceSHA256:    toolHash,
		RepositoryBase:           repositoryBase,
		BIP340Repository:         vectorRepository,
		BIP340Revision:           vectorRevision,
		BIP340Path:               vectorSourcePath,
		BIP340CSVSHA256:          sourceHash,
		PublicEncodingFixture:    publicEncodingName,
		PublicEncodingFixtureSHA: publicEncodingSHA256,
		Artifacts:                artifacts,
	}
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	files["manifest.json"] = append(manifestBytes, '\n')
	return files, nil
}

func readVectors(path string) ([]vector, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil || sha256Hex(raw) != vectorSHA256 {
		return nil, "", errors.New("BIP340 vector source does not match its pin")
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil || len(rows) != 20 || len(rows[0]) != 8 {
		return nil, "", errors.New("BIP340 vector row count is invalid")
	}
	if rows[0][0] != "index" || rows[0][1] != "secret key" || rows[0][2] != "public key" {
		return nil, "", errors.New("BIP340 vector header is invalid")
	}
	selected := make([]vector, 2)
	for i := 0; i < 2; i++ {
		row := rows[i+1]
		if len(row) != 8 || row[0] != fmt.Sprint(i) || row[6] != "TRUE" {
			return nil, "", errors.New("required public BIP340 vector is invalid")
		}
		secret, errSecret := decodeHex32(row[1])
		public, errPublic := decodeHex32(row[2])
		if errSecret != nil || errPublic != nil {
			return nil, "", errors.New("required public BIP340 vector encoding is invalid")
		}
		selected[i] = vector{index: i, secret: secret, public: public}
	}
	return selected, sha256Hex(raw), nil
}

func readFixtureOwner(root string) (string, error) {
	return readPinnedFixtureInput(root, fixtureOwnerPath, fixtureOwnerSHA256, "enrollment owner")
}

func readFixtureService(root string) (string, error) {
	return readPinnedFixtureInput(root, fixtureServicePath, fixtureServiceSHA256, "enrollment service")
}

func readPinnedFixtureInput(root, path, expectedSHA256, label string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, path))
	if err != nil || sha256Hex(raw) != expectedSHA256 {
		return "", fmt.Errorf("fixture %s input does not match its pin", label)
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("fixture %s input is malformed", label)
	}
	return value, nil
}

func createPositive(fileName, name string, v vector, wrappingScalar, ephemeralScalar byte, created, ownerMXID, service string) (generatedFixture, error) {
	wrap, err := p256Private(wrappingScalar)
	if err != nil {
		return generatedFixture{}, err
	}
	wrapPoint := wrap.PublicKey().Bytes()
	public := hex.EncodeToString(v.public)
	publicNpub, err := encodeNPub(v.public)
	if err != nil {
		return generatedFixture{}, err
	}
	metadataValue := metadata{
		Schema:              metadataSchema,
		Namespace:           agentNamespace,
		Service:             service,
		Purpose:             "nostr",
		Version:             1,
		Algorithm:           "secp256k1-bip340",
		Storage:             "enclave-wrapped-keychain",
		Presence:            false,
		PrivateExport:       false,
		Created:             created,
		PublicKey:           public,
		NPub:                publicNpub,
		WrappingPoint:       base64.StdEncoding.EncodeToString(wrapPoint),
		WrappingFingerprint: sha256Hex(wrapPoint),
	}
	metadataBytes, err := json.Marshal(metadataValue)
	if err != nil {
		return generatedFixture{}, err
	}
	keyHash := sha256.Sum256(v.public)
	metaHash := sha256.Sum256(metadataBytes)
	receiptValue := enrollment{
		Schema:            enrollmentSchema,
		OwnerMXID:         ownerMXID,
		Service:           service,
		Purpose:           "nostr",
		Version:           1,
		PublicKey:         public,
		KeySHA256:         hex.EncodeToString(keyHash[:]),
		RecordFingerprint: hex.EncodeToString(metaHash[:]),
	}
	receiptBytes, err := json.Marshal(receiptValue)
	if err != nil {
		return generatedFixture{}, err
	}
	plaintext := makePlaintext([]byte("KVAN1"), metaHash[:], v.secret)
	blob := []byte("public-fixture-blob-" + name)
	envelopeBytes, ciphertext, err := sealFixture(metadataBytes, blob, wrapPoint, wrappingScalar, ephemeralScalar, plaintext)
	if err != nil {
		return generatedFixture{}, err
	}
	return freezeFixture(fileName, name, v.index, []string{"positive-full-path", "valid-aead", "valid-domain", "valid-binding", "valid-scalar", "record-public-key-match"}, "", metadataBytes, receiptBytes, envelopeBytes, plaintext, ciphertext, wrappingScalar, ephemeralScalar)
}

func createMutants(a generatedFixture, other vector) ([]generatedFixture, error) {
	metaHash := sha256.Sum256(a.metadata)
	basePlain := makePlaintext([]byte("KVAN1"), metaHash[:], decodePlaintextScalar(a.plaintext))
	mutations := []struct {
		file      string
		name      string
		controls  []string
		failure   string
		vector    int
		plaintext []byte
	}{
		{file: "mutant-domain-kvax1.json", name: "domain-kvax1", controls: []string{"C09", "C10"}, failure: "domain", vector: 0, plaintext: mutateDomain(basePlain)},
		{file: "mutant-binding.json", name: "binding-mismatch", controls: []string{"C11"}, failure: "metadata-binding", vector: 0, plaintext: mutateBinding(basePlain)},
		{file: "mutant-scalar-zero.json", name: "scalar-zero", controls: []string{"C12-scalar-zero"}, failure: "scalar-range", vector: 0, plaintext: mutateScalar(basePlain, make([]byte, 32))},
		{file: "mutant-scalar-order.json", name: "scalar-order", controls: []string{"C12-scalar-order"}, failure: "scalar-range", vector: 0, plaintext: mutateScalar(basePlain, secpOrderBytes())},
		{file: "mutant-scalar-n-plus-3.json", name: "scalar-n-plus-3", controls: []string{"N2-C12-overflow"}, failure: "scalar-range-before-reduction", vector: 0, plaintext: mutateScalar(basePlain, scalarOrderPlusThree())},
		{file: "mutant-scalar-key-mismatch.json", name: "scalar-key-mismatch", controls: []string{"C13"}, failure: "public-key-match", vector: 1, plaintext: mutateScalar(basePlain, other.secret)},
	}
	result := make([]generatedFixture, 0, len(mutations))
	for _, mutation := range mutations {
		envelopeBytes, ciphertext, err := sealFixture(a.metadata, []byte("public-fixture-blob-A"), mustP256Point(1), 1, 2, mutation.plaintext)
		if err != nil {
			return nil, err
		}
		f, err := freezeFixture(mutation.file, mutation.name, mutation.vector, mutation.controls, mutation.failure, a.metadata, a.receipt, envelopeBytes, mutation.plaintext, ciphertext, 1, 2)
		if err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, nil
}

func freezeFixture(fileName, name string, vectorIndex int, controls []string, failure string, metadataBytes, receiptBytes, envelopeBytes, plaintext, ciphertext []byte, wrappingScalar, ephemeralScalar byte) (generatedFixture, error) {
	doc := fixtureDocument{
		Schema:               "agent-nostr-crypto-fixture/1",
		Name:                 name,
		SourceVectorIndex:    vectorIndex,
		Controls:             append([]string(nil), controls...),
		ExpectedFirstFailure: failure,
		MetadataJSON:         string(metadataBytes),
		RecordFingerprint:    sha256Hex(metadataBytes),
		KeySHA256:            keyHashFromReceipt(receiptBytes),
		EnrollmentJSON:       string(receiptBytes),
		EnvelopeJSON:         string(envelopeBytes),
		PlaintextHex:         hex.EncodeToString(plaintext),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return generatedFixture{}, err
	}
	return generatedFixture{
		fileName:             fileName,
		fileBytes:            append(raw, '\n'),
		metadata:             bytes.Clone(metadataBytes),
		receipt:              bytes.Clone(receiptBytes),
		envelope:             bytes.Clone(envelopeBytes),
		plaintext:            bytes.Clone(plaintext),
		ciphertext:           bytes.Clone(ciphertext),
		controls:             append([]string(nil), controls...),
		expectedFirstFailure: failure,
		vectorIndex:          vectorIndex,
		wrappingScalar:       wrappingScalar,
		ephemeralScalar:      ephemeralScalar,
	}, nil
}

func makePlaintext(domain, metadataHash, scalar []byte) []byte {
	plain := make([]byte, 69)
	copy(plain[:5], domain)
	copy(plain[5:37], metadataHash)
	copy(plain[37:], scalar)
	return plain
}

func mutateDomain(plain []byte) []byte {
	mutated := bytes.Clone(plain)
	copy(mutated[:5], []byte("KVAX1"))
	return mutated
}

func mutateBinding(plain []byte) []byte {
	mutated := bytes.Clone(plain)
	mutated[5] ^= 0x80
	return mutated
}

func mutateScalar(plain, scalar []byte) []byte {
	mutated := bytes.Clone(plain)
	copy(mutated[37:], scalar)
	return mutated
}

func decodePlaintextScalar(plain []byte) []byte {
	return bytes.Clone(plain[37:])
}

func secpOrderBytes() []byte {
	order, _ := new(big.Int).SetString(secp256k1OrderHex, 16)
	return order.FillBytes(make([]byte, 32))
}

func scalarOrderPlusThree() []byte {
	order, _ := new(big.Int).SetString(secp256k1OrderHex, 16)
	return new(big.Int).Add(order, big.NewInt(3)).FillBytes(make([]byte, 32))
}

func p256Private(scalar byte) (*ecdh.PrivateKey, error) {
	encoded := make([]byte, 32)
	encoded[31] = scalar
	return ecdh.P256().NewPrivateKey(encoded)
}

func mustP256Point(scalar byte) []byte {
	key, err := p256Private(scalar)
	if err != nil {
		panic("invalid fixed public P-256 fixture scalar")
	}
	return key.PublicKey().Bytes()
}

func sealFixture(metadataBytes, blob, wrappingPoint []byte, wrappingScalar, ephemeralScalar byte, plaintext []byte) ([]byte, []byte, error) {
	wrappingKey, err := p256Private(wrappingScalar)
	if err != nil {
		return nil, nil, err
	}
	ephemeralKey, err := p256Private(ephemeralScalar)
	if err != nil {
		return nil, nil, err
	}
	point := ephemeralKey.PublicKey().Bytes()
	shared, err := ephemeralKey.ECDH(wrappingKey.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	transcript := make([]byte, 0, len(shared)+4+len(point))
	transcript = append(transcript, shared...)
	transcript = append(transcript, 0, 0, 0, 1)
	transcript = append(transcript, point...)
	derived := sha256.Sum256(transcript)
	defer clear(transcript)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, nil, err
	}
	sealed := aead.Seal(nil, derived[16:], plaintext, nil)
	ciphertext := append(bytes.Clone(point), sealed...)
	if len(ciphertext) != 150 || !bytes.Equal(wrappingPoint, mustP256Point(wrappingScalar)) {
		return nil, nil, errors.New("fixture seal length or wrapping point mismatch")
	}
	value := envelope{
		Schema:      envelopeSchema,
		Algorithm:   envelopeAlgorithm,
		EnclaveBlob: base64.StdEncoding.EncodeToString(blob),
		Point:       base64.StdEncoding.EncodeToString(wrappingPoint),
		Fingerprint: sha256Hex(wrappingPoint),
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	return raw, ciphertext, nil
}

func openFixtureIndependently(envelopeBytes []byte, wrappingScalar byte) ([]byte, []byte, error) {
	var value envelope
	if err := json.Unmarshal(envelopeBytes, &value); err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, envelopeBytes) {
		return nil, nil, errors.New("fixture envelope is not canonical")
	}
	encodedPoint, err := base64.StdEncoding.Strict().DecodeString(value.Point)
	if err != nil || base64.StdEncoding.EncodeToString(encodedPoint) != value.Point || len(encodedPoint) != 65 {
		return nil, nil, errors.New("fixture wrapping point is invalid")
	}
	encodedCiphertext, err := base64.StdEncoding.Strict().DecodeString(value.Ciphertext)
	if err != nil || base64.StdEncoding.EncodeToString(encodedCiphertext) != value.Ciphertext || len(encodedCiphertext) != 150 {
		return nil, nil, errors.New("fixture ciphertext is invalid")
	}
	if !bytes.Equal(encodedPoint, mustP256Point(wrappingScalar)) || sha256Hex(encodedPoint) != value.Fingerprint || !bytes.Equal(encodedCiphertext[:65], mustP256Point(byte(int(wrappingScalar)+1))) {
		return nil, nil, errors.New("fixture key point or fingerprint is invalid")
	}
	wrappingKey, err := p256Private(wrappingScalar)
	if err != nil {
		return nil, nil, err
	}
	ephemeralKey, err := ecdh.P256().NewPublicKey(encodedCiphertext[:65])
	if err != nil {
		return nil, nil, err
	}
	shared, err := wrappingKey.ECDH(ephemeralKey)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	kdfInput := append([]byte(nil), shared...)
	kdfInput = append(kdfInput, 0, 0, 0, 1)
	kdfInput = append(kdfInput, encodedCiphertext[:65]...)
	material := sha256.Sum256(kdfInput)
	defer clear(kdfInput)
	block, err := aes.NewCipher(material[:16])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, nil, err
	}
	plain, err := aead.Open(nil, material[16:], encodedCiphertext[65:], nil)
	if err != nil {
		return nil, nil, err
	}
	if len(plain) != 69 {
		return plain, encodedCiphertext, errors.New("fixture plaintext length is invalid")
	}
	return plain, encodedCiphertext, nil
}

func encodeNPub(public []byte) (string, error) {
	if len(public) != 32 {
		return "", errors.New("x-only public key must be 32 bytes")
	}
	data, err := convertBits(public, 8, 5, true)
	if err != nil {
		return "", err
	}
	hr := "npub"
	values := append(expandHRP(hr), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	checksum := polymod(values) ^ 1
	for i := 0; i < 6; i++ {
		data = append(data, byte((checksum>>uint(5*(5-i)))&31))
	}
	var out strings.Builder
	out.WriteString(hr)
	out.WriteByte('1')
	for _, value := range data {
		out.WriteByte(bech32Alphabet[value])
	}
	return out.String(), nil
}

const bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func expandHRP(hrp string) []byte {
	result := make([]byte, 0, len(hrp)*2+1)
	for _, r := range hrp {
		result = append(result, byte(r>>5))
	}
	result = append(result, 0)
	for _, r := range hrp {
		result = append(result, byte(r&31))
	}
	return result
}

func polymod(values []byte) uint32 {
	generators := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i, generator := range generators {
			if top>>uint(i)&1 != 0 {
				checksum ^= generator
			}
		}
	}
	return checksum
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var accumulator uint32
	var bits uint
	maxValue := uint32((1 << toBits) - 1)
	result := make([]byte, 0, (len(data)*int(fromBits)+int(toBits)-1)/int(toBits))
	for _, value := range data {
		if uint32(value)>>fromBits != 0 {
			return nil, errors.New("input value exceeds bit width")
		}
		accumulator = (accumulator << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((accumulator>>bits)&maxValue))
		}
	}
	if pad {
		if bits > 0 {
			result = append(result, byte((accumulator<<(toBits-bits))&maxValue))
		}
	} else if bits >= fromBits || ((accumulator<<(toBits-bits))&maxValue) != 0 {
		return nil, errors.New("invalid bit conversion padding")
	}
	return result, nil
}

func verifyPublicEncoding(raw []byte) error {
	var fixture struct {
		Scope               string `json:"scope"`
		MetadataUTF8        string `json:"metadata_utf8"`
		MetadataBytes       int    `json:"metadata_bytes"`
		RecordFingerprint   string `json:"record_fingerprint"`
		KeySHA256           string `json:"key_sha256"`
		EnrollmentUTF8      string `json:"enrollment_utf8"`
		EnrollmentBytes     int    `json:"enrollment_bytes"`
		EnrollmentSHA256    string `json:"enrollment_sha256"`
		WrappingFingerprint string `json:"wrapping_fingerprint"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 9 {
		return errors.New("public encoding fixture field set changed")
	}
	metadataBytes := []byte(fixture.MetadataUTF8)
	receiptBytes := []byte(fixture.EnrollmentUTF8)
	if fixture.MetadataBytes != 632 || len(metadataBytes) != fixture.MetadataBytes || fixture.EnrollmentBytes != 387 || len(receiptBytes) != fixture.EnrollmentBytes {
		return errors.New("public encoding fixture byte count changed")
	}
	if sha256Hex(metadataBytes) != fixture.RecordFingerprint || sha256Hex(receiptBytes) != fixture.EnrollmentSHA256 {
		return errors.New("public encoding fixture digest changed")
	}
	var parsed struct {
		PublicKey           string `json:"public_key"`
		NPub                string `json:"npub"`
		WrappingPoint       string `json:"wrapping_point"`
		WrappingFingerprint string `json:"wrapping_fingerprint"`
	}
	if err := json.Unmarshal(metadataBytes, &parsed); err != nil {
		return err
	}
	public, err := hex.DecodeString(parsed.PublicKey)
	if err != nil || len(public) != 32 || sha256Hex(public) != fixture.KeySHA256 {
		return errors.New("public encoding fixture key hash changed")
	}
	encodedPoint, err := base64.StdEncoding.Strict().DecodeString(parsed.WrappingPoint)
	if err != nil || base64.StdEncoding.EncodeToString(encodedPoint) != parsed.WrappingPoint || sha256Hex(encodedPoint) != fixture.WrappingFingerprint || fixture.WrappingFingerprint != parsed.WrappingFingerprint {
		return errors.New("public encoding fixture wrapping point changed")
	}
	if len(encodedPoint) != 65 || base64.StdEncoding.EncodeToString(mustP256Point(1)) != parsed.WrappingPoint || parsed.WrappingPoint != knownP256GeneratorEncoded {
		return errors.New("public encoding fixture P-256 point changed")
	}
	if parsed.PublicKey != knownNIP19PublicKey || parsed.NPub != knownNIP19PublicEncoding {
		return errors.New("public NIP-19 fixture changed")
	}
	return nil
}

func manifestFor(f generatedFixture) artifactManifest {
	return artifactManifest{
		Name:                 strings.TrimSuffix(f.fileName, ".json"),
		File:                 f.fileName,
		Bytes:                len(f.fileBytes),
		SHA256:               sha256Hex(f.fileBytes),
		MetadataBytes:        len(f.metadata),
		MetadataSHA256:       sha256Hex(f.metadata),
		ReceiptBytes:         len(f.receipt),
		ReceiptSHA256:        sha256Hex(f.receipt),
		EnvelopeBytes:        len(f.envelope),
		EnvelopeSHA256:       sha256Hex(f.envelope),
		PlaintextBytes:       len(f.plaintext),
		PlaintextSHA256:      sha256Hex(f.plaintext),
		CiphertextBytes:      len(f.ciphertext),
		CiphertextSHA256:     sha256Hex(f.ciphertext),
		Controls:             append([]string(nil), f.controls...),
		ExpectedFirstFailure: f.expectedFirstFailure,
	}
}

func generatorSourceHash(root string) (string, error) {
	paths := []string{
		"tools/agentnostrfixture/main.go",
		"tools/agentnostrfixture/oracle.go",
	}
	h := sha256.New()
	for _, name := range paths {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(content)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeFiles(directory string, files map[string][]byte) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return errors.New("unsafe fixture name")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(directory, name), files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decodeHex32(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("fixture value is not 32 bytes of hexadecimal")
	}
	return decoded, nil
}

func keyHashFromReceipt(raw []byte) string {
	var value enrollment
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value.KeySHA256
}
