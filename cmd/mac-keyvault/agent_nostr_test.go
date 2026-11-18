package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type agentNostrFixtureFile struct {
	MetadataJSON   string `json:"metadata_json"`
	EnrollmentJSON string `json:"enrollment_json"`
	EnvelopeJSON   string `json:"envelope_json"`
	PlaintextHex   string `json:"plaintext_hex"`
}

type cliAgentNostrItem struct {
	metadata []byte
	envelope []byte
}

type cliAgentNostrStore struct {
	items   map[string]cliAgentNostrItem
	selects int
	loads   int
	adds    int
}

func (s *cliAgentNostrStore) ListAgentNostr() ([]keyvault.AgentNostrItem, error) {
	rows := make([]keyvault.AgentNostrItem, 0, len(s.items))
	for account, item := range s.items {
		rows = append(rows, keyvault.AgentNostrItem{Account: account, Metadata: bytes.Clone(item.metadata)})
	}
	return rows, nil
}

func (s *cliAgentNostrStore) SelectAgentNostr(account string) (keyvault.AgentNostrSelection, error) {
	s.selects++
	item, ok := s.items[account]
	if !ok {
		return nil, keyvault.ErrNotFound
	}
	return &cliAgentNostrSelection{store: s, account: account, item: item}, nil
}

func (s *cliAgentNostrStore) AddAgentNostr(string, []byte, []byte) (bool, error) {
	s.adds++
	return false, errors.New("unexpected fixture mutation")
}

type cliAgentNostrSelection struct {
	store   *cliAgentNostrStore
	account string
	item    cliAgentNostrItem
}

func (s *cliAgentNostrSelection) Metadata() []byte { return bytes.Clone(s.item.metadata) }
func (s *cliAgentNostrSelection) LoadEnvelope() ([]byte, []byte, error) {
	s.store.loads++
	item, ok := s.store.items[s.account]
	if !ok {
		return nil, nil, keyvault.ErrNotFound
	}
	return bytes.Clone(item.metadata), bytes.Clone(item.envelope), nil
}
func (*cliAgentNostrSelection) Close() {}

type cliAgentNostrPrivate struct {
	plaintext []byte
	unwraps   int
}

func (*cliAgentNostrPrivate) CreateWrap() (keyvault.AgentNostrWrap, error) {
	return keyvault.AgentNostrWrap{}, errors.New("unexpected fixture wrap")
}
func (p *cliAgentNostrPrivate) UnwrapAgentNostr(keyvault.AgentNostrEnvelope) ([]byte, error) {
	p.unwraps++
	return bytes.Clone(p.plaintext), nil
}

type cliAgentNostrLock struct{}

func (cliAgentNostrLock) Lock() (func(), error) { return func() {}, nil }

func cliAgentNostrFixture(t *testing.T) (keyvault.AgentNostrPublic, keyvault.AgentNostrEnrollment) {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "keyvault", "testdata", "agent-nostr", "fixture-a.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("public agent Nostr fixture unavailable")
	}
	var fixture agentNostrFixtureFile
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("public agent Nostr fixture malformed")
	}
	record, fingerprint, err := keyvault.ParseAgentNostrRecord([]byte(fixture.MetadataJSON))
	if err != nil {
		t.Fatal("public fixture record rejected")
	}
	public := keyvault.AgentNostrPublicResult(record, []byte(fixture.MetadataJSON))
	if public.RecordFingerprint != fingerprint {
		t.Fatal("fixture public pin changed")
	}
	receipt, err := keyvault.ParseAgentNostrEnrollment([]byte(fixture.EnrollmentJSON))
	if err != nil {
		t.Fatal("public fixture enrollment rejected")
	}
	return public, receipt
}

func cliAgentNostrEndpointFixture(t *testing.T, service string, version int, identity string) (keyvault.AgentNostrPublic, keyvault.AgentNostrEnrollment) {
	t.Helper()
	public, receipt := cliAgentNostrFixture(t)
	record := public.Record
	record.Service, record.Version = service, version
	metadata, err := keyvault.MarshalAgentNostrRecord(record)
	if err != nil {
		t.Fatal("valid endpoint metadata unavailable")
	}
	public = keyvault.AgentNostrPublicResult(record, metadata)
	receipt.OwnerMXID, receipt.Service, receipt.Version = identity, service, version
	receipt.RecordFingerprint, receipt.KeySHA256 = public.RecordFingerprint, public.KeySHA256
	raw, err := keyvault.MarshalAgentNostrEnrollment(receipt)
	if err != nil {
		t.Fatal("matching endpoint receipt unavailable")
	}
	if _, err := keyvault.ParseAgentNostrEnrollment(raw); err != nil {
		t.Fatal("matching endpoint receipt did not round-trip")
	}
	return public, receipt
}

func newCLIRealAgentNostrManager(t *testing.T) (*keyvault.AgentNostrManager, *cliAgentNostrStore, *cliAgentNostrPrivate, keyvault.AgentNostrPublic, keyvault.AgentNostrEnrollment) {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "keyvault", "testdata", "agent-nostr", "fixture-a.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("public signing fixture unavailable")
	}
	var fixture agentNostrFixtureFile
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("public signing fixture malformed")
	}
	record, _, err := keyvault.ParseAgentNostrRecord([]byte(fixture.MetadataJSON))
	if err != nil {
		t.Fatal("public signing metadata rejected")
	}
	public := keyvault.AgentNostrPublicResult(record, []byte(fixture.MetadataJSON))
	receipt, err := keyvault.ParseAgentNostrEnrollment([]byte(fixture.EnrollmentJSON))
	if err != nil {
		t.Fatal("public signing receipt rejected")
	}
	plaintext, err := hex.DecodeString(fixture.PlaintextHex)
	if err != nil || len(plaintext) != keyvault.AgentNostrPlaintextSize {
		t.Fatal("public signing plaintext fixture malformed")
	}
	account := keyvault.AgentNostrAccount(record.Service, record.Version)
	store := &cliAgentNostrStore{items: map[string]cliAgentNostrItem{
		account: {metadata: []byte(fixture.MetadataJSON), envelope: []byte(fixture.EnvelopeJSON)},
	}}
	private := &cliAgentNostrPrivate{plaintext: plaintext}
	manager := keyvault.NewAgentNostrManager(store, private, cliAgentNostrLock{})
	return manager, store, private, public, receipt
}

func writeAgentNostrReceipt(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrollment.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal("cannot write test receipt")
	}
	return path
}

type agentNostrCLIFake struct {
	public       keyvault.AgentNostrPublic
	public2      keyvault.AgentNostrPublic
	rows         []keyvault.AgentNostrPublic
	signature    keyvault.AgentNostrSignature
	listErr      error
	describeErr  error
	generateErr  error
	signErr      error
	calls        []string
	lastService  string
	lastVersion  int
	signIdentity string
	signReceipt  keyvault.AgentNostrEnrollment
	signDigest   []byte
}

func (f *agentNostrCLIFake) List() ([]keyvault.AgentNostrPublic, error) {
	f.calls = append(f.calls, "list")
	return f.rows, f.listErr
}

func (f *agentNostrCLIFake) Describe(service string, version int) (keyvault.AgentNostrPublic, error) {
	f.calls = append(f.calls, "describe")
	f.lastService, f.lastVersion = service, version
	if version == 2 && f.public2.Record.Version == 2 {
		return f.public2, f.describeErr
	}
	return f.public, f.describeErr
}

func (f *agentNostrCLIFake) Generate(service string, version int) (keyvault.AgentNostrPublic, error) {
	f.calls = append(f.calls, "generate")
	f.lastService, f.lastVersion = service, version
	if version == 2 && f.public2.Record.Version == 2 {
		return f.public2, f.generateErr
	}
	return f.public, f.generateErr
}

func (f *agentNostrCLIFake) Sign(identity string, receipt keyvault.AgentNostrEnrollment, service string, version int, digest []byte) (keyvault.AgentNostrSignature, error) {
	f.calls = append(f.calls, "sign")
	f.lastService, f.lastVersion = service, version
	f.signIdentity, f.signReceipt, f.signDigest = identity, receipt, bytes.Clone(digest)
	return f.signature, f.signErr
}

// Claim: all five operations route to the intended manager method and expose
// only the contract's public fields; limit: this fake does not cover native
// Keychain or reciprocal helper admission.
func TestAgentNostrCLIAllOperationsAndFormats(t *testing.T) {
	public, receipt := cliAgentNostrFixture(t)
	public2 := public
	public2.Record.Version = 2
	metadata2, err := keyvault.MarshalAgentNostrRecord(public2.Record)
	if err != nil {
		t.Fatal("cannot make second public version")
	}
	public2 = keyvault.AgentNostrPublicResult(public2.Record, metadata2)
	receiptPath := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
	fake := &agentNostrCLIFake{public: public, public2: public2, rows: []keyvault.AgentNostrPublic{public, public2}, signature: keyvault.AgentNostrSignature{Algorithm: "secp256k1-bip340", Signature: strings.Repeat("a", 128), RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256}}
	factoryCalls := 0
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"generate", []string{"agent-nostr", "generate", "--service", public.Record.Service, "--version", "1"}, "record_fingerprint"},
		{"generate-v2", []string{"agent-nostr", "generate", "--service", public.Record.Service, "--version", "2", "--json"}, `"version": 2`},
		{"list", []string{"--json", "agent-nostr", "list"}, `"ok": true`},
		{"describe", []string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version=1", "--json"}, `"record"`},
		{"describe-v2", []string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "2", "--json"}, `"version": 2`},
		{"pub-hex", []string{"agent-nostr", "pub", public.Record.Service + "/nostr", "--version", "1", "--format", "x-only-hex", "--json"}, `"format": "x-only-hex"`},
		{"pub-npub", []string{"agent-nostr", "pub", public.Record.Service + "/nostr", "--version", "1", "--format=npub"}, public.Record.NPub},
		{"sign", []string{"agent-nostr", "sign", public.Record.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID, "--enrollment-receipt", receiptPath, "--digest", strings.Repeat("A", 64), "--json"}, `"signature"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("operation %s did not return its public result", tc.name)
			}
		})
	}
	if factoryCalls != len(cases) || len(fake.calls) != len(cases) || fake.signIdentity != receipt.OwnerMXID || fake.signReceipt != receipt || len(fake.signDigest) != 32 || fake.signDigest[0] != 0xaa || fake.lastVersion != 1 || fake.lastService != public.Record.Service {
		t.Fatal("CLI did not preserve validated operation inputs")
	}
	if strings.Contains(fake.signIdentity, "agent-nostr") {
		t.Fatal("test identity unexpectedly came from the command name")
	}
}

// Claim: malformed/duplicate/unsupported command input is refused before a
// manager can be constructed; limit: trusted actor authorization is external.
func TestAgentNostrCLIRefusesSyntaxBeforeManagerConstruction(t *testing.T) {
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return &agentNostrCLIFake{}, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	cases := [][]string{
		{"agent-nostr", "generate", "--service", "agent-a"},
		{"agent-nostr", "generate", "--service", "agent-a", "--version", "01"},
		{"agent-nostr", "generate", "--service", "agent-a", "--version", "1", "--version", "1"},
		{"agent-nostr", "generate", "--service", "agent-a", "--version", "1", "--private"},
		{"agent-nostr", "list", "--version", "1"},
		{"agent-nostr", "describe", "agent-a/nostr", "--version", "1", "--delete"},
		{"agent-nostr", "pub", "agent-a/nostr", "--version", "1", "--format", "nsec"},
		{"agent-nostr", "sign", "agent-a/nostr", "--version", "1", "--identity", "@a:b", "--enrollment-receipt", "somewhere", "--digest", "0"},
		{"agent-nostr", "import"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitUsage || json.Unmarshal(stdout.Bytes(), &response) != nil || response.OK || response.Error == nil || response.Error.Code != "agent_nostr_invalid_input" || response.Result != nil || factoryCalls != 0 {
			t.Fatalf("invalid syntax reached backend or returned the wrong refusal for %q", args)
		}
	}
}

// Claim: valid service/version endpoints carry matching canonical receipt pins
// through CLI dispatch, while forbidden names and version spellings refuse
// before manager construction; limit: fake dispatch does not qualify actor policy.
func TestAgentNostrCLICompatibilityEndpointsAndForbiddenPairs(t *testing.T) {
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	var last *agentNostrCLIFake
	newAgentNostrOperations = func() (agentNostrOperations, error) {
		factoryCalls++
		return last, nil
	}
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	maxIdentity := "@" + strings.Repeat("a", 1024-len("@:example.invalid")) + ":example.invalid"
	for _, tc := range []struct {
		service  string
		version  int
		identity string
		jsonMode bool
	}{
		{service: "agent-a", version: 1, identity: "@agent-fixture:example.invalid"},
		{service: "agent-" + strings.Repeat("a", 34), version: 2147483647, identity: maxIdentity, jsonMode: true},
	} {
		public, receipt := cliAgentNostrEndpointFixture(t, tc.service, tc.version, tc.identity)
		path := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
		last = &agentNostrCLIFake{public: public, signature: keyvault.AgentNostrSignature{
			Algorithm: keyvault.AgentNostrAlgorithm, Signature: strings.Repeat("a", 128),
			RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256,
		}}
		args := []string{"agent-nostr", "sign", tc.service + "/nostr", "--version", strconv.Itoa(tc.version), "--identity", tc.identity,
			"--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
		if tc.jsonMode {
			args = append([]string{"--json"}, args...)
		}
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitOK || stderr.Len() != 0 || factoryCalls == 0 || last.lastService != tc.service || last.lastVersion != tc.version || last.signReceipt != receipt {
			t.Fatal("valid service/version CLI endpoint did not reach sign with its matching receipt")
		}
	}
	if factoryCalls != 2 {
		t.Fatal("valid endpoint count changed unexpectedly")
	}
	for _, service := range []string{
		"agent-", "agent--a", "agent-" + strings.Repeat("a", 35), "agent-A", "agent-a\n", "other-a",
	} {
		args := []string{"agent-nostr", "generate", "--service", service, "--version", "1"}
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitUsage || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_input" || factoryCalls != 2 {
			t.Fatalf("forbidden service %q reached backend or had the wrong refusal", service)
		}
	}
	for _, version := range []string{"0", "-1", "2147483648", "999999999999999999999999999999", "+1", "01", " 1", "1 "} {
		args := []string{"agent-nostr", "generate", "--service", "agent-a", "--version", version}
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitUsage || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_input" || factoryCalls != 2 {
			t.Fatalf("forbidden version %q reached backend or had the wrong refusal", version)
		}
	}
	for _, args := range [][]string{
		{"agent-nostr", "generate", "--service", "agent-a"},
		{"agent-nostr", "generate", "--service", "agent-a", "--version", ""},
	} {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitUsage || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_input" || factoryCalls != 2 {
			t.Fatal("missing version reached backend or had the wrong refusal")
		}
	}
}

// Claim: lower- and uppercase CLI hex forms containing a..f reach the real Go
// signer as the same 32-byte message and each signature verifies; limit: the
// fixture private boundary does not qualify native process admission.
func TestAgentNostrCLIDigestHexCaseUsesRealSigner(t *testing.T) {
	_, receipt := cliAgentNostrFixture(t)
	path := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	var stores []*cliAgentNostrStore
	var privates []*cliAgentNostrPrivate
	newAgentNostrOperations = func() (agentNostrOperations, error) {
		factoryCalls++
		manager, store, private, _, _ := newCLIRealAgentNostrManager(t)
		stores = append(stores, store)
		privates = append(privates, private)
		return manager, nil
	}
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	digestHex := strings.Repeat("abcdef0123456789", 4)
	lowerDigest, err := hex.DecodeString(digestHex)
	if err != nil || len(lowerDigest) != 32 || !strings.ContainsAny(digestHex, "abcdef") {
		t.Fatal("digest case fixture is not a discriminating 32-byte message")
	}
	upperDigest, err := hex.DecodeString(strings.ToUpper(digestHex))
	if err != nil || !bytes.Equal(lowerDigest, upperDigest) {
		t.Fatal("uppercase digest did not decode to the same message")
	}
	var signatures []string
	for _, encoded := range []string{digestHex, strings.ToUpper(digestHex)} {
		args := []string{"--json", "agent-nostr", "sign", receipt.Service + "/nostr", "--version", strconv.Itoa(receipt.Version),
			"--identity", receipt.OwnerMXID, "--enrollment-receipt", path, "--digest", encoded}
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitOK || stderr.Len() != 0 {
			t.Fatal("valid digest encoding did not complete sign delivery")
		}
		var response struct {
			OK     bool `json:"ok"`
			Result struct {
				Algorithm string `json:"algorithm"`
				Signature string `json:"signature"`
			} `json:"result"`
			Error *agentNostrJSONError `json:"error"`
		}
		if json.Unmarshal(stdout.Bytes(), &response) != nil || !response.OK || response.Error != nil || response.Result.Algorithm != keyvault.AgentNostrAlgorithm || len(response.Result.Signature) != 128 {
			t.Fatal("real signer did not return a complete signature result")
		}
		signature, err := hex.DecodeString(response.Result.Signature)
		public, _ := hex.DecodeString(receipt.PublicKey)
		if err != nil || keyvault.VerifyNostr(public, lowerDigest, signature) != nil {
			t.Fatal("CLI signature did not verify against the common decoded digest")
		}
		signatures = append(signatures, response.Result.Signature)
	}
	if factoryCalls != 2 || len(stores) != 2 || len(privates) != 2 {
		t.Fatal("digest case pair did not use two isolated full signing paths")
	}
	for i := range stores {
		if stores[i].selects != 1 || stores[i].loads != 1 || stores[i].adds != 0 || privates[i].unwraps != 1 {
			t.Fatal("digest case signing path changed state or skipped the private release boundary")
		}
	}
	if signatures[0] == "" || signatures[1] == "" {
		t.Fatal("one digest case did not produce a signature")
	}
}

// Claim: an empty public inventory succeeds as [] in JSON and as a complete
// public table in text mode; limit: the fake list does not prove native namespace isolation.
func TestAgentNostrCLIEmptyListBothModes(t *testing.T) {
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { return &agentNostrCLIFake{}, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--json", "agent-nostr", "list"}, `"result": []`},
		{[]string{"agent-nostr", "list"}, "service/nostr@version"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(tc.args, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), tc.want) || stderr.Len() != 0 {
			t.Fatal("empty agent Nostr list did not produce a complete success representation")
		}
	}
}

// Claim: an invalid file and a valid receipt mismatch stop before backend
// construction; limit: filesystem ownership is provenance hygiene, not same-
// user authentication.
func TestAgentNostrReceiptValidationBeforeManager(t *testing.T) {
	_, receipt := cliAgentNostrFixture(t)
	validPath := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
	malformedPath := writeAgentNostrReceipt(t, `{"schema":"bad"}`)
	symlinkPath := filepath.Join(t.TempDir(), "receipt-link")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal("cannot make symlink control")
	}
	unsafePath := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
	if err := os.Chmod(unsafePath, 0666); err != nil {
		t.Fatal("cannot set unsafe mode control")
	}
	missingPath := filepath.Join(t.TempDir(), "missing.json")
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return &agentNostrCLIFake{}, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	for _, path := range []string{missingPath, malformedPath, symlinkPath, unsafePath, t.TempDir()} {
		args := []string{"agent-nostr", "sign", receipt.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID, "--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitRefused || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_enrollment" || factoryCalls != 0 {
			t.Fatal("unsafe or malformed enrollment reached manager construction")
		}
	}
	for _, mismatch := range []struct {
		address, identity string
	}{
		{receipt.Service + "/nostr", "@other:example.invalid"},
		{"agent-other/nostr", receipt.OwnerMXID},
	} {
		args := []string{"agent-nostr", "sign", mismatch.address, "--version", "1", "--identity", mismatch.identity, "--enrollment-receipt", validPath, "--digest", strings.Repeat("0", 64)}
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitRefused || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_enrollment_mismatch" || factoryCalls != 0 {
			t.Fatal("valid receipt mismatch reached manager construction")
		}
	}
}

// Claim: complete-file receipt limits refuse 8,193 bytes before manager
// construction; limit: exact-cap raw bytes are a parser component probe, not
// a valid enrollment receipt.
func TestAgentNostrReceiptRawSizeBoundaries(t *testing.T) {
	_, receipt := cliAgentNostrFixture(t)
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return &agentNostrCLIFake{}, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	for _, size := range []int{8192, 8193} {
		path := writeAgentNostrReceipt(t, string(bytes.Repeat([]byte{'x'}, size)))
		args := []string{"agent-nostr", "sign", receipt.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID, "--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json"}, args...), &stdout, &stderr)
		var response agentNostrResponse
		if code != exitRefused || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_enrollment" || factoryCalls != 0 || stderr.Len() != 0 {
			t.Fatalf("%d-byte receipt probe did not refuse before manager construction", size)
		}
	}
}

// Claim: the bounded receipt reader passes exactly 8,192 bytes to its parser
// and stops 8,193 bytes before parsing; limit: this component probe does not
// establish semantic validity, which is covered by the CLI receipt fixtures.
func TestAgentNostrReceiptReaderSizeLayerBeforeParser(t *testing.T) {
	for _, size := range []int{keyvault.AgentNostrMaxReceipt, keyvault.AgentNostrMaxReceipt + 1} {
		calls, parsedLength := 0, 0
		parser := func(raw []byte) (keyvault.AgentNostrEnrollment, error) {
			calls++
			parsedLength = len(raw)
			return keyvault.AgentNostrEnrollment{}, nil
		}
		_, err := parseAgentNostrEnrollmentReader(bytes.NewReader(bytes.Repeat([]byte{'x'}, size)), parser)
		if size == keyvault.AgentNostrMaxReceipt {
			if err != nil || calls != 1 || parsedLength != size {
				t.Fatal("exact-cap receipt did not reach the parser exactly once")
			}
			continue
		}
		if err == nil || calls != 0 || parsedLength != 0 {
			t.Fatal("cap+1 receipt was not stopped before the parser")
		}
	}
}

// Claim: exact describe and pub absence return not_found without invoking
// generation or a fallback; limit: the fake exposes only the CLI dispatch seam.
func TestAgentNostrMissingDescribeAndPubDoNotCreate(t *testing.T) {
	public, _ := cliAgentNostrFixture(t)
	fake := &agentNostrCLIFake{public: public, describeErr: &keyvault.AgentNostrFailure{Code: keyvault.AgentNostrCodeNotFound}}
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	for _, args := range [][]string{
		{"--json", "agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "1"},
		{"--json", "agent-nostr", "pub", public.Record.Service + "/nostr", "--version", "1", "--format", "x-only-hex"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		var response agentNostrResponse
		if code != exitRefused || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_not_found" || stderr.Len() != 0 {
			t.Fatal("absent exact public operation did not return not_found")
		}
	}
	if factoryCalls != 2 || len(fake.calls) != 2 || fake.calls[0] != "describe" || fake.calls[1] != "describe" {
		t.Fatal("absent describe/pub created, signed, or fell back to another generation")
	}
}

// Claim: a FIFO with no writer returns invalid_enrollment before backend
// creation instead of blocking; limit: this checks file admission on the test
// host and does not exercise a native vault operation.
func TestAgentNostrFIFOReceiptRefusesWithoutBlocking(t *testing.T) {
	public, receipt := cliAgentNostrFixture(t)
	validPath := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
	fake := &agentNostrCLIFake{public: public, signature: keyvault.AgentNostrSignature{
		Algorithm: keyvault.AgentNostrAlgorithm, Signature: strings.Repeat("a", 128),
		RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256,
	}}
	oldFactory := newAgentNostrOperations
	factoryCalls := 0
	newAgentNostrOperations = func() (agentNostrOperations, error) { factoryCalls++; return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	argsFor := func(path string) []string {
		return []string{"--json", "agent-nostr", "sign", receipt.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID,
			"--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
	}
	var validOut, validErr bytes.Buffer
	if code := run(argsFor(validPath), &validOut, &validErr); code != exitOK || factoryCalls != 1 || len(fake.calls) != 1 || fake.calls[0] != "sign" || validErr.Len() != 0 {
		t.Fatal("valid regular receipt did not reach the paired positive sign path")
	}
	fifoPath := filepath.Join(t.TempDir(), "enrollment.fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal("cannot create no-writer FIFO receipt")
	}
	type runResult struct {
		code   int
		stdout []byte
		stderr []byte
	}
	done := make(chan runResult, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		code := run(argsFor(fifoPath), &stdout, &stderr)
		done <- runResult{code: code, stdout: bytes.Clone(stdout.Bytes()), stderr: bytes.Clone(stderr.Bytes())}
	}()
	select {
	case result := <-done:
		var response agentNostrResponse
		if result.code != exitRefused || json.Unmarshal(result.stdout, &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_invalid_enrollment" ||
			factoryCalls != 1 || len(fake.calls) != 1 || len(result.stderr) != 0 {
			t.Fatal("FIFO receipt was not rejected before backend creation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO receipt open blocked without a writer")
	}
}

// Claim: public error text/JSON is fixed, closed and free of OS status; limit:
// the native Security.framework status-to-class mapping is separately tested.
func TestAgentNostrClosedErrorMappingAndUnknownAllowlist(t *testing.T) {
	public, _ := cliAgentNostrFixture(t)
	for _, tc := range []struct {
		code string
		want string
		exit int
	}{
		{"invalid_input", "agent_nostr_invalid_input", exitUsage},
		{"invalid_enrollment", "agent_nostr_invalid_enrollment", exitRefused},
		{"enrollment_mismatch", "agent_nostr_enrollment_mismatch", exitRefused},
		{"duplicate", "agent_nostr_duplicate", exitRefused},
		{"not_found", "agent_nostr_not_found", exitRefused},
		{"corrupt_record", "agent_nostr_corrupt_record", exitRefused},
		{"unavailable", "agent_nostr_unavailable", exitFailure},
		{"untrusted", "agent_nostr_untrusted", exitRefused},
		{"unknown", "agent_nostr_unknown", exitFailure},
	} {
		code, response := agentNostrErrorDetails(tc.code)
		if code != tc.exit || response.Code != tc.want || response.Message == "" || response.Hint == "" {
			t.Fatalf("public mapping changed for %s", tc.code)
		}
	}
	fake := &agentNostrCLIFake{public: public, generateErr: &keyvault.AgentNostrFailure{Code: "unknown", Operation: "generate", Service: "agent-fixture", Purpose: "nostr", Version: 1, Outcome: "unknown", PublicKey: public.Record.PublicKey, KeySHA256: public.KeySHA256, RecordFingerprint: public.RecordFingerprint}}
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	var stdout, stderr bytes.Buffer
	code := run([]string{"agent-nostr", "generate", "--service", "agent-fixture", "--version", "1", "--json"}, &stdout, &stderr)
	var response struct {
		OK      bool                 `json:"ok"`
		Command string               `json:"command"`
		Result  map[string]any       `json:"result"`
		Error   *agentNostrJSONError `json:"error"`
	}
	if code != exitFailure || json.Unmarshal(stdout.Bytes(), &response) != nil || response.OK || response.Error == nil || response.Error.Code != "agent_nostr_unknown" || response.Command != "agent-nostr" || response.Result["outcome"] != "unknown" {
		t.Fatal("unknown candidate response did not match the public envelope")
	}
	allowed := map[string]bool{"operation": true, "service": true, "purpose": true, "version": true, "outcome": true, "public_key": true, "key_sha256": true, "record_fingerprint": true}
	for key := range response.Result {
		if !allowed[key] {
			t.Fatal("unknown response leaked a field outside its allowlist")
		}
	}
	if strings.Contains(stdout.String(), "os_status") || stderr.Len() != 0 {
		t.Fatal("agent Nostr error exposed a raw status or text side channel")
	}
}

type agentNostrWriteOutcome struct {
	n   int
	err error
}

type agentNostrTestWriter struct {
	outcomes []agentNostrWriteOutcome
	calls    int
	data     bytes.Buffer
}

func (w *agentNostrTestWriter) Write(data []byte) (int, error) {
	w.calls++
	if len(w.outcomes) == 0 {
		_, _ = w.data.Write(data)
		return len(data), nil
	}
	outcome := w.outcomes[0]
	w.outcomes = w.outcomes[1:]
	if outcome.n > 0 {
		written := outcome.n
		if written > len(data) {
			written = len(data)
		}
		_, _ = w.data.Write(data[:written])
	}
	return outcome.n, outcome.err
}

// Claim: the checked writer accepts only one complete nil-error write and the
// command never appends a refusal after partial success; limit: kernel pipe
// delivery and process completion require the native CLI lane.
func TestAgentNostrCheckedWriterAndAmbiguousDelivery(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    func(int) int
		err  error
		ok   bool
	}{
		{"full", func(n int) int { return n }, nil, true},
		{"short-nil", func(n int) int { return n - 1 }, nil, false},
		{"short-error", func(n int) int { return n - 1 }, io.ErrClosedPipe, false},
		{"full-error", func(n int) int { return n }, io.ErrClosedPipe, false},
		{"epipe", func(int) int { return 0 }, syscall.EPIPE, false},
		{"over-count", func(n int) int { return n + 1 }, nil, false},
		{"negative-count", func(int) int { return -1 }, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("complete-result\n")
			writer := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: tc.n(len(payload)), err: tc.err}}}
			if got := checkedAgentNostrWrite(writer, payload); got != tc.ok || writer.calls != 1 {
				t.Fatal("checked output did not enforce the full single-write contract")
			}
		})
	}
	public, _ := cliAgentNostrFixture(t)
	fake := &agentNostrCLIFake{public: public}
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	stdout := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: 3, err: nil}}}
	var stderr bytes.Buffer
	code := run([]string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "1", "--json"}, stdout, &stderr)
	if code != exitFailure || stdout.calls != 1 || !strings.Contains(stderr.String(), "agent_nostr_unavailable") {
		t.Fatal("partial public read was followed by another stdout result or reported success")
	}
	stdout = &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: 1, err: syscall.EPIPE}}}
	fake.generateErr = nil
	code = run([]string{"agent-nostr", "generate", "--service", public.Record.Service, "--version", "1"}, stdout, &stderr)
	if code != exitFailure || stdout.calls != 1 || !strings.Contains(stderr.String(), "agent_nostr_unknown") {
		t.Fatal("ambiguous generate output was not reported as unknown")
	}
}

// Claim: each chosen output mode requires one complete writer result, refusal
// delivery remains nonzero, and a lost signature is UNKNOWN without retry;
// limit: writers are borrowed and this path owns no Flush or Close operation.
func TestAgentNostrCheckedDeliveryModeMatrix(t *testing.T) {
	public, receipt := cliAgentNostrFixture(t)
	for _, jsonMode := range []bool{false, true} {
		mode := "plain"
		if jsonMode {
			mode = "json"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				n    func(int) int
				err  error
			}{
				{name: "full-nil", n: func(n int) int { return n }},
				{name: "short-nil", n: func(n int) int { return n - 1 }},
				{name: "short-error", n: func(n int) int { return n - 1 }, err: io.ErrClosedPipe},
				{name: "full-error", n: func(n int) int { return n }, err: io.ErrClosedPipe},
				{name: "epipe", n: func(int) int { return 0 }, err: syscall.EPIPE},
				{name: "over-count", n: func(n int) int { return n + 1 }},
				{name: "negative-count", n: func(int) int { return -1 }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					fake := &agentNostrCLIFake{public: public}
					oldFactory := newAgentNostrOperations
					newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
					t.Cleanup(func() { newAgentNostrOperations = oldFactory })
					args := []string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "1"}
					if jsonMode {
						args = append([]string{"--json"}, args...)
					}
					var expected []byte
					if jsonMode {
						expected, _ = agentNostrJSONEncode(agentNostrResponse{OK: true, Command: "agent-nostr", Result: public})
					} else {
						expected = []byte(agentNostrPlainSuccess("describe", public))
					}
					stdout := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: tc.n(len(expected)), err: tc.err}}}
					var stderr bytes.Buffer
					code := run(args, stdout, &stderr)
					if stdout.calls != 1 {
						t.Fatal("success delivery wrote a second stdout result after the first attempt")
					}
					if tc.name == "full-nil" {
						if code != exitOK || !bytes.Equal(stdout.data.Bytes(), expected) || stderr.Len() != 0 {
							t.Fatal("complete chosen-mode write did not produce usable success")
						}
					} else if code == exitOK || !strings.Contains(stderr.String(), "agent_nostr_unavailable") {
						t.Fatal("partial, errored, impossible-count or closed-pipe delivery was reported usable")
					}
				})
			}

			for _, tc := range []struct {
				name string
				n    func(int) int
				err  error
			}{
				{name: "full-nil", n: func(n int) int { return n }},
				{name: "short-nil", n: func(n int) int { return n - 1 }},
				{name: "short-error", n: func(n int) int { return n - 1 }, err: io.ErrClosedPipe},
				{name: "full-error", n: func(n int) int { return n }, err: io.ErrClosedPipe},
				{name: "epipe", n: func(int) int { return 0 }, err: syscall.EPIPE},
				{name: "over-count", n: func(n int) int { return n + 1 }},
				{name: "negative-count", n: func(int) int { return -1 }},
			} {
				failure := &keyvault.AgentNostrFailure{Code: "unavailable", Operation: "describe", Service: public.Record.Service, Purpose: "nostr", Version: 1}
				stdout := &agentNostrTestWriter{}
				stderr := &agentNostrTestWriter{}
				out := output{command: "agent-nostr", json: jsonMode, stdout: stdout, stderr: stderr}
				var target *agentNostrTestWriter
				if jsonMode {
					target = stdout
				} else {
					target = stderr
				}
				var expected []byte
				if jsonMode {
					_, refusal := agentNostrErrorDetails(failure.Code)
					expected, _ = agentNostrJSONEncode(agentNostrResponse{OK: false, Command: "agent-nostr", Error: &refusal})
				} else {
					_, refusal := agentNostrErrorDetails(failure.Code)
					expected = []byte(fmt.Sprintf("error: %s: %s\nhint: %s\n", refusal.Code, refusal.Message, refusal.Hint))
				}
				target.outcomes = []agentNostrWriteOutcome{{n: tc.n(len(expected)), err: tc.err}}
				code := deliverAgentNostrFailure(out, failure, false)
				if code == exitOK || target.calls != 1 || (tc.name == "full-nil" && !bytes.Equal(target.data.Bytes(), expected)) {
					t.Fatal("refusal delivery failure was reported as success or retried on the same channel")
				}
			}
		})
	}
	for _, jsonMode := range []bool{false, true} {
		fake := &agentNostrCLIFake{public: public, signature: keyvault.AgentNostrSignature{
			Algorithm: keyvault.AgentNostrAlgorithm, Signature: strings.Repeat("a", 128),
			RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256,
		}}
		oldFactory := newAgentNostrOperations
		newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
		path := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
		args := []string{"agent-nostr", "sign", public.Record.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID,
			"--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		stdout := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: 3, err: nil}}}
		var stderr bytes.Buffer
		code := run(args, stdout, &stderr)
		newAgentNostrOperations = oldFactory
		if code != exitFailure || stdout.calls != 1 || !strings.Contains(stderr.String(), "agent_nostr_unknown") || len(fake.calls) != 1 || fake.calls[0] != "sign" {
			t.Fatal("lost signature delivery was retried or did not preserve UNKNOWN state")
		}
	}

	for _, jsonMode := range []bool{false, true} {
		for _, sign := range []bool{false, true} {
			fake := &agentNostrCLIFake{public: public, signature: keyvault.AgentNostrSignature{
				Algorithm: keyvault.AgentNostrAlgorithm, Signature: strings.Repeat("a", 128),
				RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256,
			}}
			oldFactory := newAgentNostrOperations
			newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
			args := []string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "1"}
			if sign {
				path := writeAgentNostrReceipt(t, receiptJSON(t, receipt))
				args = []string{"agent-nostr", "sign", public.Record.Service + "/nostr", "--version", "1", "--identity", receipt.OwnerMXID,
					"--enrollment-receipt", path, "--digest", strings.Repeat("0", 64)}
			}
			if jsonMode {
				args = append([]string{"--json"}, args...)
			}
			stdout := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: 3, err: nil}}}
			stderr := &agentNostrTestWriter{outcomes: []agentNostrWriteOutcome{{n: 0, err: syscall.EPIPE}}}
			code := run(args, stdout, stderr)
			newAgentNostrOperations = oldFactory
			if code == exitOK || stdout.calls != 1 || stderr.calls != 1 || (sign && (len(fake.calls) != 1 || fake.calls[0] != "sign")) {
				t.Fatal("partial stdout plus stderr loss retried or reported usable result")
			}
		}
	}
}

// Claim: an encoder error in either selected mode refuses before success bytes
// are emitted; limit: borrowed writers have no owned Flush/Close semantics.
func TestAgentNostrEncodingFailureBothModes(t *testing.T) {
	public, _ := cliAgentNostrFixture(t)
	for _, jsonMode := range []bool{false, true} {
		fake := &agentNostrCLIFake{public: public}
		oldFactory := newAgentNostrOperations
		newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
		oldJSON, oldPlain := agentNostrJSONEncode, agentNostrPlainEncode
		if jsonMode {
			calls := 0
			agentNostrJSONEncode = func(value any) ([]byte, error) {
				calls++
				if calls == 1 {
					return nil, errors.New("fixture JSON encoding failure")
				}
				return oldJSON(value)
			}
		} else {
			agentNostrPlainEncode = func(string, any) ([]byte, error) {
				return nil, errors.New("fixture text encoding failure")
			}
		}
		args := []string{"agent-nostr", "describe", public.Record.Service + "/nostr", "--version", "1"}
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		agentNostrJSONEncode, agentNostrPlainEncode = oldJSON, oldPlain
		newAgentNostrOperations = oldFactory
		if code != exitFailure || len(fake.calls) != 1 {
			t.Fatal("encoding failure was not a nonzero, single-operation refusal")
		}
		if jsonMode {
			var response agentNostrResponse
			if json.Unmarshal(stdout.Bytes(), &response) != nil || response.OK || response.Error == nil || response.Error.Code != "agent_nostr_unavailable" || stderr.Len() != 0 {
				t.Fatal("JSON encoder failure emitted success or an unbounded fallback")
			}
		} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), "agent_nostr_unavailable") {
			t.Fatal("plain encoder failure emitted success or missed the fixed refusal")
		}
	}
}

func cliAgentNostrOutputRows(t *testing.T, count int, extraLengths []int) []keyvault.AgentNostrPublic {
	t.Helper()
	base, _ := cliAgentNostrFixture(t)
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	rows := make([]keyvault.AgentNostrPublic, 0, count)
	for i := 0; i < count; i++ {
		suffix := string([]byte{
			alphabet[(i/(36*36))%36],
			alphabet[(i/36)%36],
			alphabet[i%36],
		})
		extra := 0
		if len(extraLengths) != 0 {
			extra = extraLengths[i]
		}
		record := base.Record
		record.Service, record.Version = "agent-"+suffix+strings.Repeat("a", extra), 1
		metadata, err := keyvault.MarshalAgentNostrRecord(record)
		if err != nil {
			t.Fatal("cannot make canonical unique-account output row")
		}
		public := keyvault.AgentNostrPublicResult(record, metadata)
		parsed, fingerprint, err := keyvault.ParseAgentNostrRecord(metadata)
		if err != nil || parsed != record || fingerprint != public.RecordFingerprint || public.KeySHA256 != base.KeySHA256 {
			t.Fatal("output row did not preserve canonical record and public pins")
		}
		rows = append(rows, public)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Record.Service < rows[j].Record.Service })
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Record.Service == rows[i].Record.Service {
			t.Fatal("output rows do not have unique accounts")
		}
	}
	return rows
}

func cliExpectedAgentNostrList(rows []keyvault.AgentNostrPublic, jsonMode bool) []byte {
	if jsonMode {
		encoded, _ := json.MarshalIndent(agentNostrResponse{OK: true, Command: "agent-nostr", Result: rows}, "", "  ")
		return append(encoded, '\n')
	}
	var text strings.Builder
	text.WriteString("service/nostr@version\tpublic_key\tnpub\tkey_sha256\trecord_fingerprint\n")
	for _, row := range rows {
		fmt.Fprintf(&text, "%s/nostr@%d\t%s\t%s\t%s\t%s\n", row.Record.Service, row.Record.Version,
			row.Record.PublicKey, row.Record.NPub, row.KeySHA256, row.RecordFingerprint)
	}
	return []byte(text.String())
}

func cliAgentNostrCapVariants(t *testing.T, base []keyvault.AgentNostrPublic, count, limit int, jsonMode bool) (below, exact, above []keyvault.AgentNostrPublic) {
	t.Helper()
	extras := make([]int, count)
	needed := limit - len(cliExpectedAgentNostrList(base[:count], jsonMode))
	if needed < 0 || needed > 31*count {
		t.Fatal("canonical service fields cannot reach the requested exact list cap")
	}
	for i := range extras {
		if needed == 0 {
			break
		}
		extra := needed
		if extra > 31 {
			extra = 31
		}
		extras[i], needed = extra, needed-extra
	}
	if needed != 0 {
		t.Fatal("schema-valid service padding cannot reach the exact list cap")
	}
	exact = cliAgentNostrOutputRows(t, count, extras)
	for len(cliExpectedAgentNostrList(exact, jsonMode)) != limit {
		t.Fatal("complete canonical JSON list did not reach the literal cap")
	}
	belowExtras := append([]int(nil), extras...)
	aboveExtras := append([]int(nil), extras...)
	decremented, incremented := false, false
	for i := range extras {
		if !decremented && belowExtras[i] > 0 {
			belowExtras[i]--
			decremented = true
		}
		if !incremented && aboveExtras[i] < 31 {
			aboveExtras[i]++
			incremented = true
		}
	}
	if !decremented || !incremented {
		t.Fatal("could not form adjacent schema-valid service lengths")
	}
	below = cliAgentNostrOutputRows(t, count, belowExtras)
	above = cliAgentNostrOutputRows(t, count, aboveExtras)
	return below, exact, above
}

// Claim: canonical unique-account list outputs at1,048,575 and1,048,576 bytes
// succeed whole in JSON and plain modes, while1,048,577 emits only the exact
// refusal; limit: fake List proves serialization and delivery, not native reads.
func TestAgentNostrOutputCapCountsCompleteRepresentation(t *testing.T) {
	const outputLimit = 1048576
	component := bytes.Repeat([]byte{'x'}, outputLimit)
	if !agentNostrOutputFits(component) || agentNostrOutputFits(append(component, 'x')) {
		t.Fatal("bounded-output component did not use the inclusive literal byte cap")
	}
	base := cliAgentNostrOutputRows(t, 5000, nil)
	for _, jsonMode := range []bool{false, true} {
		lo, hi := 0, len(base)
		if len(cliExpectedAgentNostrList(base[:hi], jsonMode)) <= outputLimit {
			t.Fatal("bounded search list never exceeded the output cap")
		}
		for lo+1 < hi {
			mid := lo + (hi-lo)/2
			if len(cliExpectedAgentNostrList(base[:mid], jsonMode)) <= outputLimit {
				lo = mid
			} else {
				hi = mid
			}
		}
		if len(cliExpectedAgentNostrList(base[:lo], jsonMode)) == outputLimit {
			lo--
		}
		below, exact, above := cliAgentNostrCapVariants(t, base, lo, outputLimit, jsonMode)
		for _, tc := range []struct {
			name string
			rows []keyvault.AgentNostrPublic
			size int
		}{
			{name: "largest-valid-below", rows: below, size: outputLimit - 1},
			{name: "exact-cap", rows: exact, size: outputLimit},
			{name: "first-valid-above", rows: above, size: outputLimit + 1},
		} {
			t.Run(fmt.Sprintf("json-%t/%s", jsonMode, tc.name), func(t *testing.T) {
				fake := &agentNostrCLIFake{rows: tc.rows}
				oldFactory := newAgentNostrOperations
				newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
				t.Cleanup(func() { newAgentNostrOperations = oldFactory })
				args := []string{"agent-nostr", "list"}
				if jsonMode {
					args = append([]string{"--json"}, args...)
				}
				want := cliExpectedAgentNostrList(tc.rows, jsonMode)
				if len(want) != tc.size || len(want) <= 0 {
					t.Fatal("independent complete representation has the wrong adjacent boundary size")
				}
				var stdout, stderr bytes.Buffer
				code := run(args, &stdout, &stderr)
				if tc.size <= outputLimit {
					if code != exitOK || !bytes.Equal(stdout.Bytes(), want) || stderr.Len() != 0 || fake.calls == nil || len(fake.calls) != 1 || fake.calls[0] != "list" {
						t.Fatal("complete valid list at/below cap was truncated or refused")
					}
					return
				}
				if code != exitFailure || fake.calls == nil || len(fake.calls) != 1 || fake.calls[0] != "list" {
					t.Fatal("first valid list above the cap did not refuse once")
				}
				if jsonMode {
					refusal := agentNostrJSONError{Code: "agent_nostr_unavailable", Message: "Agent Nostr operation is unavailable.", Hint: "Preserve custody; do not change trust or retry privately."}
					expected, _ := json.MarshalIndent(agentNostrResponse{OK: false, Command: "agent-nostr", Error: &refusal}, "", "  ")
					expected = append(expected, '\n')
					if !bytes.Equal(stdout.Bytes(), expected) || stderr.Len() != 0 {
						t.Fatal("JSON overflow emitted partial success-list bytes or a non-contract refusal")
					}
				} else if stdout.Len() != 0 || stderr.String() != "error: agent_nostr_unavailable: Agent Nostr operation is unavailable.\nhint: Preserve custody; do not change trust or retry privately.\n" {
					t.Fatal("plain overflow emitted partial success-list bytes or a non-contract refusal")
				}
			})
		}
	}
}

func receiptJSON(t *testing.T, receipt keyvault.AgentNostrEnrollment) string {
	t.Helper()
	raw, err := keyvault.MarshalAgentNostrEnrollment(receipt)
	if err != nil {
		t.Fatal("cannot marshal test receipt")
	}
	return string(raw)
}

func TestAgentNostrFactoryFailureHasNoRawDiagnostic(t *testing.T) {
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { return nil, errors.New("private path must not appear") }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	var stdout, stderr bytes.Buffer
	code := run([]string{"agent-nostr", "list", "--json"}, &stdout, &stderr)
	var response agentNostrResponse
	if code != exitFailure || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != "agent_nostr_unavailable" || strings.Contains(stdout.String()+stderr.String(), "private path") {
		t.Fatal("factory failure leaked an internal diagnostic or used the wrong mapping")
	}
}
