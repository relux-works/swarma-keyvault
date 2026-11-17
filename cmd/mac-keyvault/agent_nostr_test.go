package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type agentNostrFixtureFile struct {
	MetadataJSON   string `json:"metadata_json"`
	EnrollmentJSON string `json:"enrollment_json"`
}

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
}

func (w *agentNostrTestWriter) Write(data []byte) (int, error) {
	w.calls++
	if len(w.outcomes) == 0 {
		return len(data), nil
	}
	outcome := w.outcomes[0]
	w.outcomes = w.outcomes[1:]
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

// Claim: the cap counts complete chosen-mode bytes and refuses list overflow
// before output; limit: schema-valid exact-boundary list reachability is a
// separate fixture sizing concern.
func TestAgentNostrOutputCapCountsCompleteRepresentation(t *testing.T) {
	limit := bytes.Repeat([]byte{'x'}, keyvault.AgentNostrMaxPublicOutput)
	if !agentNostrOutputFits(limit) || agentNostrOutputFits(append(limit, 'x')) {
		t.Fatal("public output cap is not inclusive at exactly one MiB")
	}
	rows := make([]keyvault.AgentNostrPublic, 0, 4200)
	base, _ := cliAgentNostrFixture(t)
	for i := 1; i <= 4200; i++ {
		record := base.Record
		record.Version = i
		metadata, err := keyvault.MarshalAgentNostrRecord(record)
		if err != nil {
			t.Fatal("cannot make canonical unique-version row")
		}
		rows = append(rows, keyvault.AgentNostrPublicResult(record, metadata))
	}
	fake := &agentNostrCLIFake{rows: rows}
	oldFactory := newAgentNostrOperations
	newAgentNostrOperations = func() (agentNostrOperations, error) { return fake, nil }
	t.Cleanup(func() { newAgentNostrOperations = oldFactory })
	for _, jsonMode := range []bool{true, false} {
		args := []string{"agent-nostr", "list"}
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != exitFailure || len(stdout.Bytes()) > 2000 {
			t.Fatal("oversize list streamed success bytes or failed to return a bounded unavailable result")
		}
		if jsonMode && (len(stdout.Bytes()) == 0 || !strings.Contains(stdout.String(), "agent_nostr_unavailable") || stderr.Len() != 0) {
			t.Fatal("JSON list overflow did not return one bounded unavailable envelope")
		}
		if !jsonMode && (stdout.Len() != 0 || !strings.Contains(stderr.String(), "agent_nostr_unavailable")) {
			t.Fatal("plain list overflow streamed success bytes or missed the fixed refusal")
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
