package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// SHA-256 of the exact bytes of the frozen public v1 record file (system shasum,
// not product code); that file is the canonical encoding of its own record.
const recoveryPubFixtureDigest = "7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c"

// What `recovery pub` printed for this record before the digest was added,
// written out literally from the frozen public fixture, so the extension is
// measured against the old output and not against the current formatter.
const recoveryPubOldPlain = "group: test/recovery@1\n" +
	"nostr_record: test/nostr@2\n" +
	"namecoin_record: test/namecoin@1\n" +
	"npub: npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h\n" +
	"public_key: d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573\n" +
	"namecoin_xpub: xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es\n" +
	"namecoin_origin: [57471a66/84h/7h/0h]\n" +
	"nostr_presence: none\n" +
	"namecoin_presence: biometry-any\n" +
	"private_export: false\n"

const recoveryPubNewPlain = recoveryPubOldPlain +
	"group_id: 00000000000000000000000000000000\n" +
	"pair_metadata_sha256: " + recoveryPubFixtureDigest + "\n"

type recoveryPubOperations struct {
	record keyvault.RecoveryRecord
	err    error
	calls  []string
}

func (f *recoveryPubOperations) Create(keyvault.RecoveryRequest, keyvault.RecoveryTerminal, bool) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "create")
	return keyvault.RecoveryRecord{}, errors.New("unused")
}
func (f *recoveryPubOperations) Describe(string, int) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "public")
	return f.record, f.err
}
func (f *recoveryPubOperations) Plan(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
	f.calls = append(f.calls, "plan")
	return keyvault.RecoveryPlan{}, errors.New("unused")
}
func (f *recoveryPubOperations) Delete(keyvault.RecoveryDeleteRequest, keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "delete")
	return keyvault.RecoveryRecord{}, errors.New("unused")
}

// recoveryPubFixture returns the frozen public v1 record and its file bytes.
func recoveryPubFixture(t *testing.T) (keyvault.RecoveryRecord, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/keyvault/testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	var r keyvault.RecoveryRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r, raw
}

// recoveryValidPublicRecord returns the frozen public v1 record addressed as the
// given service and version (the v1 schema inherits its one service, so any valid
// service is a valid record). It stands in for what the real manager returns.
func recoveryValidPublicRecord(service string, version int) keyvault.RecoveryRecord {
	raw, err := os.ReadFile("../../internal/keyvault/testdata/recovery/v1-public-record.json")
	if err != nil {
		panic(err)
	}
	var r keyvault.RecoveryRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		panic(err)
	}
	r.Service, r.Version = service, version
	return r
}

// installRecoveryPub routes the recovery command to the fake and counts owner
// terminal openings; a public lookup must never open one.
func installRecoveryPub(t *testing.T, f *recoveryPubOperations) *int {
	t.Helper()
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock = oldB, oldM, oldT, oldL
	})
	opened := 0
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return f }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { opened++; return recoveryReceiptTerminal{}, nil }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	return &opened
}

func runRecoveryPub(asJSON bool) (int, string, string) {
	argv := []string{"recovery", "pub", "test", "--version", "1"}
	if asJSON {
		argv = append([]string{"--json"}, argv...)
	}
	var out, diagnostic bytes.Buffer
	code := run(argv, &out, &diagnostic)
	return code, out.String(), diagnostic.String()
}

// Claim: the plain `recovery pub` receipt keeps every earlier line byte for byte
// and in order, and appends exactly the group id and the pair metadata digest,
// which equals the independent literal. It is a lookup only: one backend
// describe, no owner terminal. Limit: fake operations and one frozen record.
func TestRecoveryPubPlainPrintsGroupIDAndDigest(t *testing.T) {
	record, _ := recoveryPubFixture(t)
	f := &recoveryPubOperations{record: record}
	opened := installRecoveryPub(t, f)
	code, out, diagnostic := runRecoveryPub(false)
	if code != exitOK || diagnostic != "" {
		t.Fatalf("lookup failed: %d %q", code, diagnostic)
	}
	if out != recoveryPubNewPlain {
		t.Fatalf("plain receipt differs from the golden:\n%s", out)
	}
	if !strings.HasPrefix(out, recoveryPubOldPlain) {
		t.Fatal("an earlier line changed or moved")
	}
	if !reflect.DeepEqual(f.calls, []string{"public"}) || *opened != 0 {
		t.Fatalf("a public lookup did more than one describe or opened a terminal: %v %d", f.calls, *opened)
	}
}

// Claim: the JSON result keeps every earlier member (the result minus the new
// member equals the frozen public record exactly, and the earlier consumer shape
// still decodes to that record) and adds only pair_metadata_sha256. The
// top-level envelope is unchanged. Limit: decoded comparison, not byte layout.
func TestRecoveryPubJSONExtendsTheResult(t *testing.T) {
	record, raw := recoveryPubFixture(t)
	installRecoveryPub(t, &recoveryPubOperations{record: record})
	code, out, diagnostic := runRecoveryPub(true)
	if code != exitOK || diagnostic != "" {
		t.Fatalf("lookup failed: %d %q", code, diagnostic)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err)
	}
	if keys := sortedKeys(envelope); !reflect.DeepEqual(keys, []string{"command", "ok", "result"}) || envelope["ok"] != true {
		t.Fatalf("envelope changed: %v", keys)
	}
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		t.Fatal("result is not an object")
	}
	if result["pair_metadata_sha256"] != recoveryPubFixtureDigest || result["group_id"] != "00000000000000000000000000000000" {
		t.Fatalf("digest or group id wrong: %v %v", result["pair_metadata_sha256"], result["group_id"])
	}
	delete(result, "pair_metadata_sha256")
	var before map[string]any
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, before) {
		t.Fatal("an earlier member of the result changed")
	}
	var earlier struct {
		OK      bool                    `json:"ok"`
		Command string                  `json:"command"`
		Result  keyvault.RecoveryRecord `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &earlier); err != nil || !earlier.OK || !reflect.DeepEqual(earlier.Result, record) {
		t.Fatalf("the earlier consumer shape no longer decodes to the record: %v", err)
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Claim: no group id and no digest are printed, in plain or JSON mode, when the
// pair is missing, the backend fails, or the record is one the attach would not
// accept; each ends non-zero with its own bounded code. The valid control prints
// both, so a command that prints nothing, or always fails, does not pass.
// Limit: fake operations.
func TestRecoveryPubPrintsNoDigestWithoutAValidPair(t *testing.T) {
	valid, _ := recoveryPubFixture(t)
	cases := []struct {
		name   string
		record keyvault.RecoveryRecord
		err    error
		want   string
	}{
		{"missing", keyvault.RecoveryRecord{}, keyvault.ErrNotFound, "not_found"},
		{"backend", keyvault.RecoveryRecord{}, errors.New("synthetic backend detail"), "recovery_backend_unavailable"},
		{"invalid", keyvault.RecoveryRecord{Service: "test", Version: 1}, nil, "invalid_record"},
	}
	for _, jsonMode := range []bool{false, true} {
		installRecoveryPub(t, &recoveryPubOperations{record: valid})
		code, out, _ := runRecoveryPub(jsonMode)
		if code != exitOK || !strings.Contains(out, "pair_metadata_sha256") || !strings.Contains(out, "group_id") {
			t.Fatal("positive control failed: a valid pair did not print both")
		}
		for _, c := range cases {
			installRecoveryPub(t, &recoveryPubOperations{record: c.record, err: c.err})
			code, out, diagnostic := runRecoveryPub(jsonMode)
			all := out + diagnostic
			if code == exitOK || strings.Contains(all, "pair_metadata_sha256") || strings.Contains(all, "group_id") || strings.Contains(all, recoveryPubFixtureDigest) {
				t.Fatalf("%s json=%v: exit %d printed a digest or group id: %q", c.name, jsonMode, code, all)
			}
			if !strings.Contains(all, c.want) || strings.Contains(all, "synthetic backend detail") {
				t.Fatalf("%s json=%v: wrong or unbounded refusal: %q", c.name, jsonMode, all)
			}
		}
	}
}

// unexpectedPubKeys lists the plain-text keys and JSON result members that are
// not in the closed public set. Anything else, in particular any private value,
// is reported.
func unexpectedPubKeys(plain string, result map[string]any) []string {
	allowedPlain := map[string]bool{"group": true, "nostr_record": true, "namecoin_record": true, "npub": true, "public_key": true,
		"namecoin_xpub": true, "namecoin_origin": true, "nostr_presence": true, "namecoin_presence": true, "private_export": true,
		"group_id": true, "pair_metadata_sha256": true}
	allowedResult := map[string]bool{"schema": true, "group_id": true, "service": true, "version": true, "created": true, "nostr": true,
		"namecoin": true, "pair_metadata_sha256": true}
	allowedPurpose := map[string]bool{"service": true, "purpose": true, "version": true, "path": true, "algorithm": true, "presence": true,
		"public_key": true, "npub": true, "xpub": true, "origin": true, "wrapping_point": true, "wrapping_fingerprint": true}
	var bad []string
	for _, line := range strings.Split(strings.TrimSuffix(plain, "\n"), "\n") {
		if plain == "" {
			break
		}
		key, _, found := strings.Cut(line, ": ")
		if !found || !allowedPlain[key] {
			bad = append(bad, "plain:"+key)
		}
	}
	for key, value := range result {
		if !allowedResult[key] {
			bad = append(bad, "result:"+key)
		}
		if purpose, ok := value.(map[string]any); ok {
			for inner := range purpose {
				if !allowedPurpose[inner] {
					bad = append(bad, "result:"+key+"."+inner)
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// Claim: the public receipt, plain and JSON, contains only the closed set of
// public keys (no word, scalar, ciphertext, blob or any other member), writes
// nothing to the diagnostic stream, and never opens the owner terminal. The key
// checker is first shown to flag a planted private-looking line and member
// (control plant). Limit: the fake record has only public fields by type; this
// pins the printer's own output shape.
func TestRecoveryPubOutputIsClosedAndPublic(t *testing.T) {
	if got := unexpectedPubKeys("mnemonic: x\n", map[string]any{"nostr": map[string]any{"enclave_blob": "x"}, "seed": 1}); !reflect.DeepEqual(got, []string{"plain:mnemonic", "result:nostr.enclave_blob", "result:seed"}) {
		t.Fatalf("the key checker missed a planted private-looking key: %v", got)
	}
	record, _ := recoveryPubFixture(t)
	f := &recoveryPubOperations{record: record}
	opened := installRecoveryPub(t, f)
	code, plain, diagnostic := runRecoveryPub(false)
	jsonCode, jsonOut, jsonDiagnostic := runRecoveryPub(true)
	if code != exitOK || jsonCode != exitOK || diagnostic != "" || jsonDiagnostic != "" || *opened != 0 {
		t.Fatalf("unexpected exit, diagnostic or terminal: %d %d %q %q %d", code, jsonCode, diagnostic, jsonDiagnostic, *opened)
	}
	var envelope struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &envelope); err != nil {
		t.Fatal(err)
	}
	if bad := unexpectedPubKeys(plain, envelope.Result); len(bad) != 0 {
		t.Fatalf("keys outside the closed public set: %v", bad)
	}
	for _, token := range []string{"mnemonic", "phrase", "secret", "seed", "scalar", "ciphertext", "enclave_blob", "nsec"} {
		if strings.Contains(strings.ToLower(plain+jsonOut), token) {
			t.Fatalf("output contains %q", token)
		}
	}
}
