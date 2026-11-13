package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// Public fixture pins only (the repository's published retained-pair fixture).
const (
	rgNPub   = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h"
	rgXPub   = "xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es"
	rgOrigin = "[57471a66/84h/7h/0h]"
)

var rgFlagOrder = []string{"nostr-identity", "namecoin-identity", "version", "nostr-version", "namecoin-version", "grants-identity", "grants-version",
	"expected-group-id", "expected-pair-metadata-sha256", "expected-npub", "expected-namecoin-xpub", "expected-origin"}

func rgAttachValues() map[string]string {
	return map[string]string{"nostr-identity": "test", "namecoin-identity": "test", "version": "1", "nostr-version": "2", "namecoin-version": "1",
		"grants-identity": "example-root", "grants-version": "1", "expected-group-id": strings.Repeat("0", 32),
		"expected-pair-metadata-sha256": strings.Repeat("a", 64), "expected-npub": rgNPub, "expected-namecoin-xpub": rgXPub, "expected-origin": rgOrigin}
}

func rgArgs(op string, values map[string]string, order []string) []string {
	args := []string{op}
	for _, name := range order {
		if v, ok := values[name]; ok {
			args = append(args, "--"+name, v)
		}
	}
	return args
}

type rgFake struct {
	attachCalls []keyvault.RootGrantsAttachRequest
	attachOut   keyvault.RootGrantsAttachResult
	attachErr   error
	lookupCalls [][2]any
	lookupOut   keyvault.RootGrantsPublicReceipt
	lookupErr   error
}

// rgFixture replaces the two production routes and turns every custody
// construction of the pair family into a test failure: the root-grants commands
// must never build a backend, manager, terminal or lock.
func rgFixture(t *testing.T) *rgFake {
	t.Helper()
	f := &rgFake{}
	oldAttach, oldLookup := attachRootGrants, lookupRootGrants
	oldBackend, oldManager, oldTerminal, oldLock := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock
	t.Cleanup(func() {
		attachRootGrants, lookupRootGrants = oldAttach, oldLookup
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock = oldBackend, oldManager, oldTerminal, oldLock
	})
	attachRootGrants = func(_ context.Context, q keyvault.RootGrantsAttachRequest) (keyvault.RootGrantsAttachResult, error) {
		f.attachCalls = append(f.attachCalls, q)
		return f.attachOut, f.attachErr
	}
	lookupRootGrants = func(_ context.Context, identity string, version int) (keyvault.RootGrantsPublicReceipt, error) {
		f.lookupCalls = append(f.lookupCalls, [2]any{identity, version})
		return f.lookupOut, f.lookupErr
	}
	newRecoveryBackend = func() keyvault.RecoveryBackend { t.Fatal("root grants constructed the pair backend"); return nil }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations {
		t.Fatal("root grants constructed the recovery manager")
		return nil
	}
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) {
		t.Fatal("root grants opened the pair terminal")
		return nil, nil
	}
	vaultLock = func() (keyvault.FileLock, error) {
		t.Fatal("root grants resolved the pair lock")
		return keyvault.FileLock{}, nil
	}
	return f
}

type rgReply struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
	} `json:"error"`
}

func rgInvoke(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func rgProjection() keyvault.RootGrantsProjection {
	return keyvault.RootGrantsProjection{Namespace: keyvault.RootGrantsNamespace, Account: "example-root/root-grants@1", Profile: "namecoin-landlord-root/1",
		Derivation: "bip85-hdseed-wif/1", Path: "m/83696968h/2h/7h", PublicKey: strings.Repeat("ab", 32), SealPublicKey: "02" + strings.Repeat("ab", 32), SealScript: "76a914" + strings.Repeat("cd", 20) + "88ac",
		Pair: keyvault.RootGrantsPairBinding{Schema: "keyvault-recovery/2", Service: "test", Version: 1}}
}

// Claim: every malformed, missing, repeated, unknown or mixed form is a usage
// error (exit 2, code usage, the family's usage hint) decided before the attach
// route: zero attach calls, no custody construction, and nothing on stderr (the
// notice is printed only once every flag was admitted). The names of words, scalars,
// paths, namespaces, helper locations, timeouts and creation times are among the
// unknown flags, so no secret or fixed-boundary source exists on the command line.
func TestRootGrantsAttachCLIUsageNeverReachesTheVault(t *testing.T) {
	f := rgFixture(t)
	type c struct {
		name string
		args []string
	}
	var cases []c
	base := rgAttachValues()
	for _, name := range rgFlagOrder {
		missing := rgAttachValues()
		delete(missing, name)
		cases = append(cases, c{"missing-" + name, rgArgs("attach-root-grants", missing, rgFlagOrder)})
		repeated := append(rgArgs("attach-root-grants", base, rgFlagOrder), "--"+name, base[name])
		cases = append(cases, c{"repeated-" + name, repeated})
		valueless := append(rgArgs("attach-root-grants", func() map[string]string { m := rgAttachValues(); delete(m, name); return m }(), rgFlagOrder), "--"+name)
		cases = append(cases, c{"valueless-" + name, valueless})
	}
	for _, unknown := range []string{"service", "mnemonic", "words", "phrase", "passphrase", "seed", "scalar", "path", "namespace", "helper", "timeout", "created", "index", "env", "stdin", "file", "format", "yes", "force"} {
		cases = append(cases, c{"unknown-" + unknown, append(rgArgs("attach-root-grants", base, rgFlagOrder), "--"+unknown, "x")})
	}
	cases = append(cases, c{"positional", append(rgArgs("attach-root-grants", base, rgFlagOrder), "extra")})
	for name, bad := range map[string]map[string]string{
		"identity-uppercase":      {"nostr-identity": "Test"},
		"identity-empty":          {"namecoin-identity": ""},
		"grants-identity-long":    {"grants-identity": strings.Repeat("a", 41)},
		"generation-zero":         {"grants-version": "0"},
		"generation-leading-zero": {"grants-version": "01"},
		"generation-plus":         {"grants-version": "+1"},
		"generation-negative":     {"version": "-1"},
		"generation-over-max":     {"nostr-version": "2147483648"},
		"generation-text":         {"namecoin-version": "one"},
		"group-id-uppercase":      {"expected-group-id": strings.Repeat("A", 32)},
		"group-id-short":          {"expected-group-id": strings.Repeat("0", 31)},
		"sha-short":               {"expected-pair-metadata-sha256": strings.Repeat("a", 63)},
		"sha-uppercase":           {"expected-pair-metadata-sha256": strings.Repeat("A", 64)},
		"npub-garbled":            {"expected-npub": rgNPub[:62] + "x"},
		"npub-not-npub":           {"expected-npub": strings.Repeat("a", 63)},
		"xpub-garbled":            {"expected-namecoin-xpub": rgXPub[:110] + "1"},
		"origin-wrong-path":       {"expected-origin": "[57471a66/84h/7h/1h]"},
		"origin-uppercase":        {"expected-origin": "[57471A66/84h/7h/0h]"},
	} {
		values := rgAttachValues()
		for k, v := range bad {
			values[k] = v
		}
		cases = append(cases, c{name, rgArgs("attach-root-grants", values, rgFlagOrder)})
	}
	for _, tc := range cases {
		for _, jsonMode := range []bool{true, false} {
			args := append([]string{"recovery"}, tc.args...)
			if jsonMode {
				args = append([]string{"--json"}, args...)
			}
			code, stdout, stderr := rgInvoke(args...)
			if code != exitUsage {
				t.Fatalf("%s (json=%v): exit %d, want 2: %s%s", tc.name, jsonMode, code, stdout, stderr)
			}
			if jsonMode {
				var reply rgReply
				if json.Unmarshal([]byte(stdout), &reply) != nil || reply.OK || reply.Error == nil || reply.Error.Code != "usage" || reply.Error.Hint != usageLines["recovery"] || stderr != "" {
					t.Fatalf("%s: not the usage envelope: %s%s", tc.name, stdout, stderr)
				}
			} else if stdout != "" || strings.Contains(stderr, "follow the review window") {
				t.Fatalf("%s: usage error printed the attach notice or stdout: %q %q", tc.name, stdout, stderr)
			}
		}
	}
	if len(f.attachCalls) != 0 {
		t.Fatal("a usage error reached the attach route")
	}
}

// Claim: a fully specified invocation reaches the attach route exactly once with
// every public parameter, prints only the fixed notice on stderr and exactly the
// contract receipt on stdout (JSON: ok/command/result in the family envelope; text:
// the same facts), and exits 0. No ciphertext, wrapping, scalar or path member exists.
func TestRootGrantsAttachCLIStoredReceipt(t *testing.T) {
	for _, jsonMode := range []bool{true, false} {
		f := rgFixture(t)
		f.attachOut = keyvault.RootGrantsAttachResult{Outcome: "stored", Root: rgProjection(), PairUnchanged: true}
		args := append([]string{"recovery"}, rgArgs("attach-root-grants", rgAttachValues(), rgFlagOrder)...)
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		code, stdout, stderr := rgInvoke(args...)
		if code != exitOK || stderr != "root grants attach: follow the review window and the terminal prompts\n" {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		if len(f.attachCalls) != 1 {
			t.Fatal("attach route not called exactly once")
		}
		want := keyvault.RootGrantsAttachRequest{NostrIdentity: "test", NamecoinIdentity: "test", Version: 1, NostrVersion: 2, NamecoinVersion: 1, GrantsIdentity: "example-root", GrantsVersion: 1,
			ExpectedGroupID: strings.Repeat("0", 32), ExpectedPairMetadataSHA256: strings.Repeat("a", 64), ExpectedNPub: rgNPub, ExpectedNamecoinXPub: rgXPub, ExpectedOrigin: rgOrigin}
		if f.attachCalls[0] != want {
			t.Fatalf("request differs: %+v", f.attachCalls[0])
		}
		if !jsonMode {
			for _, line := range []string{"outcome: stored\n", "root_grants: example-root/root-grants@1\n", "private_export: false\n", "pair_unchanged: true\n", "storage: enclave-wrapped-keychain\n"} {
				if !strings.Contains(stdout, line) {
					t.Fatalf("text receipt lacks %q: %s", line, stdout)
				}
			}
			continue
		}
		var reply struct {
			OK      bool                       `json:"ok"`
			Command string                     `json:"command"`
			Result  keyvault.RootGrantsReceipt `json:"result"`
			Error   any                        `json:"error"`
		}
		if json.Unmarshal([]byte(stdout), &reply) != nil || !reply.OK || reply.Command != "recovery" || reply.Error != nil {
			t.Fatalf("envelope: %s", stdout)
		}
		r := reply.Result
		if r.Schema != "keyvault-root-grants-receipt/1" || r.Mode != "attach" || r.Outcome != "stored" || r.Storage != "enclave-wrapped-keychain" ||
			r.Presence != "biometry-any-per-signature" || r.PrivateExport || !r.PairUnchanged || r.Root != rgProjection() {
			t.Fatalf("receipt differs from the contract: %s", stdout)
		}
		for _, forbidden := range []string{"ciphertext", "enclave_blob", "wrapping", "scalar", "envelope"} {
			if strings.Contains(stdout, forbidden) {
				t.Fatalf("receipt exposes %s", forbidden)
			}
		}
	}
}

// Claim: the failure map is the contract's: a closed not_applied outcome exits 3
// with ok=false, the closed code and no result; every other outcome (unknown, an
// unrecognized state, an untyped error) exits 1 with ok=false, the UNCONFIRMED
// reference and no retry advice. Text mode keeps the same split on stderr.
func TestRootGrantsAttachCLIFailureMap(t *testing.T) {
	refusals := []string{"retained_record_mismatch", "lock_unavailable", "duplicate", "inventory_changed", "code_not_admitted", "acl_refused", "wrapping_policy_refused",
		"invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "public_pin_mismatch", "input_canceled", "canceled", "timeout"}
	for _, code := range refusals {
		for _, jsonMode := range []bool{true, false} {
			var out, errb bytes.Buffer
			o := output{command: "recovery", json: jsonMode, stdout: &out, stderr: &errb}
			got := rootGrantsAttachFailureReceipt(o, keyvault.RootGrantsAttachFailure{Code: code, Phase: "preflight", Outcome: "not_applied", Message: "Root grants attachment refused; preserve existing items"})
			if got != exitRefused {
				t.Fatalf("%s: exit %d, want 3", code, got)
			}
			if jsonMode {
				var reply rgReply
				if json.Unmarshal(out.Bytes(), &reply) != nil || reply.OK || reply.Error == nil || reply.Error.Code != code || reply.Result != nil || errb.Len() != 0 {
					t.Fatalf("%s: envelope %s", code, out.String())
				}
			} else if out.Len() != 0 || !strings.Contains(errb.String(), "error: "+code+": ") {
				t.Fatalf("%s: text %q %q", code, out.String(), errb.String())
			}
		}
	}
	reference := rgProjection()
	for name, failure := range map[string]keyvault.RootGrantsAttachFailure{
		"unknown":            {Code: "mutation_unknown", Phase: "readback", Outcome: "unknown", Message: "Root grants attachment outcome unknown; do not retry or delete", Reference: &reference},
		"unrecognized-state": {Code: "mutation_unknown", Phase: "commit", Outcome: "stored", Message: "x", Reference: &reference},
		"empty-state":        {Code: "mutation_unknown", Phase: "commit", Message: "x"},
	} {
		for _, jsonMode := range []bool{true, false} {
			var out, errb bytes.Buffer
			o := output{command: "recovery", json: jsonMode, stdout: &out, stderr: &errb}
			if got := rootGrantsAttachFailureReceipt(o, failure); got != exitFailure {
				t.Fatalf("%s: exit %d, want 1", name, got)
			}
			if jsonMode {
				var reply struct {
					OK     bool                    `json:"ok"`
					Result rootGrantsUnknownResult `json:"result"`
					Error  *struct{ Code string }  `json:"error"`
				}
				if json.Unmarshal(out.Bytes(), &reply) != nil || reply.OK || reply.Error == nil || reply.Error.Code != "mutation_unknown" ||
					reply.Result.Outcome != "unknown" || reply.Result.Operation != "attach-root-grants" || (failure.Reference != nil && (reply.Result.Reference == nil || *reply.Result.Reference != reference)) {
					t.Fatalf("%s: envelope %s", name, out.String())
				}
			} else if !strings.Contains(errb.String(), "error: mutation_unknown") || strings.Contains(errb.String(), "safe to repeat") {
				t.Fatalf("%s: text %q", name, errb.String())
			}
		}
	}
}

// Claim: the real CLI maps an attach error that is not a typed attach failure to
// UNKNOWN (exit 1), because it may follow a possible add; a typed refusal from the
// route cannot be forged here, it is covered where the error type is built.
func TestRootGrantsAttachCLIUntypedErrorIsUnknown(t *testing.T) {
	f := rgFixture(t)
	f.attachErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	code, stdout, stderr := rgInvoke(append([]string{"--json", "recovery"}, rgArgs("attach-root-grants", rgAttachValues(), rgFlagOrder)...)...)
	var reply rgReply
	if code != exitFailure || json.Unmarshal([]byte(stdout), &reply) != nil || reply.OK || reply.Error == nil || reply.Error.Code != "mutation_unknown" ||
		strings.Contains(stdout+stderr, "PUBLIC_TEST_PRIVATE_SENTINEL") {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
}

type rgFailingWriter struct{}

func (rgFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
}

// Claim: a stored attach whose receipt cannot be written is exit 1 with one bounded
// stderr diagnostic naming the UNCONFIRMED reference and forbidding retry/delete;
// it is never exit 0 and never a refusal. A refusal whose result cannot be written
// is also exit 1 with a bounded diagnostic. No writer error text is echoed.
func TestRootGrantsAttachCLIReceiptDeliveryFailure(t *testing.T) {
	for _, jsonMode := range []bool{true, false} {
		f := rgFixture(t)
		f.attachOut = keyvault.RootGrantsAttachResult{Outcome: "stored", Root: rgProjection(), PairUnchanged: true}
		args := append([]string{"recovery"}, rgArgs("attach-root-grants", rgAttachValues(), rgFlagOrder)...)
		if jsonMode {
			args = append([]string{"--json"}, args...)
		}
		var errb bytes.Buffer
		code := run(args, rgFailingWriter{}, &errb)
		diagnostic := errb.String()
		if code != exitFailure || !strings.Contains(diagnostic, "receipt_unavailable") || !strings.Contains(diagnostic, "example-root/root-grants@1") ||
			!strings.Contains(diagnostic, "do not retry or delete") || strings.Contains(diagnostic, "PUBLIC_TEST_PRIVATE_SENTINEL") {
			t.Fatalf("json=%v exit %d diagnostic %q", jsonMode, code, diagnostic)
		}
	}
	var errb bytes.Buffer
	o := output{command: "recovery", json: true, stdout: rgFailingWriter{}, stderr: &errb}
	if code := rootGrantsAttachFailureReceipt(o, keyvault.RootGrantsAttachFailure{Code: "duplicate", Outcome: "not_applied"}); code != exitFailure || !strings.Contains(errb.String(), "refusal=duplicate") {
		t.Fatalf("undeliverable refusal: exit %d %q", code, errb.String())
	}
}

func rgPubValues() map[string]string {
	return map[string]string{"grants-identity": "example-root", "grants-version": "1"}
}

func rgPubReceipt() keyvault.RootGrantsPublicReceipt {
	value := `{"nostr":{"names":{"_":"` + strings.Repeat("11", 32) + `"}},"swarma":{"landlord":{"grant":"` + strings.Repeat("ab", 32) + `"}}}`
	return keyvault.RootGrantsPublicReceipt{Schema: keyvault.RootGrantsPublicSchema, RootGrantsPublicExport: keyvault.RootGrantsPublicExport{
		Root: rgProjection(), IDValueUTF8: value, IDValueByteLength: len(value), IDValueSHA256: strings.Repeat("e", 64)}}
}

// Claim: the public export admits exactly its flags: usage errors (missing,
// repeated, unknown, --format other than id-value, --format id-value with --json)
// never reach the lookup. Valid forms: JSON returns the receipt; text prints the
// facts; --format id-value writes ONLY the exact value bytes, no LF, nothing on
// stderr.
func TestRootGrantsPubCLI(t *testing.T) {
	f := rgFixture(t)
	f.lookupOut = rgPubReceipt()
	order := []string{"grants-identity", "grants-version", "format"}
	for name, args := range map[string][]string{
		"missing-identity":     rgArgs("root-grants-pub", map[string]string{"grants-version": "1"}, order),
		"missing-version":      rgArgs("root-grants-pub", map[string]string{"grants-identity": "example-root"}, order),
		"repeated-identity":    append(rgArgs("root-grants-pub", rgPubValues(), order), "--grants-identity", "example-root"),
		"unknown-flag":         append(rgArgs("root-grants-pub", rgPubValues(), order), "--path", "x"),
		"positional":           append(rgArgs("root-grants-pub", rgPubValues(), order), "extra"),
		"bad-identity":         rgArgs("root-grants-pub", map[string]string{"grants-identity": "Bad", "grants-version": "1"}, order),
		"bad-generation":       rgArgs("root-grants-pub", map[string]string{"grants-identity": "example-root", "grants-version": "00"}, order),
		"unknown-format":       rgArgs("root-grants-pub", map[string]string{"grants-identity": "example-root", "grants-version": "1", "format": "json"}, order),
		"empty-format":         rgArgs("root-grants-pub", map[string]string{"grants-identity": "example-root", "grants-version": "1", "format": ""}, order),
		"repeated-format":      append(rgArgs("root-grants-pub", map[string]string{"grants-identity": "example-root", "grants-version": "1", "format": "id-value"}, order), "--format", "id-value"),
		"legacy-pair-position": {"root-grants-pub", "example-root", "--version", "1"},
	} {
		if code, stdout, stderr := rgInvoke(append([]string{"recovery"}, args...)...); code != exitUsage || strings.Contains(stdout+stderr, `{"nostr"`) {
			t.Fatalf("%s: exit %d %q %q", name, code, stdout, stderr)
		}
	}
	// --json together with --format id-value is a usage error as well.
	idValue := map[string]string{"grants-identity": "example-root", "grants-version": "1", "format": "id-value"}
	if code, stdout, _ := rgInvoke(append([]string{"--json", "recovery"}, rgArgs("root-grants-pub", idValue, order)...)...); code != exitUsage || !strings.Contains(stdout, `"usage"`) {
		t.Fatalf("--json with --format id-value: exit %d %s", code, stdout)
	}
	if len(f.lookupCalls) != 0 {
		t.Fatal("a usage error reached the lookup")
	}

	code, stdout, stderr := rgInvoke(append([]string{"recovery"}, rgArgs("root-grants-pub", idValue, order)...)...)
	if code != exitOK || stdout != f.lookupOut.IDValueUTF8 || stderr != "" || strings.HasSuffix(stdout, "\n") {
		t.Fatalf("id-value output must be exactly the value bytes: exit %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = rgInvoke(append([]string{"--json", "recovery"}, rgArgs("root-grants-pub", rgPubValues(), order)...)...)
	var reply struct {
		OK     bool                             `json:"ok"`
		Result keyvault.RootGrantsPublicReceipt `json:"result"`
	}
	if code != exitOK || stderr != "" || json.Unmarshal([]byte(stdout), &reply) != nil || !reply.OK || reply.Result.Schema != "keyvault-root-grants-public/1" ||
		reply.Result.IDValueUTF8 != f.lookupOut.IDValueUTF8 || reply.Result.IDValueByteLength != len(f.lookupOut.IDValueUTF8) || reply.Result.IDValueSHA256 != strings.Repeat("e", 64) {
		t.Fatalf("json export: exit %d %s", code, stdout)
	}
	code, stdout, _ = rgInvoke(append([]string{"recovery"}, rgArgs("root-grants-pub", rgPubValues(), order)...)...)
	if code != exitOK || !strings.Contains(stdout, "public_key: "+strings.Repeat("ab", 32)+"\n") || !strings.Contains(stdout, "id_value_utf8: "+f.lookupOut.IDValueUTF8+"\n") {
		t.Fatalf("text export: exit %d %s", code, stdout)
	}
	if len(f.lookupCalls) != 3 || f.lookupCalls[0] != [2]any{"example-root", 1} {
		t.Fatalf("lookup calls: %v", f.lookupCalls)
	}

	// Refusals produce no value bytes; a failed write is exit 1 with a bounded line.
	for name, c := range map[string]struct {
		err  error
		want int
	}{
		"not-found":    {keyvault.ErrNotFound, exitFailure},
		"refusal":      {&keyvault.Refusal{Code: "recovery_retained_record_mismatch", Message: "m", Hint: "h"}, exitRefused},
		"generic":      {errors.New("PUBLIC_TEST_PRIVATE_SENTINEL"), exitFailure},
		"status-error": {&keyvault.StatusError{Op: "x", Status: -25293}, exitFailure},
	} {
		f.lookupErr = c.err
		code, stdout, stderr := rgInvoke(append([]string{"recovery"}, rgArgs("root-grants-pub", idValue, order)...)...)
		if code != c.want || strings.Contains(stdout+stderr, "PUBLIC_TEST_PRIVATE_SENTINEL") || strings.Contains(stdout, `{"nostr"`) {
			t.Fatalf("%s: exit %d %q %q", name, code, stdout, stderr)
		}
	}
	f.lookupErr = nil
	var errb bytes.Buffer
	if code := run(append([]string{"recovery"}, rgArgs("root-grants-pub", idValue, order)...), rgFailingWriter{}, &errb); code != exitFailure || !strings.Contains(errb.String(), "recovery_public_output_unavailable") {
		t.Fatalf("partial output: exit %d %q", code, errb.String())
	}
}

// Claim: the usage line names both operations, an unrelated operation is still
// refused, and the production recovery backend exposes the attachment inventory
// that makes `recovery delete` refuse an attached pair (the delete refusal itself
// is covered in the keyvault package). Limit: a type check of the default factory.
func TestRecoveryUsageAndDeleteInventoryWiring(t *testing.T) {
	if !strings.Contains(recoveryUsage, "recovery attach-root-grants") || !strings.Contains(recoveryUsage, "recovery root-grants-pub") {
		t.Fatal("usage does not list the root-grants operations")
	}
	if code, _, _ := rgInvoke("--json", "recovery", "export-private"); code != exitUsage {
		t.Fatal("unrelated recovery operation admitted")
	}
	if _, ok := newRecoveryBackend().(keyvault.RootGrantsAttachmentInventory); !ok {
		t.Fatal("the default recovery backend cannot see root attachments; delete would not refuse an attached pair")
	}
}

// rootGrantsCLISourceInputs lists every non-flag input source found in the source.
func rootGrantsCLISourceInputs(src string) []string {
	var found []string
	for _, forbidden := range []string{"os.Stdin", "Getenv", "LookupEnv", "Environ(", "os.ReadFile", "os.Open", "ioutil", "os.Args", "bufio", "exec.Command"} {
		if strings.Contains(src, forbidden) {
			found = append(found, forbidden)
		}
	}
	return found
}

// Claim: the root-grants command file has no input source other than its flags:
// no stdin, environment, file or raw argument access, so no word, scalar, path or
// namespace can reach the attach through them. A source guard with control plants
// (each forbidden access appended must be reported); the flag-set tests above cover
// the argument side.
func TestRootGrantsCLIHasNoOtherInputSource(t *testing.T) {
	raw, err := os.ReadFile("recovery_root_grants.go")
	if err != nil {
		t.Fatal(err)
	}
	if found := rootGrantsCLISourceInputs(string(raw)); len(found) != 0 {
		t.Fatalf("root-grants CLI gained an input source: %v", found)
	}
	for _, plant := range []string{"os.Stdin", "os.Getenv(\"X\")", "os.ReadFile(p)", "os.Args[1]", "bufio.NewReader(f)", "exec.Command(p)"} {
		if found := rootGrantsCLISourceInputs(string(raw) + "\n// planted: " + plant); len(found) == 0 {
			t.Fatalf("the guard did not report the planted input %s", plant)
		}
	}
}
