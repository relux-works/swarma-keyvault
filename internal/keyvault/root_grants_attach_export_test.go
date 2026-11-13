package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// A valid secp256k1 x-only key different from every fixture key (the generator's
// x coordinate), so an altered npub pin is well formed but wrong.
const rootGrantsOtherXOnly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

type rootGrantsRunRecorder struct {
	calls   int
	request []byte
	result  RootGrantsAttachResult
	err     error
}

func (r *rootGrantsRunRecorder) run(_ context.Context, _ rootGrantsAttachVault, raw []byte) (RootGrantsAttachResult, error) {
	r.calls++
	r.request = bytes.Clone(raw)
	return r.result, r.err
}

var rootGrantsFixedNow = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 987654321, time.UTC) }

// The attach request the CLI would build from the owner's retained printout: every
// pin comes from the fixture's independently stored binding, not from the vault.
func rootGrantsAttachRequestFor(t *testing.T, schema string) RootGrantsAttachRequest {
	t.Helper()
	_, pins := rootGrantsTestPair(t, schema)
	return RootGrantsAttachRequest{NostrIdentity: pins.NostrIdentity, NamecoinIdentity: pins.NamecoinIdentity, Version: pins.Version,
		NostrVersion: pins.NostrVersion, NamecoinVersion: pins.NamecoinVersion, GrantsIdentity: "example-root", GrantsVersion: 1,
		ExpectedGroupID: pins.GroupID, ExpectedPairMetadataSHA256: pins.MetadataSHA256, ExpectedNPub: pins.NostrNPub,
		ExpectedNamecoinXPub: pins.NamecoinXPub, ExpectedOrigin: pins.NamecoinOrigin}
}

// rootGrantsAltXPub returns a well-formed xpub that differs from the input only in
// its chain code, with a recomputed checksum: valid for the pin grammar, wrong.
func rootGrantsAltXPub(t *testing.T, xpub string) string {
	t.Helper()
	raw := base58.Decode(xpub)
	if len(raw) != 82 {
		t.Fatal("fixture xpub")
	}
	raw[20] ^= 0x01
	first := sha256.Sum256(raw[:78])
	second := sha256.Sum256(first[:])
	copy(raw[78:], second[:4])
	return base58.Encode(raw)
}

// Claim: for both retained schemas the production orchestration reads the pair as
// public metadata, matches EVERY independently supplied pin, builds the helper
// request with the vault-chosen UTC-second creation time, and reaches the helper
// stage exactly once. The request bytes equal an independently written literal
// wire fixture (not the production encoder), so a mutually wrong encoder and
// decoder cannot bless themselves. Limit: fake native; the helper is a recorder.
func TestRootGrantsAttachPinnedCanonicalRequestGolden(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", PairUnchanged: true}}
			result, err := attachRootGrantsPinned(context.Background(), x.vault, rootGrantsAttachRequestFor(t, schema), rootGrantsFixedNow, recorder.run)
			if err != nil || result.Outcome != "stored" || recorder.calls != 1 {
				t.Fatalf("legitimate invocation failed: %v calls=%d", err, recorder.calls)
			}
			if want := rootGrantsRequest44(t, schema); !bytes.Equal(recorder.request, want) {
				t.Fatalf("request bytes differ from the literal wire fixture:\n got %s\nwant %s", recorder.request, want)
			}
			if _, err := rootGrantsHelperRequest(recorder.request); err != nil {
				t.Fatal("request does not pass the helper's own admission")
			}
			// Public reads and one discarded access-object admission before the helper
			// stage: no lock, add or readback, and the prepared object is closed.
			for _, call := range x.fake.calls {
				if call != "startup" && call != "pair-rows" && call != "prepare" && call != "close" {
					t.Fatalf("unexpected native call before the helper stage: %s", call)
				}
			}
			if x.fake.prepares != 1 || x.fake.closes != 1 || x.fake.commits != 0 || rootGrantsLockHeld(t, x.lock) {
				t.Fatal("pre-helper stage did not admit and discard exactly one access object, or mutated or held the guard")
			}
		})
	}
}

// Claim: each pin and each pair field, altered one at a time to a well-formed
// but wrong value, is a definite retained_record_mismatch BEFORE the helper
// stage, with no lock and no add. The unaltered control above passes, so a
// comparison that rejects everything (or nothing) fails one side.
// Limit: the pair record is a fixture, not a Keychain read.
func TestRootGrantsAttachPinnedEveryFieldMismatchRefusesBeforeHelper(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		cases := []struct {
			name   string
			mutate func(*RootGrantsAttachRequest)
		}{
			{"group-id", func(q *RootGrantsAttachRequest) { q.ExpectedGroupID = strings.Repeat("a", 32) }},
			{"metadata-sha256", func(q *RootGrantsAttachRequest) { q.ExpectedPairMetadataSHA256 = strings.Repeat("b", 64) }},
			{"npub", func(q *RootGrantsAttachRequest) {
				raw, _ := hex.DecodeString(rootGrantsOtherXOnly)
				q.ExpectedNPub, _ = NostrNPub(raw)
			}},
			{"namecoin-xpub", func(q *RootGrantsAttachRequest) {
				q.ExpectedNamecoinXPub = rootGrantsAltXPub(t, q.ExpectedNamecoinXPub)
			}},
			{"namecoin-origin", func(q *RootGrantsAttachRequest) { q.ExpectedOrigin = "[00000000/84h/7h/0h]" }},
			{"nostr-identity", func(q *RootGrantsAttachRequest) { q.NostrIdentity = "other-social" }},
			{"namecoin-identity", func(q *RootGrantsAttachRequest) { q.NamecoinIdentity = "other-wallet" }},
			{"group-version", func(q *RootGrantsAttachRequest) { q.Version++ }},
			{"nostr-version", func(q *RootGrantsAttachRequest) { q.NostrVersion++ }},
			{"namecoin-version", func(q *RootGrantsAttachRequest) { q.NamecoinVersion++ }},
		}
		for _, c := range cases {
			t.Run(schema+"/"+c.name, func(t *testing.T) {
				x := newRootGrantsVaultFixture(t, schema)
				locks := 0
				x.vault.lockSource = func() (FileLock, error) { locks++; return x.lock, nil }
				q := rootGrantsAttachRequestFor(t, schema)
				c.mutate(&q)
				recorder := &rootGrantsRunRecorder{}
				result, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
				rootGrantsAttachFailure13(t, result, err, "retained_record_mismatch", "preflight", "not_applied")
				if recorder.calls != 0 || locks != 0 || x.fake.commits != 0 || x.fake.prepares != 0 {
					t.Fatal("mismatch reached the helper stage, the guard or the add")
				}
			})
		}
	}
}

// Claim: syntactically invalid public inputs are refused as invalid_arguments
// before ANY native call (not even the code check), lock or helper stage.
func TestRootGrantsAttachPinnedInvalidArgumentsTouchNothing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RootGrantsAttachRequest)
	}{
		{"grants-identity-uppercase", func(q *RootGrantsAttachRequest) { q.GrantsIdentity = "Root" }},
		{"grants-identity-empty", func(q *RootGrantsAttachRequest) { q.GrantsIdentity = "" }},
		{"grants-identity-too-long", func(q *RootGrantsAttachRequest) { q.GrantsIdentity = strings.Repeat("a", 41) }},
		{"grants-version-zero", func(q *RootGrantsAttachRequest) { q.GrantsVersion = 0 }},
		{"grants-version-negative", func(q *RootGrantsAttachRequest) { q.GrantsVersion = -1 }},
		{"grants-version-over-max", func(q *RootGrantsAttachRequest) { q.GrantsVersion = 2147483648 }},
		{"group-version-zero", func(q *RootGrantsAttachRequest) { q.Version = 0 }},
		{"nostr-identity-invalid", func(q *RootGrantsAttachRequest) { q.NostrIdentity = "bad name" }},
		{"group-id-uppercase", func(q *RootGrantsAttachRequest) { q.ExpectedGroupID = strings.Repeat("A", 32) }},
		{"group-id-short", func(q *RootGrantsAttachRequest) { q.ExpectedGroupID = q.ExpectedGroupID[:30] }},
		{"metadata-sha-short", func(q *RootGrantsAttachRequest) { q.ExpectedPairMetadataSHA256 = q.ExpectedPairMetadataSHA256[:62] }},
		{"npub-garbled", func(q *RootGrantsAttachRequest) { q.ExpectedNPub = q.ExpectedNPub[:62] + "x" }},
		{"xpub-garbled", func(q *RootGrantsAttachRequest) { q.ExpectedNamecoinXPub = q.ExpectedNamecoinXPub[:110] + "1" }},
		{"origin-wrong-path", func(q *RootGrantsAttachRequest) { q.ExpectedOrigin = "[00000000/84h/7h/1h]" }},
		{"pin-missing", func(q *RootGrantsAttachRequest) { q.ExpectedOrigin = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			q := rootGrantsAttachRequestFor(t, "keyvault-recovery/2")
			c.mutate(&q)
			recorder := &rootGrantsRunRecorder{}
			result, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
			rootGrantsAttachFailure13(t, result, err, "invalid_arguments", "preflight", "not_applied")
			if len(x.fake.calls) != 0 || recorder.calls != 0 {
				t.Fatalf("invalid input reached native or the helper: %v", x.fake.calls)
			}
		})
	}
	// Absent collaborators and a nil/canceled context refuse the same way.
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	q := rootGrantsAttachRequestFor(t, "keyvault-recovery/2")
	recorder := &rootGrantsRunRecorder{}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, call := range map[string]func() (RootGrantsAttachResult, error){
		"nil-context": func() (RootGrantsAttachResult, error) {
			return attachRootGrantsPinned(nil, x.vault, q, rootGrantsFixedNow, recorder.run) //nolint:staticcheck // the refusal of a nil context is the claim
		},
		"nil-vault": func() (RootGrantsAttachResult, error) {
			return attachRootGrantsPinned(context.Background(), nil, q, rootGrantsFixedNow, recorder.run)
		},
		"nil-clock": func() (RootGrantsAttachResult, error) {
			return attachRootGrantsPinned(context.Background(), x.vault, q, nil, recorder.run)
		},
		"nil-runner": func() (RootGrantsAttachResult, error) {
			return attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, nil)
		},
		"canceled": func() (RootGrantsAttachResult, error) {
			return attachRootGrantsPinned(canceled, x.vault, q, rootGrantsFixedNow, recorder.run)
		},
	} {
		result, err := call()
		code := "invalid_arguments"
		if name == "canceled" {
			code = "canceled"
		}
		rootGrantsAttachFailure13(t, result, err, code, "preflight", "not_applied")
	}
	if len(x.fake.calls) != 0 || recorder.calls != 0 {
		t.Fatal("refused collaborators reached native or the helper")
	}
	// A vault without an ACL policy is a definite refusal before any native call, not
	// a panic (a Go panic would exit 2 and read as a usage error).
	y := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	y.vault.policy = nil
	result, err := attachRootGrantsPinned(context.Background(), y.vault, q, rootGrantsFixedNow, recorder.run)
	rootGrantsAttachFailure13(t, result, err, "invalid_arguments", "preflight", "not_applied")
	if len(y.fake.calls) != 0 || recorder.calls != 0 {
		t.Fatal("a vault without a policy reached native or the helper")
	}
}

// Claim: failures of the public pre-helper reads are closed, definite and precede
// the helper: running code not admitted, absent pair, OS failure, unparsable or
// ambiguous inventory. Each maps to its own code with zero helper stage.
func TestRootGrantsAttachPinnedPreHelperReadFailures(t *testing.T) {
	for _, c := range []struct {
		name, code string
		configure  func(*rootGrantsVaultFixture)
	}{
		{"code-not-admitted", "code_not_admitted", func(x *rootGrantsVaultFixture) { x.fake.startupErr = errRootGrantsNativeCode }},
		{"pair-absent", "retained_record_mismatch", func(x *rootGrantsVaultFixture) {
			x.fake.pair, x.fake.pairRowsErr = nil, nil
			x.vault.native = &rootGrantsRawPairFake{rootGrantsNativeFake: x.fake}
		}},
		{"os-failure", "operation_unavailable", func(x *rootGrantsVaultFixture) { x.fake.pairRowsErr = &StatusError{Op: "inventory", Status: -25293} }},
		{"unparsable-inventory", "inventory_changed", func(x *rootGrantsVaultFixture) {
			x.vault.native = &rootGrantsRawPairFake{rootGrantsNativeFake: x.fake, raw: rootGrantsRowBytes([2]string{"x/recovery@1", "{not json"})}
		}},
		{"ambiguous-inventory", "inventory_changed", func(x *rootGrantsVaultFixture) {
			row := [2]string{x.fake.pairAccount, string(x.fake.pair)}
			x.vault.native = &rootGrantsRawPairFake{rootGrantsNativeFake: x.fake, raw: append(rootGrantsRowBytes(row), rootGrantsRowBytes(row)...)}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			c.configure(x)
			recorder := &rootGrantsRunRecorder{}
			result, err := attachRootGrantsPinned(context.Background(), x.vault, rootGrantsAttachRequestFor(t, "keyvault-recovery/2"), rootGrantsFixedNow, recorder.run)
			rootGrantsAttachFailure13(t, result, err, c.code, "preflight", "not_applied")
			if recorder.calls != 0 || x.fake.commits != 0 {
				t.Fatal("read failure reached the helper stage")
			}
		})
	}
}

// Claim: the helper-stage result is never upgraded: a typed failure passes
// through unchanged (not_applied stays not_applied, unknown stays unknown); an
// untyped error or a non-stored success after the stage is UNKNOWN, never a
// refusal and never a stored receipt.
func TestRootGrantsAttachPinnedRunnerOutcomes(t *testing.T) {
	q := rootGrantsAttachRequestFor(t, "keyvault-recovery/2")
	for _, c := range []struct {
		name                string
		result              RootGrantsAttachResult
		err                 error
		code, phase, status string
	}{
		{"typed-not-applied", RootGrantsAttachResult{}, rootGrantsAttachFailed("duplicate", "preflight", "not_applied", nil), "duplicate", "preflight", "not_applied"},
		{"typed-unknown", RootGrantsAttachResult{}, rootGrantsAttachFailed("mutation_unknown", "readback", "unknown", &RootGrantsProjection{}), "mutation_unknown", "readback", "unknown"},
		{"untyped-error", RootGrantsAttachResult{}, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL"), "mutation_unknown", "commit", "unknown"},
		{"success-not-stored", RootGrantsAttachResult{Outcome: "closed"}, nil, "mutation_unknown", "readback", "unknown"},
		{"stored-without-unchanged-pair", RootGrantsAttachResult{Outcome: "stored"}, nil, "mutation_unknown", "readback", "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			recorder := &rootGrantsRunRecorder{result: c.result, err: c.err}
			result, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
			var failure *rootGrantsAttachError
			if result != (RootGrantsAttachResult{}) || !errors.As(err, &failure) || failure.public.Code != c.code || failure.public.Phase != c.phase || failure.public.Outcome != c.status {
				t.Fatalf("outcome not preserved: %v", err)
			}
			if recorder.calls != 1 || strings.Contains(err.Error(), "PUBLIC_TEST_PRIVATE_SENTINEL") {
				t.Fatal("helper stage count or diagnostic leak")
			}
		})
	}
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", Root: RootGrantsProjection{Account: "example-root/root-grants@1"}, PairUnchanged: true}}
	result, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
	if err != nil || result.Outcome != "stored" || !result.PairUnchanged {
		t.Fatal("a verified stored result must pass through")
	}
}

// Claim: the receipt exists only for a completed, verified attach; it carries the
// specified fields in order, the device-wrapped storage label, no private export,
// and none of the sealed material. Limit: the Go shape, not a CLI emitter test.
func TestRootGrantsReceiptShape(t *testing.T) {
	root, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	projection := rootGrantsProject(root)
	receipt, err := NewRootGrantsReceipt(RootGrantsAttachResult{Outcome: "stored", Root: projection, PairUnchanged: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]json.RawMessage
	if json.Unmarshal(raw, &generic) != nil || len(generic) != 8 {
		t.Fatalf("unexpected receipt members: %s", raw)
	}
	text := string(raw)
	for _, want := range []string{`"schema":"keyvault-root-grants-receipt/1"`, `"mode":"attach"`, `"outcome":"stored"`, `"storage":"enclave-wrapped-keychain"`,
		`"presence":"biometry-any-per-signature"`, `"private_export":false`, `"pair_unchanged":true`, `"namespace":"works.relux.mac-keyvault.root-grants.v1"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("receipt lacks %s: %s", want, text)
		}
	}
	if strings.Index(text, `"schema"`) > strings.Index(text, `"mode"`) || strings.Index(text, `"mode"`) > strings.Index(text, `"outcome"`) || strings.Index(text, `"outcome"`) > strings.Index(text, `"root"`) {
		t.Fatal("receipt member order changed")
	}
	for _, forbidden := range []string{"wrapping", "ciphertext", "enclave_blob", "envelope", "scalar", "private_key"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("receipt exposes %s", forbidden)
		}
	}
	for _, bad := range []RootGrantsAttachResult{{}, {Outcome: "stored"}, {Outcome: "unknown", PairUnchanged: true}, {PairUnchanged: true}} {
		if _, err := NewRootGrantsReceipt(bad); err == nil {
			t.Fatalf("receipt built for %+v", bad)
		}
	}
}

func rootGrantsStoredFixture(t *testing.T, x *rootGrantsVaultFixture) {
	t.Helper()
	x.fake.stored = &rootGrantsStoredFake{account: "example-root/root-grants@1", metadata: x.item.metadata}
}

// Claim: the public export reads only attributes and the actual ACL under the
// existing guard, validates the sidecar and its referenced pair, and returns the
// compact value whose bytes, length and SHA-256 equal an independently written
// oracle. Limit: fake native; deployed consumers are not qualified by this.
func TestRootGrantsPublicLookupValueAgreesWithIndependentOracle(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			rootGrantsStoredFixture(t, x)
			receipt, err := rootGrantsPublicLookup(context.Background(), x.vault, x.item.address)
			if err != nil {
				t.Fatal(err)
			}
			_, pins := rootGrantsTestPair(t, schema)
			r, _ := rootGrantsRecordFixture13(t, schema)
			value := `{"nostr":{"names":{"_":"` + pins.NostrPublicKey + `"}},"swarma":{"landlord":{"grant":"` + r.PublicKey + `"}}}`
			sum := sha256.Sum256([]byte(value))
			if receipt.Schema != RootGrantsPublicSchema || receipt.IDValueUTF8 != value || receipt.IDValueByteLength != len(value) || receipt.IDValueSHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("export differs from the independent oracle: %+v", receipt)
			}
			if receipt.Root.Account != "example-root/root-grants@1" || receipt.Root.Namespace != RootGrantsNamespace || receipt.Root.Pair != pins {
				t.Fatal("export projection differs from the stored record")
			}
			for _, call := range x.fake.calls {
				if call == "commit" || call == "prepare" {
					t.Fatal("public lookup performed a write step")
				}
			}
			if rootGrantsLockHeld(t, x.lock) {
				t.Fatal("guard leaked")
			}
		})
	}
}

// Claim: the public export refuses, with no output, when the root is absent, the
// guard is missing, the code is not admitted, an inventory row is unparsable or
// duplicated, the actual ACL is not admitted, the stored metadata is another
// record, or the referenced pair changed. The valid export above is the paired
// positive control.
func TestRootGrantsPublicLookupRefusals(t *testing.T) {
	changedPair := func(x *rootGrantsVaultFixture) {
		x.fake.pair = bytes.Replace(x.fake.pair, []byte("2026-01-02"), []byte("2026-01-03"), 1)
	}
	for _, c := range []struct {
		name      string
		configure func(*testing.T, *rootGrantsVaultFixture)
		wantErr   func(error) bool
	}{
		{"absent", func(t *testing.T, x *rootGrantsVaultFixture) {}, func(err error) bool { return errors.Is(err, ErrNotFound) }},
		{"code-not-admitted", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			x.fake.startupErr = errRootGrantsNativeCode
		}, func(err error) bool { return err != nil }},
		{"guard-missing", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			x.vault.lockSource = func() (FileLock, error) { return FileLock{Path: x.lock.Path + ".absent"}, nil }
		}, func(err error) bool { return err != nil }},
		{"unparsable-row", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			x.fake.rootRows = rootGrantsRowBytes([2]string{"x/root-grants@1", "{}"})
			x.fake.stored = nil
		}, func(err error) bool { return err != nil && !errors.Is(err, ErrNotFound) }},
		{"actual-acl-not-admitted", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			x.fake.readbackFrame = rootGrantsSyntheticFrame(t, rootGrantsSyntheticVariants[0].mutate)
		}, func(err error) bool { return errors.Is(err, errRootGrantsSyntheticRefusal) }},
		{"default-policy", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			x.vault.policy = productionRootGrantsACLPolicy()
		}, func(err error) bool { return errors.Is(err, errRootGrantsACLPolicyUnavailable) }},
		{"record-names-another-group", func(t *testing.T, x *rootGrantsVaultFixture) {
			rootGrantsStoredFixture(t, x)
			other, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
			other.Pair.GroupID = strings.Repeat("d", 32) // a self-consistent record naming a different group
			meta, err := CanonicalRootGrantsRecord(other)
			if err != nil {
				t.Fatal(err)
			}
			x.fake.readbackMeta = meta
			x.fake.stored.metadata = string(meta)
		}, func(err error) bool { return err != nil }},
		{"referenced-pair-changed", func(t *testing.T, x *rootGrantsVaultFixture) { rootGrantsStoredFixture(t, x); changedPair(x) }, func(err error) bool {
			var r *Refusal
			return errors.As(err, &r) && r.Code == "recovery_retained_record_mismatch"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			c.configure(t, x)
			receipt, err := rootGrantsPublicLookup(context.Background(), x.vault, x.item.address)
			if !c.wantErr(err) || receipt.IDValueUTF8 != "" || receipt.Schema != "" {
				t.Fatalf("lookup did not refuse as intended: %v", err)
			}
			if x.fake.commits != 0 || x.fake.prepares != 0 {
				t.Fatal("refusal performed a write step")
			}
		})
	}
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	for name, call := range map[string]func() error{
		"nil-context": func() error { _, err := rootGrantsPublicLookup(nil, x.vault, x.item.address); return err }, //nolint:staticcheck // nil context refusal is the claim
		"nil-vault":   func() error { _, err := rootGrantsPublicLookup(context.Background(), nil, x.item.address); return err },
		"bad-address": func() error {
			_, err := rootGrantsPublicLookup(context.Background(), x.vault, RootGrantsAddress{Service: "Bad Name", Version: 1})
			return err
		},
	} {
		if call() == nil {
			t.Fatalf("%s admitted", name)
		}
	}
	if len(x.fake.calls) != 0 {
		t.Fatal("invalid public lookup reached native")
	}
}

// Claim: an attached pair is recognized by address OR group id across the whole
// validated root inventory, a root on another pair is not, and an inventory that
// cannot be parsed refuses instead of reading as "not attached".
func TestRootGrantsAttachedToInventory(t *testing.T) {
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	pairRecord, err := parseRecoveryRecord(x.fake.pair)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	row := func(r RootGrantsRecord) [2]string {
		meta, err := CanonicalRootGrantsRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		account, _ := (RootGrantsAddress{Service: r.Service, Version: r.Version}).Account()
		return [2]string{account, string(meta)}
	}
	byAddress := root // references this pair by service and version
	otherPair := root
	otherPair.Service = "second-root"
	otherPair.Pair.Service, otherPair.Pair.NostrIdentity, otherPair.Pair.Version = "second-social", "second-social", 7
	otherPair.Pair.GroupID = strings.Repeat("c", 32)
	groupOnly := otherPair // different address, same group id
	groupOnly.Service = "third-root"
	groupOnly.Pair.GroupID = pairRecord.GroupID
	for _, c := range []struct {
		name     string
		raw      []byte
		attached bool
		refused  bool
	}{
		{"empty", nil, false, false},
		{"root-on-another-pair", rootGrantsRowBytes(row(otherPair)), false, false},
		{"by-address", rootGrantsRowBytes(row(otherPair), row(byAddress)), true, false},
		{"by-group-id-only", rootGrantsRowBytes(row(groupOnly)), true, false},
		{"unparsable-row", rootGrantsRowBytes([2]string{"x/root-grants@1", "{}"}), false, true},
		{"duplicate-row", rootGrantsRowBytes(row(byAddress), row(byAddress)), false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			x.fake.stored = nil
			x.fake.rootRows = c.raw
			attached, err := rootGrantsAttachedTo(x.fake, pairRecord)
			if attached != c.attached || (err != nil) != c.refused {
				t.Fatalf("attached=%v err=%v", attached, err)
			}
		})
	}
	x.fake.rootRowsErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	if attached, err := rootGrantsAttachedTo(x.fake, pairRecord); attached || err == nil {
		t.Fatal("inventory failure read as not attached")
	}
}

// rootGrantsAttachOrderViolations reports a helper stage that is not exactly one call
// after the pin comparison and the request build, or an exported entry that no
// longer fixes the production helper stage and clock.
func rootGrantsAttachOrderViolations(src string) []string {
	var violations []string
	i := strings.Index(src, "func attachRootGrantsPinned(")
	if i < 0 {
		return []string{"orchestration missing"}
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	match := strings.Index(body, "rootGrantsMatchPair(pairRaw, expected)")
	admit := strings.Index(body, "vault.admitIntendedACL()")
	build := strings.Index(body, "rootGrantsPrivateRequest{")
	call := strings.Index(body, "run(ctx, vault, encoded)")
	if match < 0 || admit < 0 || build < 0 || call < 0 || !(match < admit && admit < build && build < call) ||
		strings.Count(body, "run(") != 1 || strings.Count(body, "admitIntendedACL(") != 1 {
		violations = append(violations, "helper stage is not exactly one call after the pin comparison, the ACL admission and the request build")
	}
	if !strings.Contains(body, "vault.policy == nil") {
		violations = append(violations, "the nil check before the helper does not cover the ACL policy")
	}
	if !strings.Contains(src, "return attachRootGrantsPinned(ctx, vault, q, time.Now, attachRootGrantsWithHelper)") || strings.Count(src, "attachRootGrantsWithHelper") != 2 {
		violations = append(violations, "the exported entry no longer fixes the production helper stage and clock")
	}
	return violations
}

// Claim: in the exported orchestration the helper stage is called exactly once,
// only after every pin comparison and the access-object admission, and the
// production entry fixes the real helper stage and the real clock. A source-order
// guard in the style of the helper boundary test, with control plants (a missing
// comparison, a missing admission, a second call, a configurable stage) that it
// must report. Limit: source text, not behavior
// (behavior is the recorder tests above).
func TestRootGrantsAttachPinnedSourceOrder(t *testing.T) {
	src := string(mustRead(t, "root_grants_attach_export.go"))
	if violations := rootGrantsAttachOrderViolations(src); len(violations) != 0 {
		t.Fatalf("orchestration order changed: %v", violations)
	}
	for _, plant := range []struct {
		name, want string
		mutate     func(string) string
	}{
		{"comparison-removed", "not exactly one call after the pin comparison", func(s string) string {
			return strings.Replace(s, "rootGrantsMatchPair(pairRaw, expected)", "false", 1)
		}},
		{"admission-removed", "not exactly one call after the pin comparison", func(s string) string {
			return strings.Replace(s, "if err := vault.admitIntendedACL(); err != nil {", "if err := error(nil); err != nil {", 1)
		}},
		{"nil-policy-check-removed", "does not cover the ACL policy", func(s string) string {
			return strings.Replace(s, "vault.policy == nil || ", "", 1)
		}},
		{"second-helper-call", "not exactly one call after the pin comparison", func(s string) string {
			return strings.Replace(s, "\tresult, err := run(ctx, vault, encoded)", "\t_, _ = run(ctx, vault, encoded)\n\tresult, err := run(ctx, vault, encoded)", 1)
		}},
		{"configurable-stage", "no longer fixes the production helper stage", func(s string) string {
			return strings.Replace(s, "time.Now, attachRootGrantsWithHelper)", "time.Now, rootGrantsAttachRunner(nil))", 1)
		}},
	} {
		planted := plant.mutate(src)
		if planted == src {
			t.Fatalf("%s: the plant was not applied", plant.name)
		}
		caught := ""
		for _, v := range rootGrantsAttachOrderViolations(planted) {
			if caught == "" && strings.Contains(v, plant.want) {
				caught = v
			}
		}
		if caught == "" {
			t.Fatalf("%s: the guard did not report %q", plant.name, plant.want)
		}
		t.Logf("plant %q caught: %s", plant.name, caught)
	}
}

// Claim: the access object the add would use is admitted BEFORE the helper starts,
// so the owner never types the words only to be refused at the add. Every refusal
// of that early admission (code not admitted, access object refused, nothing
// prepared, undecodable or empty projection, the fail-closed production policy and
// seven well-formed forbidden synthetic forms) is a definite preflight refusal with
// its closed code, zero helper stages, no guard taken, no add, and the prepared
// object closed exactly once. The admitted form (the golden test above) reaches the
// helper stage once, so refusing everything fails the pair.
func TestRootGrantsAttachPinnedRefusesUnadmittedACLBeforeHelper(t *testing.T) {
	type refusal struct {
		name, code string
		configure  func(*testing.T, *rootGrantsVaultFixture)
	}
	cases := []refusal{
		{"prepare-code-refused", "code_not_admitted", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareErr = errRootGrantsNativeCode }},
		{"prepare-acl-refused", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareErr = errRootGrantsNativeACL }},
		{"prepare-other-failure", "operation_unavailable", func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.prepareErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		}},
		{"prepare-returned-nothing", "operation_unavailable", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareNil = true }},
		{"undecodable-frame", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = []byte("not a KVQP1 frame") }},
		{"empty-frame", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = nil }},
		{"production-default-policy", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.vault.policy = productionRootGrantsACLPolicy() }},
	}
	for _, v := range rootGrantsSyntheticVariants {
		v := v
		cases = append(cases, refusal{"policy-refuses-" + v.name, "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = rootGrantsSyntheticFrame(t, v.mutate) }})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			locks := 0
			x.vault.lockSource = func() (FileLock, error) { locks++; return x.lock, nil }
			c.configure(t, x)
			recorder := &rootGrantsRunRecorder{}
			result, err := attachRootGrantsPinned(context.Background(), x.vault, rootGrantsAttachRequestFor(t, "keyvault-recovery/2"), rootGrantsFixedNow, recorder.run)
			rootGrantsAttachFailure13(t, result, err, c.code, "preflight", "not_applied")
			if recorder.calls != 0 || locks != 0 || x.fake.commits != 0 || x.fake.stored != nil || x.fake.closes != x.fake.added {
				t.Fatal("the early refusal reached the helper stage, the guard or the add, or leaked the prepared object")
			}
		})
	}
}

// rootGrantsAllowedImports is the closed set of package paths each attach source may
// import, by path and whatever the alias: none of them can read an environment,
// stdin, a file, a socket or a process.
var rootGrantsAllowedImports = map[string]map[string]bool{
	"root_grants_attach_export.go": rootGrantsSet("context", "encoding/hex", "encoding/json", "errors", "time", "github.com/btcsuite/btcd/btcutil/bech32"),
	"root_grants_vault.go": rootGrantsSet("bytes", "context", "errors", "strings", "sync",
		"github.com/relux-works/swarma-keyvault/internal/rootqualification"),
	"root_grants_vault_darwin.go": rootGrantsSet("C", "unsafe"),
}

// rootGrantsInputSources lists every way a source file can reach an input other than
// its typed request: an import outside its allowlist (parsed, so an alias, a dot or a
// blank import changes nothing) and the spellings of the usual readers.
func rootGrantsInputSources(name, src string) []string {
	var found []string
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return []string{"unparsable source: " + err.Error()}
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !rootGrantsAllowedImports[name][path] {
			found = append(found, fmt.Sprintf("import %s is not in the allowlist", imp.Path.Value))
		}
	}
	for _, forbidden := range []string{"os.Stdin", "Getenv", "LookupEnv", "Environ(", "os.ReadFile", "os.Open", "ioutil", "os.Args", "bufio", "exec.Command"} {
		if strings.Contains(src, forbidden) {
			found = append(found, forbidden)
		}
	}
	return found
}

// Claim: the keyvault side of the attach has no input source other than its typed
// request: the orchestration, the production vault and its cgo binding import no
// os package and read no environment, stdin, file or raw argument, so no word,
// scalar, path, namespace, helper location or timeout can reach the attach from
// them. A source guard with control plants, including an environment variable that
// carries a timeout into the orchestration, that it must report.
func TestRootGrantsKeyvaultSourcesHaveNoOtherInputSource(t *testing.T) {
	for name := range rootGrantsAllowedImports {
		if found := rootGrantsInputSources(name, string(mustRead(t, name))); len(found) != 0 {
			t.Fatalf("%s gained an input source: %v", name, found)
		}
	}
	src := string(mustRead(t, "root_grants_attach_export.go"))
	withImports := func(imports string) string {
		return strings.Replace(src, "\t\"errors\"\n\t\"time\"\n", "\t\"errors\"\n"+imports+"\t\"time\"\n", 1)
	}
	withBlock := func(s, block string) string {
		return strings.Replace(s, "\taddress, expected, err := q.expectedPair()\n", block+"\taddress, expected, err := q.expectedPair()\n", 1)
	}
	for name, planted := range map[string]string{
		"environment-timeout (MG1)": withBlock(withImports("\t\"os\"\n"), "\tif v, ok := os.LookupEnv(\"KEYVAULT_ROOT_GRANTS_TIMEOUT\"); ok {\n\t\t_ = v\n\t}\n"),
		"aliased-os-stdin-timeout (MG3)": withBlock(withImports("\t\"fmt\"\n\tosx \"os\"\n"),
			"\tif q.GrantsVersion == 2147483647 { // mutant MG3\n\t\tvar seconds int\n\t\t_, _ = fmt.Fscan(osx.NewFile(0, \"in\"), &seconds)\n\t\tvar cancel context.CancelFunc\n\t\tctx, cancel = context.WithTimeout(ctx, time.Duration(seconds)*time.Second)\n\t\tdefer cancel()\n\t}\n"),
		"blank-os-import":        withImports("\t_ \"os\"\n"),
		"dot-os-import":          withImports("\t. \"os\"\n"),
		"aliased-syscall-import": withImports("\tsc \"syscall\"\n"),
		"ioutil-import":          withImports("\t\"io/ioutil\"\n"),
		"bufio-import":           withImports("\t\"bufio\"\n"),
		"exec-import":            withImports("\t\"os/exec\"\n"),
		"stdin-spelling":         src + "\nvar _ = os.Stdin",
		"file-spelling":          src + "\nvar _, _ = os.ReadFile(\"x\")",
	} {
		reported := rootGrantsInputSources("root_grants_attach_export.go", planted)
		if planted == src || len(reported) == 0 {
			t.Fatalf("%s: the guard did not report the planted input source", name)
		}
		t.Logf("plant %q caught: %s", name, reported[0])
	}
	// The vault file and the cgo binding have the same closed import sets.
	for _, c := range []struct{ name, old, new string }{
		{"root_grants_vault.go", "\t\"bytes\"\n", "\t\"bytes\"\n\tosx \"os\"\n"},
		{"root_grants_vault_darwin.go", "import \"unsafe\"", "import (\n\t\"unsafe\"\n\tosx \"os\"\n)"},
	} {
		original := string(mustRead(t, c.name))
		planted := strings.Replace(original, c.old, c.new, 1)
		if planted == original || len(rootGrantsInputSources(c.name, planted)) == 0 {
			t.Fatalf("%s: the guard did not report a planted aliased os import", c.name)
		}
	}
}
