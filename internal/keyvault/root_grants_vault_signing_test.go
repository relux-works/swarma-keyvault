package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func rootGrantsSigningReadFixture(t *testing.T) (*rootGrantsVaultFixture, *rootGrantsNativeFake, RootGrantsAddress, string) {
	t.Helper()
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	x.fake.stored = &rootGrantsStoredFake{account: x.itemAccount(t), metadata: x.item.metadata, envelope: []byte(x.item.envelope)}
	address := x.item.address
	return x, x.fake, address, rootGrantsHashHex([]byte(x.item.metadata))
}

func (x *rootGrantsVaultFixture) itemAccount(t *testing.T) string {
	t.Helper()
	account, err := x.item.address.Account()
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func rootGrantsWantReadRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil || failure.Code != code || failure.Phase != "read" || failure.Outcome != "not_applied" {
		t.Fatalf("read refusal = %#v (%v), want %s/read/not_applied", failure, err, code)
	}
}

// Claim: the production read seam returns exact bytes only after startup, a
// canonical exact-address inventory, actual stored-ACL admission, full metadata
// digest checking and retained-pair binding. It reads through one plan and frees
// the existing guard and native item reference before returning. Limit: the
// native plan is a test double; this does not exercise Keychain or Secure Enclave.
func TestRootGrantsSigningReadReturnsOwnedSnapshotAndReleasesGuard(t *testing.T) {
	x, native, address, digest := rootGrantsSigningReadFixture(t)
	native.readValueHook = func() {
		if !rootGrantsLockHeld(t, x.lock) {
			t.Error("read-value ran without the existing guard")
		}
		if native.pairCalls != 1 || len(*x.entries) != 1 || (*x.entries)[0] != "stored" {
			t.Errorf("value read preceded pair binding or actual stored-ACL admission: pair calls=%d policy=%v", native.pairCalls, *x.entries)
		}
	}
	snapshot, err := x.vault.ReadRootGrantsForSigning(context.Background(), address, digest)
	if err != nil {
		t.Fatal("valid stored item refused")
	}
	if !bytes.Equal(snapshot.Metadata, []byte(x.item.metadata)) ||
		!bytes.Equal(snapshot.Envelope, []byte(x.item.envelope)) || !bytes.Equal(snapshot.PairMetadata, native.pair) {
		t.Fatal("read seam did not return the exact retained bytes")
	}
	if rootGrantsLockHeld(t, x.lock) {
		t.Fatal("guard remained held after the read returned")
	}
	if native.readValues != 1 || native.readPlanCloses != 1 || native.commits != 0 || native.prepares != 0 {
		t.Fatalf("read plan or mutation counts: values=%d closes=%d adds=%d commits=%d", native.readValues, native.readPlanCloses, native.prepares, native.commits)
	}
	if len(*x.entries) != 1 || (*x.entries)[0] != "stored" {
		t.Fatalf("read did not apply only the actual stored ACL predicate: %v", *x.entries)
	}

	// Claim: the returned buffers are caller-owned and do not alias native or
	// retained storage. Limit: fake-backed ownership only.
	originalEnvelope := bytes.Clone(native.stored.envelope)
	originalPair := bytes.Clone(native.pair)
	clear(snapshot.Metadata)
	clear(snapshot.Envelope)
	clear(snapshot.PairMetadata)
	if !bytes.Equal(native.stored.envelope, originalEnvelope) || !bytes.Equal(native.pair, originalPair) {
		t.Fatal("caller clearing the snapshot modified retained state")
	}
}

// Claim: every closed seam refusal is distinguishable, pre-signature and
// side-effect-free. Failures before ReadValue never consume the native value
// plan; later failures still close it exactly once. Limit: no OS refusal is
// produced by these native doubles.
func TestRootGrantsSigningReadClosedRefusalTable(t *testing.T) {
	changedPair := func(t *testing.T, raw []byte) []byte {
		t.Helper()
		record, err := parseRecoveryRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		record.GroupID = strings.Repeat("1", 32)
		changed, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRecoveryRecord(changed); err != nil {
			t.Fatal("changed pair fixture is not a valid retained record")
		}
		return changed
	}
	changedMetadata := func(t *testing.T, raw []byte) []byte {
		t.Helper()
		record, err := ParseRootGrantsRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		record.Created = "2026-01-03T03:04:05Z"
		changed, err := CanonicalRootGrantsRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	cases := []struct {
		name    string
		code    string
		context func() (context.Context, context.CancelFunc)
		setup   func(*testing.T, *rootGrantsVaultFixture, *rootGrantsNativeFake)
		address func(RootGrantsAddress) RootGrantsAddress
		digest  func(string) string
		values  int
	}{
		{name: "invalid-arguments", code: "invalid_arguments", address: func(RootGrantsAddress) RootGrantsAddress { return RootGrantsAddress{Service: "Bad Name", Version: 1} }},
		{name: "operation-unavailable-after-validation", code: "operation_unavailable", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = errors.New("PRIVATE_NATIVE_DIAGNOSTIC")
		}, values: 1},
		{name: "unknown-native-status-is-private-protocol-error", code: "private_protocol_error", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = &StatusError{Op: "PRIVATE_NATIVE_DIAGNOSTIC", Status: -67050}
		}, values: 1},
		{name: "native-auth-failure-is-acl-refused", code: "acl_refused", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = &StatusError{Op: "PRIVATE_NATIVE_DIAGNOSTIC", Status: -25293}
		}, values: 1},
		{name: "native-item-not-found-is-inventory-changed", code: "inventory_changed", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = &StatusError{Op: "PRIVATE_NATIVE_DIAGNOSTIC", Status: -25300}
		}, values: 1},
		{name: "native-user-cancel-is-canceled", code: "canceled", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = &StatusError{Op: "PRIVATE_NATIVE_DIAGNOSTIC", Status: -128}
		}, values: 1},
		{name: "malformed-native-result-is-private-protocol-error", code: "private_protocol_error", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readValueErr = recoveryRefuse("invalid_record")
		}, values: 1},
		{name: "code-not-admitted", code: "code_not_admitted", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.startupErr = errRootGrantsNativeCode
		}},
		{name: "acl-refused", code: "acl_refused", setup: func(t *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readFrame = rootGrantsSyntheticFrame(t, rootGrantsSyntheticVariants[0].mutate)
		}},
		{name: "lock-unavailable", code: "lock_unavailable", setup: func(_ *testing.T, x *rootGrantsVaultFixture, _ *rootGrantsNativeFake) {
			x.vault.lockSource = func() (FileLock, error) { return FileLock{}, errors.New("PRIVATE_LOCK_DIAGNOSTIC") }
		}},
		{name: "retained-record-mismatch", code: "retained_record_mismatch", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.pair = []byte("not a retained pair row")
		}},
		{name: "retained-record-changed-after-value-read", code: "retained_record_mismatch", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.pairChangeAt = 2
		}, values: 1},
		{name: "public-pin-mismatch", code: "public_pin_mismatch", digest: func(string) string { return strings.Repeat("0", 64) }},
		{name: "binding-mismatch", code: "binding_mismatch", setup: func(t *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.pair = changedPair(t, f.pair)
		}},
		{name: "inventory-changed-record-is-not-the-inventoried-item", code: "inventory_changed", setup: func(t *testing.T, x *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readMetadata = changedMetadata(t, []byte(x.item.metadata))
		}},
		{name: "inventory-changed-after-value-read", code: "inventory_changed", setup: func(t *testing.T, x *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.rootRowsChangeAt = 2
			f.rootRowsChanged = rootGrantsRowBytes([2]string{f.stored.account, string(changedMetadata(t, []byte(x.item.metadata)))})
		}, values: 1},
		{name: "invalid-envelope", code: "invalid_envelope", setup: func(_ *testing.T, _ *rootGrantsVaultFixture, f *rootGrantsNativeFake) {
			f.readEnvelope = []byte(`{"schema":"wrong"}`)
		}, values: 1},
		{name: "canceled", code: "canceled", context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}},
		{name: "timeout", code: "timeout", context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			return ctx, cancel
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, native, address, digest := rootGrantsSigningReadFixture(t)
			if tc.setup != nil {
				tc.setup(t, x, native)
			}
			if tc.address != nil {
				address = tc.address(address)
			}
			if tc.digest != nil {
				digest = tc.digest(digest)
			}
			ctx, cancel := context.Background(), func() {}
			if tc.context != nil {
				ctx, cancel = tc.context()
			}
			defer cancel()
			_, err := x.vault.ReadRootGrantsForSigning(ctx, address, digest)
			rootGrantsWantReadRefusal(t, err, tc.code)
			if strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("native or lock diagnostic escaped the closed refusal")
			}
			if native.readValues != tc.values {
				t.Fatalf("read-value count=%d, want %d; calls=%v", native.readValues, tc.values, native.calls)
			}
			if native.readPlanCloses != native.readPrepareCount() {
				t.Fatalf("read plans not closed exactly once: prepared=%d closed=%d calls=%v", native.readPrepareCount(), native.readPlanCloses, native.calls)
			}
			if native.commits != 0 || native.prepares != 0 || native.stored.metadata != x.item.metadata || !bytes.Equal(native.stored.envelope, []byte(x.item.envelope)) {
				t.Fatal("a refusal mutated retained root state")
			}
			if rootGrantsLockHeld(t, x.lock) {
				t.Fatal("guard remained held after refusal")
			}
		})
	}
}

func (f *rootGrantsNativeFake) readPrepareCount() int {
	n := 0
	for _, call := range f.calls {
		if call == "read-prepare" {
			n++
		}
	}
	return n
}

// Claim: the policy read uses the same retained item plan and never falls back
// to another address when the exact target is absent. Limit: the source-level
// C guard and this fake do not prove Keychain's real item-reference semantics.
func TestRootGrantsSigningReadRejectsAbsentTarget(t *testing.T) {
	t.Run("target-absent", func(t *testing.T) {
		x, native, address, digest := rootGrantsSigningReadFixture(t)
		native.stored = nil
		native.rootRows = nil
		_, err := x.vault.ReadRootGrantsForSigning(context.Background(), address, digest)
		rootGrantsWantReadRefusal(t, err, "inventory_changed")
		if native.readPrepareCount() != 0 || native.readValues != 0 || len(native.calls) != 2 {
			t.Fatalf("missing exact target reached the item read: %v", native.calls)
		}
	})
}
