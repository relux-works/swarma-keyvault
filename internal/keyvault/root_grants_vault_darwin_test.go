//go:build darwin && cgo

package keyvault

import (
	"errors"
	"testing"
)

// Claim: the cgo store's namespace literal equals RootGrantsNamespace, so the Go
// inventory and the native query cannot address different services.
// Limit: a string comparison; it creates and queries nothing.
func TestRootGrantsNativeNamespaceAgrees(t *testing.T) {
	if rootGrantsNativeNamespace() != RootGrantsNamespace {
		t.Fatal("native root-grants namespace differs from RootGrantsNamespace")
	}
}

// Claim: bound to the real cgo store, every native entry refuses in an executable
// that is not the signed vault, with the pre-query status, BEFORE any Keychain
// access: Startup, PrepareAdd and ReadPrepare report the code refusal, the
// inventories and readback fail with errSecAuthFailed, and no value or add object
// is selected. This is a
// native negative control for the startup ordering, run from the
// unsigned test executable in the confined lane. It does NOT show that the signed
// vault is admitted or what the OS stores: that needs the attended native lane.
func TestRootGrantsNativeUnsignedExecutableRefusesBeforeKeychain(t *testing.T) {
	native := newRootGrantsNative()
	if native == nil {
		t.Fatal("native seam missing on darwin")
	}
	if err := native.Startup(); !errors.Is(err, errRootGrantsNativeCode) {
		t.Fatalf("unsigned executable passed the code check: %v", err)
	}
	if read, err := native.PrepareRead("example-root/root-grants@1"); !errors.Is(err, errRootGrantsNativeCode) || read != nil {
		t.Fatalf("unsigned executable selected a root item: %v", err)
	}
	add, err := native.PrepareAdd()
	if !errors.Is(err, errRootGrantsNativeCode) || add != nil {
		t.Fatalf("unsigned executable obtained an access object: %v", err)
	}
	const errSecAuthFailed = -25293
	for name, call := range map[string]func() error{
		"pair inventory": func() error { _, err := native.PairRows(); return err },
		"root inventory": func() error { _, err := native.RootRows(); return err },
		"readback":       func() error { _, _, err := native.Readback("example-root/root-grants@1"); return err },
	} {
		var status *StatusError
		if err := call(); !errors.As(err, &status) || status.Status != errSecAuthFailed {
			t.Fatalf("%s did not refuse before the Keychain query: %v", name, err)
		}
	}
}
