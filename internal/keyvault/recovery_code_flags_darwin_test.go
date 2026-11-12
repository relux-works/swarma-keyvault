//go:build darwin && cgo

package keyvault

import "testing"

// The actual C predicate accepts both existing hardened ad-hoc and new
// certificate runtime flags, and no extra flags. This pure call does not prove
// signature, dynamic code validity, certificate trust, ACLs or native adoption.
func TestRecoveryCodeFlagCompatibility(t *testing.T) {
	for _, flags := range []uint32{0x10002, 0x10000} {
		if !recoveryCodeFlags(flags) {
			t.Fatalf("valid flags%x refused", flags)
		}
	}
	for _, flags := range []uint32{0, 1, 2, 0x10001, 0x10004, 0x10006, 0x10000000, 0x10010000, 0xffffffff} {
		if recoveryCodeFlags(flags) {
			t.Fatalf("unknown flags%x admitted", flags)
		}
	}
}
