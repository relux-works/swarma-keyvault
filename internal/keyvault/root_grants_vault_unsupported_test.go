//go:build !darwin || !cgo

package keyvault

import "testing"

// Claim: without the macOS Security framework there is no native seam, so the
// production vault cannot be constructed and nothing can be attached.
func TestRootGrantsProductionVaultUnavailableWithoutNative(t *testing.T) {
	vault, err := newRootGrantsProductionVault()
	if err == nil || vault != nil {
		t.Fatal("production vault constructed without a native seam")
	}
}
