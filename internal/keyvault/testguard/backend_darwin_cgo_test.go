//go:build darwin && cgo

package testguard

import "testing"

// Claim: a build that compiles the real Security.framework store also reports
// a real backend, so Require does not silently skip every real-backend test
// on the Mac. It reads only the constant and touches no Keychain.
func TestRealBackendOnDarwinCgo(t *testing.T) {
	if !realBackend {
		t.Fatal("darwin with cgo builds the real store, but realBackend is false")
	}
}
