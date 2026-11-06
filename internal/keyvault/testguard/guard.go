// Package testguard is test-only infrastructure for suites that can reach the
// login Keychain or Secure Enclave. Production code must not import it.
package testguard

import (
	"os"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

const SkipEnv = keychaingate.SkipEnv

// Enabled reports whether real Security.framework and helper tests are disabled.
func Enabled() bool { return os.Getenv(SkipEnv) != "" }

// Require must precede all real-backend setup, including helper compilation.
// It skips when the gate is set and when this build has no real backend.
func Require(t testing.TB) {
	t.Helper()
	if !realBackend {
		t.Skip("real Keychain and Secure Enclave tests need darwin with cgo")
	}
	if Enabled() {
		t.Skip(SkipEnv + " set: real Keychain and Secure Enclave tests disabled")
	}
}
