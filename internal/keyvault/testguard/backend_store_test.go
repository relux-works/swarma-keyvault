package testguard_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/testguard"
)

// Claim: off darwin, Require skips even with the gate unset, and the
// production store itself refuses as unsupported, so the guard's build
// condition agrees with the store's. Limit: it runs only off darwin; on darwin
// a store call could reach the login Keychain, so that side is not probed.
func TestRequireSkipsOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin: the store may be real, and probing it could touch the Keychain")
	}
	t.Setenv(testguard.SkipEnv, "")
	var skipped bool
	t.Run("require", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		testguard.Require(t)
	})
	if !skipped {
		t.Fatal("Require did not skip on a build without the real backend")
	}
	_, err := keyvault.NewSecurityStore().List()
	if err == nil || !strings.Contains(err.Error(), "requires darwin with cgo") {
		t.Fatalf("store answered %v, want the unsupported refusal", err)
	}
}
