//go:build darwin && cgo && keyvault_gate_regression

package keyvault

import (
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

// Tagged source without the _test.go suffix cannot bypass the process sandbox.
func TestSandboxNonTestHelper(t *testing.T) {
	requireSandboxRegression(t)
	items, err := sandboxHiddenBackend().List()
	assertSandboxListRefused(t, items, err, keychaingate.Applied() || keychaingate.Confined())
}
