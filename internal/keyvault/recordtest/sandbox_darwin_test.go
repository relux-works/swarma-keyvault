//go:build darwin && cgo

package recordtest_test

import (
	"errors"
	"os"
	"testing"

	kv "github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

// A standalone leaf test binary receives the sandbox without a parent TestMain.
func TestSandboxLeafPackage(t *testing.T) {
	if os.Getenv(keychaingate.SkipEnv) == "" {
		t.Skip("requires the init sandbox")
	}
	items, err := kv.NewSecurityStore().List()
	var status *kv.StatusError
	if len(items) != 0 || !errors.As(err, &status) || status.Status != -50 {
		t.Fatalf("expected no items and sandbox OSStatus -50, got %d items, %v", len(items), err)
	}
	t.Logf("in-process=%t; external=%t; read-only List refused: %v; no write attempted", keychaingate.Applied(), keychaingate.Confined(), err)
	if !keychaingate.Applied() && !keychaingate.Confined() {
		t.Fatal("neither confinement layer was verified")
	}
}
