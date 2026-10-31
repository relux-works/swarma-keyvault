//go:build darwin && cgo

package keyvault

import (
	"errors"
	"os"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

var initSandboxProtected bool
var initSandboxItems []Item
var initSandboxError error

func init() {
	if os.Getenv(keychaingate.SkipEnv) != "" {
		initSandboxProtected = keychaingate.Applied() || keychaingate.Confined()
		initSandboxItems, initSandboxError = NewSecurityStore().List()
	}
}

func assertSandboxListRefused(t *testing.T, items []Item, err error, protected bool) {
	t.Helper()
	var status *StatusError
	if len(items) != 0 || !errors.As(err, &status) || status.Status != -50 {
		t.Fatalf("expected no items and sandbox OSStatus -50, got %d items, %v", len(items), err)
	}
	t.Logf("confinement verified=%t; read-only List refused: %v; no write attempted", protected, err)
	if !protected {
		t.Fatal("neither confinement layer was verified before backend access")
	}
}

func requireSandboxRegression(t *testing.T) {
	t.Helper()
	if os.Getenv(keychaingate.SkipEnv) == "" {
		t.Skip("requires the init sandbox")
	}
}

// The imported sandbox is installed before a test-file init's first Security.framework contact.
func TestSandboxInitBeforeBackend(t *testing.T) {
	requireSandboxRegression(t)
	assertSandboxListRefused(t, initSandboxItems, initSandboxError, initSandboxProtected)
}

// A nil receiver and captured method value cannot bypass the process sandbox.
func TestSandboxNilMethodValue(t *testing.T) {
	requireSandboxRegression(t)
	var value any
	store, _ := value.(*SecurityStore)
	list := store.List
	items, err := list()
	assertSandboxListRefused(t, items, err, keychaingate.Applied() || keychaingate.Confined())
}
