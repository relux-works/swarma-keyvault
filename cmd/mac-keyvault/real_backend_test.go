package main

import (
	"os"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/testguard"
)

func TestMain(m *testing.M) {
	if testguard.Enabled() {
		// A test that forgets to inject a fake must fail before production wiring
		// can construct either backend. Existing withBackend restores this guard.
		newBackend = func() keyvault.Backend {
			panic("test must inject a fake backend while " + testguard.SkipEnv + " is set")
		}
	}
	os.Exit(m.Run())
}

func newTestSecurityStore(t *testing.T) keyvault.Backend {
	t.Helper()
	testguard.Require(t)
	return keyvault.NewSecurityStore()
}
