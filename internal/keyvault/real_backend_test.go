package keyvault

import (
	"os"
	"testing"
)

// Confinement is installed by keychaingate before keyvault initializes.
func TestMain(m *testing.M) {
	code := m.Run()
	if documentPeerBuild.dir != "" {
		_ = os.RemoveAll(documentPeerBuild.dir)
	}
	os.Exit(code)
}
