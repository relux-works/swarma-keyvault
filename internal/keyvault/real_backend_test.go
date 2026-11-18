package keyvault

import (
	"fmt"
	"os"
	"testing"
)

// Confinement is installed by keychaingate before keyvault initializes.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--root-grants-sign-trust-contract-countersign-v1" {
		_, _ = fmt.Fprint(os.Stdout, os.Args[1])
		os.Exit(0)
	}
	code := m.Run()
	if documentPeerBuild.dir != "" {
		_ = os.RemoveAll(documentPeerBuild.dir)
	}
	os.Exit(code)
}
