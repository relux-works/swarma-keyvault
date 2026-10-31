package keyvault

import (
	"os"
	"testing"
)

// Confinement is installed by keychaingate before keyvault initializes.
func TestMain(m *testing.M) { os.Exit(m.Run()) }
