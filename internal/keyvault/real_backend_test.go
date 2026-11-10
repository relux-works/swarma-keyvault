package keyvault

import (
	"fmt"
	"os"
	"testing"
)

// Confinement is installed by keychaingate before keyvault initializes.
func TestMain(m *testing.M) {
	lane, err := openRecoveryTestLane(os.Getenv(recoveryCodesignTestsEnv), recoveryCodesignHostLock, os.TempDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(75)
	}
	recoveryFixtureLane = lane
	code := m.Run()
	if documentPeerBuild.dir != "" {
		_ = os.RemoveAll(documentPeerBuild.dir)
	}
	if lane != nil {
		if err := lane.close(); err != nil {
			fmt.Fprintln(os.Stderr, "codesign test fixture cleanup:", err)
			code = 1
		}
	}
	os.Exit(code)
}
