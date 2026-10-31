//go:build darwin && cgo && keyvault_gate_regression

package keychaingate

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// Either confinement layer is recorded before this read-only lookup returns -50.
func TestSandboxCanary(t *testing.T) {
	if os.Getenv(SkipEnv) == "" {
		t.Fatal("canary requires the gate to be set")
	}
	t.Logf("keychaingate.Applied()=%t keychaingate.Confined()=%t before the test lookup", Applied(), Confined())
	if !Applied() && !Confined() {
		t.Fatal("neither confinement layer was verified")
	}
	service := fmt.Sprintf("works.relux.mac-keyvault.sandbox-canary.nonexistent.%d.%d", os.Getpid(), time.Now().UnixNano())
	status := canaryFindNonexistent(service)
	t.Logf("read-only SecItemCopyMatching for nonexistent item: OSStatus %d; no write attempted", status)
	if status != -50 {
		t.Fatalf("expected sandbox OSStatus -50, got %d", status)
	}
}
