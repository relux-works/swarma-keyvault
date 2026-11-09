//go:build darwin || linux

package scripts_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Both repaired modules retain their complete upstream and lifecycle suites.
// All module commands finish or refuse before verdicts are reported. This is
// test execution, not native Keychain or product-latency qualification.
func TestCryptoRepairUpstream(t *testing.T) {
	var specs []upstreamSpec
	for _, module := range []string{"btcec", "secp256k1"} {
		specs = append(specs, upstreamSpec{
			name: module, path: filepath.Join(runtime.GOROOT(), "bin", "go"),
			args:   []string{"-C", "../../third_party/" + module, "test", "-race", "-count=1", "-timeout=10m", "./..."},
			env:    append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off"),
			budget: 12 * time.Minute,
		})
	}
	for _, result := range runUpstreamModules(specs) {
		t.Run(result.name, func(t *testing.T) {
			t.Logf("elapsed=%s pid=%d\n%s", result.elapsed, result.pid, result.output)
			if result.failed() {
				t.Fatalf("upstream command refused: start=%v wait=%v context=%v cleanup=%v", result.startErr, result.waitErr, result.contextErr, result.cleanupErr)
			}
		})
	}
}
