package scripts_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The ordinary repository suite also runs both repaired modules' retained
// upstream tests and their direct-buffer lifecycle tests. Each module runs
// even if the other fails; this does not qualify native Keychain custody.
func TestCryptoRepairUpstream(t *testing.T) {
	for _, module := range []string{"btcec", "secp256k1"} {
		t.Run(module, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "-C", "../../third_party/"+module, "test", "-race", "-count=1", "./...")
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("upstream module %s failed: %v\n%s", module, err, out)
			}
		})
	}
}
