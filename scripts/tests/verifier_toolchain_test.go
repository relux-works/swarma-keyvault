package scripts_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// An assertion failure must retain its exit code without claiming a namespace
// cause. This executes the actual outer refusal branch, without a sandbox call.
func TestVerifierPreflightDiagnostic(t *testing.T) {
	source, err := os.ReadFile("../verifier-latency-confined.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "else\n  status=$?\n  echo \"verifier sandbox preflight failed")
	end := strings.Index(string(source), "\nfi\n# Download/verify")
	if start < 0 || end <= start {
		t.Fatal("actual outer refusal branch not found")
	}
	cmd := exec.Command("/bin/bash", "-euc", "if (exit 2); then exit 91;\n"+string(source[start:end])+"\nfi\nprintf 'forbidden-continuation\\n'")
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 || !strings.Contains(string(output), "preflight failed (exit 2)") || !strings.Contains(string(output), "No timing samples collected") || strings.Contains(string(output), "namespaces unavailable") || strings.Contains(string(output), "forbidden-continuation") {
		t.Fatalf("misleading diagnostic, lost status or continuation: err=%v output=%q", err, output)
	}
}
