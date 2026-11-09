package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These controls execute the actual pin-check shell fragment, with only the Go
// version query replaced. They prove pin/diagnostic decisions and no continuation
// after refusal; they do not qualify namespaces, native custody or real latency.
func TestVerifierToolchainPin(t *testing.T) {
	source, err := os.ReadFile("../verifier-latency-confined.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "  # Resolve the exact runtime pin")
	end := strings.Index(string(source), "  go version\n")
	if start < 0 || end <= start {
		t.Fatal("actual preflight pin check not found")
	}
	fragment := string(source[start:end])
	currentModule, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, module, runtime, diagnostic string
	}{
		{name: "repository-go-mod", module: string(currentModule), runtime: "go1.26.10"},
		{name: "explicit-toolchain", module: "go 1.26.0\n\ntoolchain go1.26.10\n", runtime: "go1.26.10"},
		{name: "canonical-go-only", module: "go 1.26.10\n", runtime: "go1.26.10"},
		{name: "commented-directives", module: "// toolchain go9.9.9\ngo 1.26.10 // exact minimum\n", runtime: "go1.26.10"},
		{name: "missing-go", module: "toolchain go1.26.10\n", runtime: "go1.26.10", diagnostic: "exact patch go directive required"},
		{name: "missing-all", module: "module example.invalid/test\n", runtime: "go1.26.10", diagnostic: "exact patch go directive required"},
		{name: "missing-patch", module: "go 1.26\n", runtime: "go1.26.10", diagnostic: "exact patch go directive required"},
		{name: "malformed-toolchain", module: "go 1.26.10\ntoolchain default\n", runtime: "go1.26.10", diagnostic: "exact released toolchain pin required"},
		{name: "empty-toolchain", module: "go 1.26.10\ntoolchain\n", runtime: "go1.26.10", diagnostic: "exact released toolchain pin required"},
		{name: "prerelease-toolchain", module: "go 1.26.0\ntoolchain go1.26rc1\n", runtime: "go1.26rc1", diagnostic: "exact released toolchain pin required"},
		{name: "explicit-runtime-mismatch", module: "go 1.26.0\ntoolchain go1.26.10\n", runtime: "go1.26.11", diagnostic: "runtime go1.26.11 differs from pin go1.26.10"},
		{name: "canonical-runtime-mismatch", module: "go 1.26.10\n", runtime: "go1.26.0", diagnostic: "runtime go1.26.0 differs from pin go1.26.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tc.module), 0600); err != nil {
				t.Fatal(err)
			}
			// The mock accepts only the non-product version query used by this fragment.
			program := "go() { [ \"$*\" = \"env GOVERSION\" ] || return 91; printf '%s\\n' \"$TEST_GO_VERSION\"; }\n" + fragment + "\nprintf 'continued-after-pin\\n'\n"
			cmd := exec.Command("/bin/bash", "-euc", program)
			cmd.Dir = dir
			cmd.Env = []string{"TEST_GO_VERSION=" + tc.runtime}
			output, err := cmd.CombinedOutput()
			if tc.diagnostic == "" {
				if err != nil || string(output) != "continued-after-pin\n" {
					t.Fatalf("valid canonical pin refused: err=%v output=%q", err, output)
				}
				return
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 || !strings.Contains(string(output), tc.diagnostic) || strings.Contains(string(output), "continued-after-pin") {
				t.Fatalf("wrong refusal or continuation: err=%v output=%q", err, output)
			}
		})
	}
}

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
