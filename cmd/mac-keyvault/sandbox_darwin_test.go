//go:build darwin && cgo

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

var sandboxCapturedFactory = newBackend

func requireSandboxRegression(t *testing.T) {
	t.Helper()
	if os.Getenv(keychaingate.SkipEnv) == "" {
		t.Skip("requires the init sandbox")
	}
}

func assertSandboxInstalled(t *testing.T) {
	t.Helper()
	t.Logf("in-process=%t; external=%t", keychaingate.Applied(), keychaingate.Confined())
	if !keychaingate.Applied() && !keychaingate.Confined() {
		t.Fatal("neither confinement layer was verified")
	}
}

// Capturing the production factory before TestMain cannot bypass the init sandbox.
func TestSandboxCapturedFactory(t *testing.T) {
	requireSandboxRegression(t)
	list := sandboxCapturedFactory().List
	items, err := list()
	var status *keyvault.StatusError
	if len(items) != 0 || !errors.As(err, &status) || status.Status != -50 {
		t.Fatalf("expected no items and sandbox OSStatus -50, got %d items, %v", len(items), err)
	}
	t.Logf("read-only List refused: %v; no write attempted", err)
	assertSandboxInstalled(t)
}

func sandboxChildEnv() []string {
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, keychaingate.SkipEnv+"=") {
			env = append(env, entry)
		}
	}
	return env
}

func assertSandboxCLIRefused(t *testing.T, code int, output []byte) {
	t.Helper()
	var response struct {
		OK    bool `json:"ok"`
		Error struct {
			Code   string `json:"code"`
			Status int    `json:"os_status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatalf("CLI JSON: %v: %s", err, output)
	}
	if code != 1 || response.OK || response.Error.Code != "security" || response.Error.Status != -50 {
		t.Fatalf("expected sandbox security refusal, code=%d: %s", code, output)
	}
	t.Log("child read-only list refused: OSStatus -50; no write attempted")
}

// A re-executed test binary inherits the sandbox after the gate is stripped from its environment.
func TestSandboxReexecWithoutGate(t *testing.T) {
	if os.Getenv("KEYVAULT_GATE_REGRESSION_CHILD") == "1" {
		if os.Getenv(keychaingate.SkipEnv) != "" || keychaingate.Applied() {
			t.Fatal("child must have no gate and no newly installed sandbox")
		}
		var out, stderr bytes.Buffer
		code := run([]string{"--json", "list", "--service", "test"}, &out, &stderr)
		assertSandboxCLIRefused(t, code, out.Bytes())
		return
	}
	requireSandboxRegression(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSandboxReexecWithoutGate$", "-test.v")
	cmd.Env = append(sandboxChildEnv(), "KEYVAULT_GATE_REGRESSION_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v: %s", err, output)
	}
	t.Logf("%s", output)
	assertSandboxInstalled(t)
}

// A real CLI stays inert with the gate set and inherits confinement with the gate stripped.
func TestSandboxBuiltCLIWithoutGate(t *testing.T) {
	requireSandboxRegression(t)
	binary := filepath.Join(t.TempDir(), "mac-keyvault")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"gate-retained-production-inert", os.Environ()},
		{"gate-stripped-sandbox-inherited", sandboxChildEnv()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, "--json", "list", "--service", "test")
			cmd.Env = tc.env
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("expected CLI exit error, got %v: %s", err, output)
			}
			assertSandboxCLIRefused(t, exit.ExitCode(), output)
		})
	}
	assertSandboxInstalled(t)
}
