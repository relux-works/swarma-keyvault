package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This fixture reader covers the shipped job layout, not arbitrary YAML.
// Actionlint separately validates the complete workflow syntax/expressions.
func diagnosticGoGuard(workflow string) (string, error) {
	_, job, found := strings.Cut(workflow, "\n  verifier-attribution:\n")
	if !found {
		return "", errors.New("diagnostic job missing")
	}
	if strings.Count(job, "uses: actions/setup-go@") != 1 {
		return "", errors.New("one shared setup-go step required")
	}
	_, setup, _ := strings.Cut(job, "uses: actions/setup-go@")
	setup, _, _ = strings.Cut(setup, "\n      - name:")
	fixed := regexp.MustCompile(`(?m)^          go-version: (?:1\.26\.10|'1\.26\.10'|"1\.26\.10") *$`)
	if !fixed.MatchString(setup) {
		return "", errors.New("diagnostic setup requires explicit Go1.26.10")
	}
	const guard = `test "$(go env GOVERSION)" = go1.26.10`
	where := strings.Index(job, "\n          "+guard+"\n")
	build := strings.Index(job, "\n          go test -race -count=1 ./tools/verifierdiagnostic\n")
	if where < 0 || build < 0 || where >= build {
		return "", errors.New("shared Go version guard missing or late")
	}
	return guard, nil
}

func shippedWorkflow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "hosted-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The shipped setup explicitly pins the agreed SDK before preparation. The
// historical file-only selection (main go1.26.0), wrong pin and missing/late
// runtime guard reject the exact contract, beside accepted literal YAML forms.
func TestWorkflowToolchainContract(t *testing.T) {
	actual := shippedWorkflow(t)
	guard, err := diagnosticGoGuard(actual)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.26.10", "'1.26.10'", `"1.26.10"`} {
		valid := strings.Replace(actual, "go-version: '1.26.10'", "go-version: "+version, 1)
		if got, err := diagnosticGoGuard(valid); err != nil || got != guard {
			t.Fatal("valid literal pin refused", err)
		}
	}
	for _, name := range []string{"historical-file-only", "wrong-version", "missing-guard", "late-guard"} {
		t.Run(name, func(t *testing.T) {
			bad := actual
			want := "diagnostic setup requires explicit Go1.26.10"
			switch name {
			case "historical-file-only":
				bad = strings.Replace(bad, "go-version: '1.26.10'", "go-version-file: go.mod", 1)
			case "wrong-version":
				bad = strings.Replace(bad, "go-version: '1.26.10'", "go-version: '1.26.0'", 1)
			case "missing-guard", "late-guard":
				bad = strings.Replace(bad, "          "+guard+"\n", "", 1)
				if name == "late-guard" {
					bad = strings.Replace(bad, "          go test -race -count=1 ./tools/verifierdiagnostic\n", "          go test -race -count=1 ./tools/verifierdiagnostic\n          "+guard+"\n", 1)
				}
				want = "shared Go version guard missing or late"
			}
			if _, err := diagnosticGoGuard(bad); err == nil || err.Error() != want {
				t.Fatalf("wrong contract refusal %v; want %s", err, want)
			}
		})
	}
}

// Execute the actual shipped guard with a Go-only version-provider fixture.
// Correct argv and a successful provider are witnessed independently; old and
// neighboring versions fail the guard, rather than failing fixture setup.
// This does not execute GitHub setup-go or a Linux collection.
func TestShippedGoVersionGuard(t *testing.T) {
	guard, err := diagnosticGoGuard(shippedWorkflow(t))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"go1.26.10", "go1.26.0", "go1.26.9"} {
		t.Run(version, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.Symlink(executable, filepath.Join(bin, "go")); err != nil {
				t.Fatal(err)
			}
			witness := filepath.Join(bin, "call.txt")
			t.Setenv("PATH", bin)
			t.Setenv("VERIFIER_DIAG_GO_VERSION_FIXTURE", version)
			t.Setenv("VERIFIER_DIAG_GO_CALL_FIXTURE", witness)
			cmd := exec.Command("/bin/bash", "-euc", guard)
			output, err := cmd.CombinedOutput()
			if len(output) != 0 {
				t.Fatalf("unexpected guard output %q", output)
			}
			got, readErr := os.ReadFile(witness)
			if readErr != nil || string(got) != "env GOVERSION\n" {
				t.Fatalf("provider not exercised correctly: %s %v", got, readErr)
			}
			if version == "go1.26.10" {
				if err != nil {
					t.Fatal("correct selected version refused", err)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("wrong version did not fail guard with exit1: %v", err)
				}
			}
		})
	}
}
