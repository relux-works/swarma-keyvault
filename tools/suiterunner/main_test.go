package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The admitted option grammar accepts bounded budgets and an explicit command
// boundary; malformed, repeated, unknown and oversized options refuse.
func TestArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--", "go", "test", "./..."},
		{"--timeout=1m", "--report=/tmp/result.json", "--", "go", "test"},
		{"--timeout=30m", "--", "go"},
	} {
		if _, err := parse(args); err != nil {
			t.Fatal("valid invocation refused")
		}
	}
	for _, args := range [][]string{
		nil, {"go", "test"}, {"--"}, {"--", ""},
		{"--timeout=0", "--", "go"}, {"--timeout=-1s", "--", "go"},
		{"--timeout=31m", "--", "go"}, {"--timeout=invalid", "--", "go"},
		{"--timeout=1m", "--timeout=2m", "--", "go"},
		{"--unknown=1", "--", "go"}, {"--report=relative", "--", "go"},
		{"--report=/tmp/a/../result", "--", "go"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatal("invalid invocation accepted")
		}
	}
	o, err := parse([]string{"--timeout=200ms", "--", "go"})
	if err != nil || o.timeout != 200*time.Millisecond {
		t.Fatal("scaled deadline was not preserved")
	}
}

// Report creation fails before dispatch for existing files and public parents;
// the existing bytes are retained. A fresh private report reaches the actual
// missing-command/unsupported result instead of the argument rejection.
func TestReportRefusals(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, "result.json")
	if err := os.WriteFile(report, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	validReport := filepath.Join(dir, "new-result.json")
	code := execute([]string{"--report=" + validReport, "--", "missing-fixture-command"}, devnull, devnull, devnull)
	var valid result
	created, readErr := os.ReadFile(validReport)
	if (code != 125 && code != 127) || readErr != nil || json.Unmarshal(created, &valid) != nil || valid.ExitCode != code {
		t.Fatal("private report positive neighbor did not reach execution/refusal classification")
	}

	if code := execute([]string{"--report=" + report, "--", "missing-fixture-command"}, devnull, devnull, devnull); code != 64 {
		t.Fatal("existing report did not refuse before command dispatch")
	}
	raw, err := os.ReadFile(report)
	if err != nil || string(raw) != "retained" {
		t.Fatal("existing result changed")
	}
	public := filepath.Join(dir, "public")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if code := execute([]string{"--report=" + filepath.Join(public, "result"), "--", "missing-fixture-command"}, devnull, devnull, devnull); code != 64 {
		t.Fatal("nonprivate report parent did not refuse")
	}
}
