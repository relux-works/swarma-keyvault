//go:build darwin || linux

package budget

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Complete healthy binaries pass; incomplete/setup, per-binary timeout and an
// aggregate that incorrectly completes beyond the short limit are rejected.
// These synthetic records have no process-control side effects.
func TestRecordContract(t *testing.T) {
	healthy := []record{{11, 12, true, work}, {21, 22, true, work}, {31, 32, true, work}}
	partial := append([]record(nil), healthy...)
	partial[2].Completed, partial[2].Elapsed = false, 0
	for _, tc := range []struct {
		name     string
		records  []record
		positive bool
		wantOK   bool
	}{
		{"roomy-complete", healthy, true, true},
		{"short-refused", partial, false, true},
		{"short-incorrectly-passes", healthy, false, false},
		{"roomy-incomplete", partial, true, false},
		{"setup-failure", partial[:1], false, false},
		{"missing-witnesses", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (validateRecords(tc.records, tc.positive) == nil) != tc.wantOK {
				t.Fatal("wrong suite record verdict")
			}
		})
	}
	bad := append([]record(nil), partial...)
	bad[0].Elapsed = binaryLimit
	if validateRecords(bad, false) == nil {
		t.Fatal("a per-binary timeout must not satisfy the aggregate deadline control")
	}
}

// The actual hosted negative step must fail around its native one-minute
// deadline, after two healthy binaries complete, and leave no recorded parent
// or separate-group descendant. The positive step must complete all three.
// The hosted timeout annotation remains required evidence of the failure cause;
// this check alone does not label arbitrary failures as platform deadlines.
func TestHostedDeadlineResult(t *testing.T) {
	root := fixtureRoot(t)
	var all []record
	// Install emergency cleanup before checking outcomes/missing witnesses, so
	// even a broken fixture is drained. Successful acceptance still depends on
	// the no-survivor assertions below, before this cleanup executes.
	t.Cleanup(func() {
		for _, r := range all {
			for _, pid := range []int{r.Parent, r.Child} {
				if pid > 1 && ownedGone(pid) != nil {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	})
	for _, phase := range []string{"positive", "negative"} {
		var records []record
		for _, name := range []string{"a", "b", "c"} {
			raw, err := os.ReadFile(filepath.Join(root, phase, name+".json"))
			var r record
			if err != nil || json.Unmarshal(raw, &r) != nil {
				t.Error("missing actual fixture binary witness")
				continue
			}
			if r.Parent <= 1 || r.Child <= 1 || r.Parent == r.Child {
				t.Error("invalid actual fixture PID witness")
				continue
			}
			records = append(records, r)
		}
		all = append(all, records...)
		if err := validateRecords(records, phase == "positive"); err != nil {
			t.Error(err)
		}
	}
	if os.Getenv("KEYVAULT_SUITE_POSITIVE") != "success" || os.Getenv("KEYVAULT_SUITE_NEGATIVE") != "failure" {
		t.Error("expected roomy success and short-suite failure outcomes")
	}
	start, err := os.ReadFile(filepath.Join(root, "negative-start"))
	seconds, parseErr := strconv.ParseInt(strings.TrimSpace(string(start)), 10, 64)
	elapsed := time.Since(time.Unix(seconds, 0))
	if err != nil || parseErr != nil || elapsed < 59*time.Second || elapsed >= 90*time.Second {
		t.Error("negative result is not in the scaled suite deadline/cleanup window")
	}
	for _, r := range all {
		for _, pid := range []int{r.Parent, r.Child} {
			if err := ownedGone(pid); err != nil {
				t.Fatal(err)
			}
		}
	}
}
