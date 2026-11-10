//go:build darwin || linux

package budget

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

// Separate real own-deadline and native-cancellation steps stop during the third
// healthy binary, report their actual distinct cause and leave no recorded
// parent/descendant. Positive completes all three; an outsider must survive.
// The same-attempt native annotation is separately required for native cause.
func TestHostedDeadlineResult(t *testing.T) {
	root := fixtureRoot(t)
	var all []record
	labels := make(map[int]string)
	var outsider int
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
		if outsider > 1 {
			_ = syscall.Kill(outsider, syscall.SIGKILL)
		}
	})
	for _, phase := range []string{"positive", "deadline", "native"} {
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
			labels[r.Parent] = phase + "/" + name + "/parent"
			labels[r.Child] = phase + "/" + name + "/descendant"
		}
		all = append(all, records...)
		if err := validateRecords(records, phase == "positive"); err != nil {
			t.Error(err)
		}
		raw, err := os.ReadFile(filepath.Join(root, phase+"-result.json"))
		var result runnerResult
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
			t.Error("missing strict actual supervisor result")
		} else if err := validateResult(result, phase); err != nil {
			t.Error(err)
		}
	}
	if os.Getenv("KEYVAULT_SUITE_POSITIVE") != "success" || os.Getenv("KEYVAULT_SUITE_DEADLINE") != "failure" || os.Getenv("KEYVAULT_SUITE_NEGATIVE") != "failure" {
		t.Error("expected roomy success and distinct own/native failure outcomes")
	}
	start, err := os.ReadFile(filepath.Join(root, "native-start"))
	seconds, parseErr := strconv.ParseInt(strings.TrimSpace(string(start)), 10, 64)
	elapsed := time.Since(time.Unix(seconds, 0))
	if err != nil || parseErr != nil || elapsed < 59*time.Second || elapsed >= 90*time.Second {
		t.Error("native result is not in the scaled suite deadline/cleanup window")
	}
	raw, err := os.ReadFile(filepath.Join(root, "outsider.pid"))
	outsider, parseErr = strconv.Atoi(strings.TrimSpace(string(raw)))
	_, readyErr := os.Stat(filepath.Join(root, "outsider", "a.json.ready"))
	if err != nil || parseErr != nil || outsider <= 1 || readyErr != nil || syscall.Kill(outsider, 0) != nil {
		t.Error("independent outsider did not remain alive")
	}
	heartbeat := filepath.Join(root, "outsider", "a.json.ready")
	before, _ := os.ReadFile(heartbeat)
	advanced := false
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		time.Sleep(20 * time.Millisecond)
		after, err := os.ReadFile(heartbeat)
		if err == nil && len(after) > 0 && string(after) != string(before) {
			advanced = true
			break
		}
	}
	if !advanced {
		t.Error("outsider heartbeat did not advance after both interruptions")
	}
	for _, r := range all {
		for _, pid := range []int{r.Parent, r.Child} {
			if err := ownedGone(pid); err != nil {
				t.Fatalf("%s: %v", labels[pid], err)
			}
		}
	}
}

type runnerResult struct {
	Reason         string   `json:"reason"`
	Cause          string   `json:"cause"`
	ExitCode       int      `json:"exit_code"`
	RootExit       int      `json:"root_exit"`
	Reaped         bool     `json:"reaped"`
	ElapsedNS      int64    `json:"elapsed_ns"`
	FirstSignal    string   `json:"first_signal"`
	ObservedCauses []string `json:"observed_causes"`
}

func validateResult(r runnerResult, phase string) error {
	seen := make(map[string]bool)
	first := ""
	for _, cause := range r.ObservedCauses {
		switch cause {
		case "success", "exit", "deadline", "canceled", "SIGINT", "SIGTERM":
		default:
			return errors.New("unexpected observed cause")
		}
		if seen[cause] {
			return errors.New("duplicate observed cause")
		}
		seen[cause] = true
		if first == "" && (cause == "SIGINT" || cause == "SIGTERM") {
			first = cause
		}
	}
	if first != r.FirstSignal || !seen[r.Cause] || !r.Reaped || r.Cause != r.Reason {
		return errors.New("supervisor did not establish ECHILD")
	}
	switch phase {
	case "positive":
		if r.FirstSignal != "" || seen["SIGINT"] || seen["SIGTERM"] || seen["canceled"] || seen["deadline"] || seen["exit"] {
			return errors.New("unexpected healthy trigger")
		}
		if r.Reason != "success" || r.ExitCode != 0 || r.RootExit != 0 || r.ElapsedNS < int64(3*work) || r.ElapsedNS >= int64(2*time.Minute) {
			return errors.New("healthy supervisor control did not complete")
		}
	case "deadline":
		if r.FirstSignal != "" || seen["SIGINT"] || seen["SIGTERM"] || r.RootExit != -1 || !seen["exit"] || r.Reason != "deadline" || r.ExitCode != 124 || r.ElapsedNS < int64(time.Minute) || r.ElapsedNS >= int64(time.Minute+5*time.Second) {
			return errors.New("supervisor own deadline did not fire and clean within its bound")
		}
	case "native":
		if (r.FirstSignal != "SIGINT" && r.FirstSignal != "SIGTERM") || !seen[r.FirstSignal] || r.RootExit != -1 || !seen["exit"] || r.Reason != "canceled" || r.ExitCode != 130 || r.ElapsedNS < int64(59*time.Second) || r.ElapsedNS >= int64(90*time.Second) {
			return errors.New("native cancellation did not reach the supervisor")
		}
	default:
		return errors.New("unknown supervisor phase")
	}
	return nil
}

// Correct own-deadline and native-signal results have separate causes. Generic
// exit, setup/cleanup refusal, late cleanup and false success cannot substitute.
func TestRunnerResultContract(t *testing.T) {
	valid := map[string]runnerResult{
		"positive": {Reason: "success", Cause: "success", ExitCode: 0, RootExit: 0, Reaped: true, ElapsedNS: int64(3 * work), ObservedCauses: []string{"success"}},
		"deadline": {Reason: "deadline", Cause: "deadline", ExitCode: 124, RootExit: -1, Reaped: true, ElapsedNS: int64(time.Minute), ObservedCauses: []string{"deadline", "exit"}},
		"native":   {Reason: "canceled", Cause: "canceled", ExitCode: 130, RootExit: -1, Reaped: true, ElapsedNS: int64(time.Minute), FirstSignal: "SIGINT", ObservedCauses: []string{"canceled", "SIGINT", "exit"}},
	}
	for phase, r := range valid {
		if err := validateResult(r, phase); err != nil {
			t.Fatal(err)
		}
		mutations := []func(*runnerResult){
			func(b *runnerResult) { b.Reaped = false }, func(b *runnerResult) { b.Reason = "exit" },
			func(b *runnerResult) { b.Reason = "cleanup-refused"; b.ExitCode = 125 },
			func(b *runnerResult) { b.ElapsedNS = 0 }, func(b *runnerResult) { b.ElapsedNS = int64(3 * time.Minute) },
			func(b *runnerResult) { b.RootExit = -2 }, func(b *runnerResult) { b.RootExit = 7 },
			func(b *runnerResult) { b.FirstSignal = "SIGKILL" },
			func(b *runnerResult) {
				b.FirstSignal = "SIGTERM"
				b.ObservedCauses = []string{b.Cause, "SIGINT", "SIGTERM", "exit"}
			}, func(b *runnerResult) { b.ObservedCauses = nil },
			func(b *runnerResult) { b.ObservedCauses = append(append([]string{}, b.ObservedCauses...), b.Cause) },
			func(b *runnerResult) { b.ObservedCauses = append(append([]string{}, b.ObservedCauses...), "invented") },
		}
		for _, mutate := range mutations {
			bad := r
			mutate(&bad)
			if validateResult(bad, phase) == nil {
				t.Fatalf("corrupt %s result accepted: %+v", phase, bad)
			}
		}

	}
	if validateResult(valid["native"], "deadline") == nil || validateResult(valid["deadline"], "native") == nil {
		t.Fatal("own deadline and native cancellation were conflated")
	}
}
