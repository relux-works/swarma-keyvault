//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fixtureWitness struct{ Parent, Child, Intermediate int }

// Explicit subprocess-only fixture modes supply real separate-group leaves.
// The ordinary parent invocation does not enter a fixture mode.
func TestRunnerFixture(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	dir := os.Getenv("SUITE_FIXTURE_DIRECTORY")
	switch mode {
	case "runner-helper":
		var args []string
		if json.Unmarshal([]byte(os.Getenv("SUITE_RUNNER_ARGUMENTS")), &args) != nil {
			os.Exit(99)
		}
		os.Exit(execute(args, os.Stdin, os.Stdout, os.Stderr))
	case "late-signal-helper":
		var args []string
		if json.Unmarshal([]byte(os.Getenv("SUITE_RUNNER_ARGUMENTS")), &args) != nil {
			os.Exit(99)
		}
		o, err := parse(args)
		if err != nil {
			os.Exit(99)
		}
		ctx, stop := signalContext(context.Background())
		defer stop()
		r := supervise(ctx, o.timeout, o.command, os.Stdin, os.Stdout, os.Stderr, func(until time.Time) error {
			if os.WriteFile(filepath.Join(dir, "cleanup-ready"), []byte("ready"), 0600) != nil {
				return syscall.EIO
			}
			limit := time.Now().Add(2 * time.Second)
			for time.Now().Before(limit) && time.Now().Before(until) {
				var observed result
				observed.observeSignals(ctx)
				if hasObservation(observed, "SIGTERM") {
					return drain(until)
				}
				time.Sleep(time.Millisecond)
			}
			return context.DeadlineExceeded
		})
		raw, _ := json.Marshal(r)
		if os.WriteFile(o.report, raw, 0600) != nil {
			os.Exit(99)
		}
		os.Exit(r.ExitCode)
	case "omitted-live-reaper-helper":
		var args []string
		if json.Unmarshal([]byte(os.Getenv("SUITE_RUNNER_ARGUMENTS")), &args) != nil {
			os.Exit(99)
		}
		o, err := parse(args)
		if err != nil {
			os.Exit(99)
		}
		// Known violation: omit only active reaping, retaining real custody
		// setup and final draining so the nested group's assertion must fail.
		r := superviseWithMaintenance(context.Background(), o.timeout, o.command, os.Stdin, os.Stdout, os.Stderr,
			func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, drain, func(context.Context, int) error { return nil })
		raw, _ := json.Marshal(r)
		if os.WriteFile(o.report, raw, 0600) != nil {
			os.Exit(99)
		}
		os.Exit(r.ExitCode)
	case "omitted-cleanup-helper", "omitted-subreaper-helper":
		// Test-only known violation: claim cleanup without draining a real leaf.
		args := []string{os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-root"}
		var r result
		if mode == "omitted-cleanup-helper" {
			r = supervise(context.Background(), time.Second, args, os.Stdin, os.Stdout, os.Stderr, func(time.Time) error { return nil })
		} else {
			r = superviseWithSetup(context.Background(), time.Second, args, os.Stdin, os.Stdout, os.Stderr, func() error { return nil }, drain)
		}
		raw, _ := json.Marshal(r)
		_ = os.WriteFile(filepath.Join(dir, "result.json"), raw, 0600)
		os.Exit(r.ExitCode)
	case "fixture-leaf":
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
		for {
			if os.WriteFile(filepath.Join(dir, "leaf-ready"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0600) != nil {
				os.Exit(99)
			}
			time.Sleep(100 * time.Millisecond)
		}
	case "fixture-work":
		time.Sleep(200 * time.Millisecond)
		return
	case "fixture-intermediate":
		leaf := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-leaf")
		leaf.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if leaf.Start() != nil {
			os.Exit(99)
		}
		if os.WriteFile(filepath.Join(dir, "double-fork-leaf"), []byte(strconv.Itoa(leaf.Process.Pid)), 0600) != nil {
			os.Exit(99)
		}
		os.Exit(0) // The detached leaf is adopted before the root itself exits.
	case "fixture-nested-parent":
		nestedParentFixture(dir)
	case "fixture-root":
		if strings.HasPrefix(os.Getenv("SUITE_FIXTURE_MODE"), "nested-") {
			nestedRootFixture(dir)
			return
		}
		if os.Getenv("SUITE_FIXTURE_MODE") == "serial" {
			for i := 0; i < 3; i++ {
				child := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=1s", "fixture-work")
				if child.Run() != nil {
					os.Exit(98)
				}
				_ = os.WriteFile(filepath.Join(dir, "complete-"+strconv.Itoa(i)), []byte("complete"), 0600)
			}
			return
		}
		w := fixtureWitness{Parent: os.Getpid()}
		if os.Getenv("SUITE_FIXTURE_MODE") == "double-fork" {
			middle := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-intermediate")
			if middle.Start() != nil {
				os.Exit(99)
			}
			w.Intermediate = middle.Process.Pid
			if middle.Wait() != nil {
				os.Exit(99)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "double-fork-leaf"))
			if err != nil {
				os.Exit(99)
			}
			w.Child, err = strconv.Atoi(string(raw))
			if err != nil || w.Child <= 1 {
				os.Exit(99)
			}
		} else {
			child := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-leaf")
			child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if child.Start() != nil {
				os.Exit(99)
			}
			w.Child = child.Process.Pid
		}
		raw, _ := json.Marshal(w)
		if os.WriteFile(filepath.Join(dir, "tree.json"), raw, 0600) != nil {
			os.Exit(99)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "leaf-ready")); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		switch os.Getenv("SUITE_FIXTURE_MODE") {
		case "exit":
			os.Exit(7) // A real orphan whose parent cannot run a cleanup defer.
		case "success":
			os.Exit(0) // Successful root exit must not leave its orphan either.
		default:
			for {
				time.Sleep(time.Hour)
			}
		}
	}
}

func runnerCommand(t *testing.T, dir, mode, timeout string) *exec.Cmd {
	t.Helper()
	return runnerCommandMode(t, dir, "runner-helper", mode, timeout)
}

func runnerCommandMode(t *testing.T, dir, helper, mode, timeout string) *exec.Cmd {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("prepare owned private fixture directory", err)
	}
	args := []string{"--timeout=" + timeout, "--report=" + filepath.Join(dir, "result.json"), "--", os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-root"}
	raw, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=20s", helper)
	cmd.Env = append(os.Environ(), "SUITE_RUNNER_ARGUMENTS="+string(raw), "SUITE_FIXTURE_DIRECTORY="+dir, "SUITE_FIXTURE_MODE="+mode, "GORACE=atexit_sleep_ms=0")
	cmd.Stderr = os.Stderr
	return cmd
}

func readResult(t *testing.T, dir string) result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
	var r result
	if err != nil || json.Unmarshal(raw, &r) != nil {
		t.Fatal("missing actual runner result")
	}
	return r
}

func assertTreeGone(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "tree.json"))
	var w fixtureWitness
	if err != nil || json.Unmarshal(raw, &w) != nil || w.Parent <= 1 || w.Child <= 1 || w.Parent == w.Child {
		t.Fatal("missing actual root/leaf witness")
	}
	if err := treeGone(w); err != nil {
		t.Fatal(err)
	}
}

func treeGone(w fixtureWitness) error {
	pids := []int{w.Parent, w.Child}
	if w.Intermediate > 1 {
		pids = append(pids, w.Intermediate)
	}
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("owned PID %d remains before emergency cleanup: %v; %s", pid, err, processState(pid))
		}
	}
	return nil
}

func processState(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "state unavailable"
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "state unavailable"
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "state unavailable"
	}
	return fmt.Sprintf("state=%s ppid=%s pgid=%s sid=%s start=%s", fields[0], fields[1], fields[2], fields[3], fields[19])
}

// Successful, failed and deadline-killed roots all leave no actual separate-
// group descendant. Root exit7 stays7; the independent outer timer stays124.
// A sibling outsider survives every run and is reaped only by this test parent.
func TestOwnedTreeCustody(t *testing.T) {
	outside := t.TempDir()
	outsider := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=20s", "fixture-leaf")
	outsider.Env = append(os.Environ(), "SUITE_FIXTURE_DIRECTORY="+outside, "GORACE=atexit_sleep_ms=0")
	if err := outsider.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outsider.Process.Kill(); _ = outsider.Wait() })
	for _, tc := range []struct {
		mode, timeout, reason string
		code                  int
	}{
		{"success", "5s", "success", 0},
		{"exit", "5s", "exit", 7},
		{"hang", "1s", "deadline", 124},
		{"double-fork", "1s", "deadline", 124},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			assertOutsiderLive(t, outside)
			dir := t.TempDir()
			err := runnerCommand(t, dir, tc.mode, tc.timeout).Run()
			if tc.code == 0 && err != nil {
				t.Fatal("healthy control failed", err)
			}
			if tc.code != 0 {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != tc.code {
					t.Fatal("wrong refusal exit", err)
				}
			}
			r := readResult(t, dir)
			root := -1
			if tc.mode == "success" {
				root = 0
			}
			if tc.mode == "exit" {
				root = 7
			}
			if r.Reason != tc.reason || r.Cause != tc.reason || r.RootExit != root || r.ExitCode != tc.code || !r.Reaped {
				t.Fatal("wrong actual result", r)
			}
			assertTreeGone(t, dir)
			if err := syscall.Kill(outsider.Process.Pid, 0); err != nil {
				t.Fatal("runner harmed the outsider")
			}
			assertOutsiderLive(t, outside)
		})
	}
}

func assertOutsiderLive(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "leaf-ready")
	before, _ := os.ReadFile(path)
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		time.Sleep(20 * time.Millisecond)
		after, err := os.ReadFile(path)
		if err == nil && len(after) > 0 && string(after) != string(before) {
			return
		}
	}
	t.Fatal("outsider heartbeat did not advance")
}

// Cancellation of the dedicated runner triggers the same strict descendant
// drain as its own timer. The test sends only its exact owned helper a signal.
func TestRunnerSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) { testRunnerSignal(t, sig) })
	}
}

func testRunnerSignal(t *testing.T, sig syscall.Signal) {
	dir := t.TempDir()
	cmd := runnerCommand(t, dir, "hang", "10s")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	until := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "leaf-ready")); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("real signal fixture did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 130 {
			t.Fatal("wrong signal result", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("signal cleanup exceeded its bound")
	}
	r := readResult(t, dir)
	if r.Reason != "canceled" || r.Cause != "canceled" || r.RootExit != -1 || r.FirstSignal != map[syscall.Signal]string{syscall.SIGINT: "SIGINT", syscall.SIGTERM: "SIGTERM"}[sig] || !hasObservation(r, r.FirstSignal) || !hasObservation(r, "exit") || !r.Reaped {
		t.Fatal("signal cancellation not recorded")
	}
	assertTreeGone(t, dir)
}

// The complete serial command is bounded even though its three subprocess
// binaries are each healthy under their own one-second alarms. Positive completes
// all three; the shorter outer limit must stop before all three complete.
func TestAggregateBudget(t *testing.T) {
	for _, timeout := range []string{"5s", "500ms"} {
		t.Run(timeout, func(t *testing.T) {
			dir := t.TempDir()
			err := runnerCommand(t, dir, "serial", timeout).Run()
			r := readResult(t, dir)
			files, _ := filepath.Glob(filepath.Join(dir, "complete-*"))
			if timeout == "5s" {
				if err != nil || r.Reason != "success" || len(files) != 3 || !r.Reaped {
					t.Fatal("healthy aggregate refused", r, len(files))
				}
			} else if err == nil || r.Reason != "deadline" || r.ExitCode != 124 || len(files) == 3 || !r.Reaped {
				t.Fatal("aggregate deadline not enforced", r, len(files))
			}
		})
	}
}

// A canceled parent refuses before starting its command, preserving absence of
// the proposed effect. A missing command remains a start refusal, not timeout.
func TestStartRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	marker := filepath.Join(dir, "must-not-exist")
	r := run(ctx, time.Second, []string{"touch", marker}, nil, nil, nil)
	if r.Reason != "canceled" || r.ExitCode != 130 || !r.Reaped {
		t.Fatal("canceled start did not refuse")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("canceled start dispatched")
	}
	r = run(context.Background(), time.Second, []string{filepath.Join(dir, "missing-command")}, nil, nil, nil)
	if r.Reason != "start-refused" || r.ExitCode != 127 || !r.Reaped {
		t.Fatal(fmt.Sprint("missing executable was misclassified: ", r))
	}
}

// An injected drain refusal cannot turn a successful real root into success;
// its original root cause/status remain alongside the cleanup failure. This
// injection checks propagation, not a naturally occurring kernel refusal.
func TestCleanupRefusal(t *testing.T) {
	for _, fault := range []error{syscall.EPERM, context.DeadlineExceeded} {
		r := supervise(context.Background(), time.Second, []string{"/bin/true"}, nil, nil, nil, func(time.Time) error { return fault })
		if r.Reason != "cleanup-refused" || r.Cause != "success" || r.RootExit != 0 || r.ExitCode != 125 || r.Reaped {
			t.Fatal("cleanup refusal lost cause or returned success", r)
		}
	}
}

// Required subreaper setup failure forbids command dispatch; the absent marker
// checks the intended no-child effect. The injected error is not a kernel probe.
func TestSubreaperRefusal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	r := superviseWithSetup(context.Background(), time.Second, []string{"touch", marker}, nil, nil, nil, func() error { return syscall.EPERM }, drain)
	if r.Reason != "subreaper-refused" || r.Cause != "subreaper-refused" || r.ExitCode != 125 || r.Reaped {
		t.Fatal("setup refusal did not fail closed", r)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("refused setup dispatched a command")
	}
}

// A known omitted drain leaves an actual detached leaf; the same strict
// absence probe used by positive lifecycle controls rejects it. This parent
// adopts, kills and reaps that exact synthetic leaf after observing rejection.
func TestCleanupOmissionControl(t *testing.T) {
	for _, mode := range []string{"omitted-cleanup-helper", "omitted-subreaper-helper"} {
		t.Run(mode, func(t *testing.T) { testCleanupOmission(t, mode) })
	}
}

func testCleanupOmission(t *testing.T, mode string) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", mode)
	cmd.Env = append(os.Environ(), "SUITE_FIXTURE_DIRECTORY="+dir, "SUITE_FIXTURE_MODE=hang", "GORACE=atexit_sleep_ms=0")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 124 {
		t.Fatal("known omission did not reach its actual deadline", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tree.json"))
	var w fixtureWitness
	if err != nil || json.Unmarshal(raw, &w) != nil || w.Child <= 1 || w.Parent <= 1 {
		t.Fatal("known omission lacks actual process witnesses")
	}
	t.Cleanup(func() {
		_ = syscall.Kill(w.Child, syscall.SIGKILL)
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			var status unix.WaitStatus
			pid, err := unix.Wait4(w.Child, &status, unix.WNOHANG, nil)
			if pid == w.Child || errors.Is(err, unix.ECHILD) {
				return
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				t.Error("known omission emergency reap refused")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("known omission emergency reap exceeded its bound")
	})
	r := readResult(t, dir)
	if !r.Reaped || r.Reason != "deadline" {
		t.Fatal("known omission did not produce the intended false cleanup claim")
	}
	if err := treeGone(w); err == nil {
		t.Fatal("strict absence checker missed the actual omitted cleanup")
	} else {
		t.Logf("known ownership omission rejected: %v", err)
	}
}
