//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A refused ownership enumerator prevents the actual marker command. Its
// working neighbor dispatches that command and completes genuine final drain.
func TestOwnershipPrerequisite(t *testing.T) {
	for _, fail := range []bool{false, true} {
		marker := filepath.Join(t.TempDir(), "marker")
		enum := directChildren
		if fail {
			enum = func() (map[int]bool, error) { return nil, syscall.EACCES }
		}
		r := superviseWithOwnership(context.Background(), time.Second, []string{"/usr/bin/touch", marker}, nil, nil, nil, func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, drain, reapExitedChildren, enum)
		_, err := os.Stat(marker)
		if fail {
			if r.Reason != "ownership-refused" || r.Cause != "ownership-refused" || r.ExitCode != 125 || r.Reaped || !os.IsNotExist(err) {
				t.Fatal("unavailable ownership dispatched or misreported", r, err)
			}
		} else if r.Reason != "success" || !r.Reaped || err != nil {
			t.Fatal("working ownership refused marker", r, err)
		}
	}
}

// These fault controls invoke the production drain loop with synthetic syscalls
// only. Actual clock guards must reject late ECHILD, EINTR and reaped-child
// churn; an immediate valid ECHILD must still pass. No real PID is signaled.
func TestDrainAbsoluteClock(t *testing.T) {
	empty := func() (map[int]bool, error) { return map[int]bool{}, nil }
	noKill := func(int, syscall.Signal) error { t.Fatal("unexpected synthetic kill"); return nil }
	for _, mode := range []string{"good", "late-ECHILD", "EINTR", "reaped-churn"} {
		t.Run(mode, func(t *testing.T) {
			until := time.Now().Add(20 * time.Millisecond)
			calls := 0
			wait := func(_ int, _ *unix.WaitStatus, _ int, _ *unix.Rusage) (int, error) {
				calls++
				switch mode {
				case "good":
					return -1, unix.ECHILD
				case "late-ECHILD":
					time.Sleep(time.Until(until) + 10*time.Millisecond)
					return -1, unix.ECHILD
				case "EINTR":
					time.Sleep(time.Millisecond)
					return -1, unix.EINTR
				default:
					time.Sleep(time.Millisecond)
					return 10, nil
				}
			}
			err := drainWithOperations(until, empty, wait, noKill)
			if calls == 0 || (mode == "good" && err != nil) || (mode != "good" && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("drain clock accepted late completion or rejected control", err)
			}
		})
	}
	calls := 0
	err := drainWithOperations(time.Now().Add(time.Second), func() (map[int]bool, error) { return nil, syscall.EACCES }, func(int, *unix.WaitStatus, int, *unix.Rusage) (int, error) { calls++; return -1, unix.ECHILD }, noKill)
	if !errors.Is(err, syscall.EACCES) || calls != 0 {
		t.Fatal("final enumeration failure was bypassed", err)
	}
}

// The caller independently refuses a nil cleanup returned after the real five
// second allowance. Its quick genuine-drain neighbor remains successful.
func TestLateCleanupCompletion(t *testing.T) {
	for _, late := range []bool{false, true} {
		cleanup := drain
		if late {
			cleanup = func(until time.Time) error { time.Sleep(time.Until(until) + 10*time.Millisecond); return nil }
		}
		r := supervise(context.Background(), 30*time.Second, []string{"/bin/true"}, nil, nil, nil, cleanup)
		if late {
			if r.Reason != "cleanup-refused" || r.Cause != "success" || r.RootExit != 0 || r.ExitCode != 125 || r.Reaped {
				t.Fatal("late nil cleanup accepted", r)
			}
		} else if r.Reason != "success" || !r.Reaped {
			t.Fatal("within-budget cleanup refused", r)
		}
	}
}

// Exact active waits preserve live/root PIDs, consume terminated non-roots,
// refresh ECHILD, and refuse contradictory ownership or syscall/enumerator
// errors. Injected waits supplement the real nested-process regression.
func TestActiveWaitTransitions(t *testing.T) {
	for _, mode := range []string{"live", "exited", "refreshed", "contradictory", "wait-fault", "enum-fault", "wrong-pid", "stopped", "EINTR"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			enums, calls := 0, 0
			enum := func() (map[int]bool, error) {
				enums++
				if mode == "enum-fault" {
					return nil, unix.EACCES
				}
				if mode == "refreshed" && enums > 1 {
					return map[int]bool{}, nil
				}
				return map[int]bool{100: true, 101: true}, nil
			}
			wait := func(pid int, status *unix.WaitStatus, _ int, _ *unix.Rusage) (int, error) {
				calls++
				if pid != 101 {
					t.Fatal("root wait stolen")
				}
				switch mode {
				case "live":
					return 0, nil
				case "exited":
					*status = 0
					return pid, nil
				case "wrong-pid":
					return 102, nil
				case "stopped":
					*status = unix.WaitStatus(0x7f)
					return pid, nil
				case "wait-fault":
					return -1, unix.EPERM
				case "EINTR":
					time.Sleep(time.Millisecond)
					return -1, unix.EINTR
				default:
					return -1, unix.ECHILD
				}
			}
			err := reapExitedChildrenWith(ctx, 100, enum, wait)
			refused := mode == "contradictory" || mode == "wait-fault" || mode == "enum-fault" || mode == "wrong-pid" || mode == "stopped"
			if (err != nil) != refused || (mode != "enum-fault" && calls == 0) || (mode == "EINTR" && ctx.Err() == nil) {
				t.Fatal("wrong active wait transition", mode, err, calls)
			}
		})
	}
}

// A cancellation already observed alongside an active fault wins the agreed
// tie; the active fault remains recorded even if final cleanup also refuses.
func TestConcurrentActiveRefusal(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		cleanup := drain
		if failCleanup {
			cleanup = func(time.Time) error { return unix.EPERM }
		}
		r := superviseWithMaintenance(ctx, 10*time.Second, []string{"/bin/sleep", "5"}, nil, nil, nil, func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, cleanup, func(context.Context, int) error { cancel(); return unix.EPERM })
		cancel()
		reason := "active-reap-refused"
		if failCleanup {
			reason = "cleanup-refused"
		}
		if r.Cause != "canceled" || r.Reason != reason || r.ExitCode != 125 || r.RootExit != -1 || r.Reaped == failCleanup || !hasObservation(r, "active-reap-refused") || !hasObservation(r, "exit") {
			t.Fatal("competing refusal lost primary or observation", r)
		}
	}
}

// Two actual signals reach one owned helper. The second arrives only after
// cleanup begins; it must be recorded without bypassing drain or relabeling the
// first-signal primary. The delayed cleanup is test-only synchronization.
func TestLaterSignalDuringCleanup(t *testing.T) {
	dir := t.TempDir()
	cmd := runnerCommandMode(t, dir, "late-signal-helper", "hang", "10s")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()
	waitFile := func(name string) {
		t.Helper()
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("missing actual fixture phase %s", name)
	}
	waitFile("leaf-ready")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	waitFile("cleanup-ready")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("signal helper reported success")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("late signal bypassed bounded completion")
	}
	r := readResult(t, dir)
	if r.Reason != "canceled" || r.Cause != "canceled" || r.ExitCode != 130 || r.RootExit != -1 || !r.Reaped || r.FirstSignal != "SIGINT" || !hasObservation(r, "SIGINT") || !hasObservation(r, "SIGTERM") || !hasObservation(r, "exit") {
		t.Fatal("later signal erased first or cleanup", r)
	}
	assertTreeGone(t, dir)
}

// Persistent injected EINTR in active maintenance returns at the actual run
// deadline. Same-goroutine maintenance has no separate join; the real root wait
// and final drain complete within the original single cleanup allowance.
func TestActiveEINTRAtDeadline(t *testing.T) {
	calls := 0
	maintain := func(ctx context.Context, root int) error {
		return reapExitedChildrenWith(ctx, root, func() (map[int]bool, error) { return map[int]bool{root: true, root + 1: true}, nil }, func(pid int, _ *unix.WaitStatus, _ int, _ *unix.Rusage) (int, error) {
			if pid == root {
				t.Fatal("root status stolen")
			}
			calls++
			time.Sleep(time.Millisecond)
			return -1, unix.EINTR
		})
	}
	start := time.Now()
	r := superviseWithMaintenance(context.Background(), 80*time.Millisecond, []string{"/bin/sleep", "10"}, nil, nil, nil, func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, drain, maintain)
	if calls < 2 || r.Reason != "deadline" || r.Cause != "deadline" || r.RootExit != -1 || !r.Reaped || r.ExitCode != 124 || hasObservation(r, "active-reap-refused") || time.Since(start) >= 80*time.Millisecond+cleanupBudget {
		t.Fatal("active EINTR escaped deadline or invented fault", r)
	}
}
