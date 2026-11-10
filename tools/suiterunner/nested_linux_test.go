//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nestedWitness struct{ Root, Middle, Dead, Live, Supervisor int }
type nestedObservation struct {
	Phase, Role, RootState, DeadState, LiveState string
	GroupAbsent, LiveAdvancing                   bool
}

func writeNestedFixture(dir, name string, value any) {
	raw, err := json.Marshal(value)
	if err != nil || os.WriteFile(filepath.Join(dir, name), raw, 0600) != nil {
		os.Exit(96)
	}
}

func nestedParentFixture(dir string) {
	start := func(name string, detached bool) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-leaf")
		cmd.Env = append(os.Environ(), "SUITE_FIXTURE_DIRECTORY="+filepath.Join(dir, name))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: detached}
		if cmd.Start() != nil {
			os.Exit(96)
		}
		return cmd
	}
	dead, live := start("dead", false), start("live", true)
	w := nestedWitness{Root: os.Getppid(), Middle: os.Getpid(), Dead: dead.Process.Pid, Live: live.Process.Pid}
	writeNestedFixture(dir, "nested-tree.json", w)
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		_, a := os.Stat(filepath.Join(dir, "dead", "leaf-ready"))
		_, b := os.Stat(filepath.Join(dir, "live", "leaf-ready"))
		if a == nil && b == nil {
			os.Exit(0) // Both leaves become adopted while the outer root lives.
		}
		time.Sleep(5 * time.Millisecond)
	}
	os.Exit(96)
}

func nestedRootFixture(dir string) {
	for _, name := range []string{"dead", "live"} {
		if os.Mkdir(filepath.Join(dir, name), 0700) != nil {
			os.Exit(96)
		}
	}
	middle := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=15s", "fixture-nested-parent")
	middle.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if middle.Start() != nil || middle.Wait() != nil {
		os.Exit(96)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "nested-tree.json"))
	var w nestedWitness
	if err != nil || json.Unmarshal(raw, &w) != nil || w.Root != os.Getpid() || w.Middle != middle.Process.Pid || w.Dead <= 1 || w.Live <= 1 || w.Dead == w.Live {
		os.Exit(96)
	}
	w.Supervisor = os.Getppid()
	writeNestedFixture(dir, "nested-tree.json", w)
	before, err := os.ReadFile(filepath.Join(dir, "live", "leaf-ready"))
	if err != nil || syscall.Kill(-w.Middle, syscall.SIGKILL) != nil {
		os.Exit(96)
	}
	o := nestedObservation{Phase: "group-absence-before-root-exit", Role: "terminated-adopted-leaf"}
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if errors.Is(syscall.Kill(-w.Middle, 0), syscall.ESRCH) {
			o.GroupAbsent = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	until = time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		after, err := os.ReadFile(filepath.Join(dir, "live", "leaf-ready"))
		if err == nil && string(before) != string(after) && syscall.Kill(w.Live, 0) == nil {
			o.LiveAdvancing = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	o.RootState, o.DeadState, o.LiveState = processState(w.Root), processState(w.Dead), processState(w.Live)
	writeNestedFixture(dir, "nested-observation.json", o)
	if !o.LiveAdvancing {
		os.Exit(88)
	}
	if !o.GroupAbsent {
		os.Exit(87) // The omission plant must reach this exact assertion.
	}
	if os.Getenv("SUITE_FIXTURE_MODE") == "nested-exit" {
		os.Exit(7)
	}
	os.Exit(0)
}

// A nested group disappears while the root is still alive, without killing a
// live adopted leaf or sibling outsider. Root0/7 stay0/7. Omitting active reaping
// must instead reach the exact group-absence refusal with an adopted zombie;
// its later successful final drain cannot erase that regression witness.
func TestNestedGroupsUnderLiveRoot(t *testing.T) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	outdir := t.TempDir()
	outside := exec.Command(os.Args[0], "-test.run=^TestRunnerFixture$", "-test.timeout=25s", "fixture-leaf")
	outside.Env = append(os.Environ(), "SUITE_FIXTURE_DIRECTORY="+outdir, "GORACE=atexit_sleep_ms=0")
	if err := outside.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outside.Process.Kill(); _ = outside.Wait() })
	for _, tc := range []struct {
		name, helper, mode string
		code               int
	}{
		{"success", "runner-helper", "nested-success", 0},
		{"root-failure", "runner-helper", "nested-exit", 7},
		{"repeated-0-success", "runner-helper", "nested-success", 0},
		{"repeated-0-exit", "runner-helper", "nested-exit", 7},
		{"repeated-1-success", "runner-helper", "nested-success", 0},
		{"repeated-1-exit", "runner-helper", "nested-exit", 7},
		{"repeated-2-success", "runner-helper", "nested-success", 0},
		{"repeated-2-exit", "runner-helper", "nested-exit", 7},
		{"omitted-active-reaper", "omitted-live-reaper-helper", "nested-success", 87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertOutsiderLive(t, outdir)
			dir := t.TempDir()
			err := runnerCommandMode(t, dir, tc.helper, tc.mode, "8s").Run()
			raw, readErr := os.ReadFile(filepath.Join(dir, "nested-tree.json"))
			var w nestedWitness
			if readErr != nil || json.Unmarshal(raw, &w) != nil || w.Root <= 1 || w.Middle <= 1 || w.Dead <= 1 || w.Live <= 1 || w.Supervisor <= 1 {
				t.Fatal("nested fixture did not reach actual owned process startup")
			}
			t.Cleanup(func() { emergencyReapNested(t, w) })
			var exit *exec.ExitError
			if (tc.code == 0 && err != nil) || (tc.code != 0 && (!errors.As(err, &exit) || exit.ExitCode() != tc.code)) {
				t.Fatal("wrong actual nested root outcome", err)
			}
			r := readResult(t, dir)
			reason := "exit"
			if tc.code == 0 {
				reason = "success"
			}
			if r.Reason != reason || r.Cause != reason || r.RootExit != tc.code || r.ExitCode != tc.code || !r.Reaped {
				t.Fatal("root status stolen or final cleanup unqualified", r)
			}
			raw, readErr = os.ReadFile(filepath.Join(dir, "nested-observation.json"))
			var o nestedObservation
			if readErr != nil || json.Unmarshal(raw, &o) != nil || !o.LiveAdvancing || o.Phase != "group-absence-before-root-exit" || o.Role != "terminated-adopted-leaf" {
				t.Fatal("nested assertion or live-adopted control was not reached")
			}
			if !strings.Contains(o.LiveState, "ppid="+strconv.Itoa(w.Supervisor)+" ") || strings.HasPrefix(o.RootState, "state=Z ") || !strings.HasPrefix(o.RootState, "state=") {
				t.Fatal("live-root/adopted ownership witness missing", o)
			}
			if tc.code == 87 {
				if o.GroupAbsent || !strings.HasPrefix(o.DeadState, "state=Z ") || !strings.Contains(o.DeadState, "ppid="+strconv.Itoa(w.Supervisor)+" ") {
					t.Fatal("omission did not produce the intended adopted-zombie group witness", o)
				}
				t.Logf("known active-reaping omission rejected phase=%s role=%s root={%s} dead={%s} live={%s}", o.Phase, o.Role, o.RootState, o.DeadState, o.LiveState)
			} else if !o.GroupAbsent {
				t.Fatal("healthy live-root nested group did not disappear", o)
			}
			for _, pid := range []int{w.Root, w.Middle, w.Dead, w.Live} {
				if !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
					t.Fatalf("owned nested PID remains before emergency cleanup: %d; %s", pid, processState(pid))
				}
			}
			assertOutsiderLive(t, outdir)
		})
	}
}

// Emergency cleanup first proves exact current child ownership with wait4.
// Already reaped/nonchild PIDs are never signaled; one bounded budget covers
// only this synthetic witness, in parent-before-descendant adoption order.
func emergencyReapNested(t *testing.T, w nestedWitness) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for _, child := range []int{w.Root, w.Middle, w.Dead, w.Live} {
		for {
			if time.Now().After(until) {
				t.Error("owned nested emergency reaping exceeded its bound")
				return
			}
			var status unix.WaitStatus
			pid, err := unix.Wait4(child, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.ECHILD) || pid == child {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				t.Error("owned nested emergency wait refused", err)
				return
			}
			if err := unix.Kill(child, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				t.Error("owned nested emergency termination refused", err)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// Injected active enumeration/wait failure refuses and starts bounded cleanup;
// final cleanup success still records ECHILD, while a second injected refusal
// overrides only the final reason. These are propagation tests, not kernel faults.
func TestActiveReapRefusal(t *testing.T) {
	setup := func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }
	good := superviseWithMaintenance(context.Background(), 3*time.Second, []string{"/bin/sleep", "0.08"}, nil, nil, nil, setup, drain, func(context.Context, int) error { return nil })
	if good.Reason != "success" || good.RootExit != 0 || !good.Reaped {
		t.Fatal("healthy maintenance control refused", good)
	}
	for _, refuseCleanup := range []bool{false, true} {
		cleanup := drain
		reason := "active-reap-refused"
		if refuseCleanup {
			cleanup = func(time.Time) error { return syscall.EPERM }
			reason = "cleanup-refused"
		}
		var faultAt time.Time
		r := superviseWithMaintenance(context.Background(), 15*time.Second, []string{"/bin/sleep", "10"}, nil, nil, nil, setup, cleanup, func(context.Context, int) error {
			faultAt = time.Now()
			return syscall.EPERM
		})
		if faultAt.IsZero() || time.Since(faultAt) >= cleanupBudget+250*time.Millisecond || r.Reason != reason || r.Cause != "active-reap-refused" || r.RootExit != -1 || r.ExitCode != 125 || r.Reaped == refuseCleanup {
			t.Fatal("active refusal lost its cause or cleanup result", r)
		}
	}
}
