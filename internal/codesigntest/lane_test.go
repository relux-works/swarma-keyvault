package codesigntest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Disabled and unsupported invocations never reach the inherited native lane.
// Exact selection, single worker and one execution reach it once.
func TestAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, env, selection, parallel, count string
		admitted                              bool
		skip                                  bool
	}{
		{"unset", "", RecoverySelection, "1", "1", false, true},
		{"disabled", "0", RecoverySelection, "1", "1", false, true},
		{"other opt-in spelling", "true", RecoverySelection, "1", "1", false, true},
		{"unrelated filter", "1", "^TestSSH$", "1", "1", false, false},
		{"unfiltered", "1", "", "1", "1", false, false},
		{"parallel", "1", KEKSelection, "2", "1", false, false},
		{"repeated", "1", KEKSelection, "1", "2", false, false},
		{"recovery", "1", RecoverySelection, "1", "1", true, false},
		{"kek", "1", KEKSelection, "1", "1", true, false},
		{"certificate", "1", CertificateSelection, "1", "1", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run, err := admit(tc.env, tc.selection, tc.parallel, tc.count,
				[]string{RecoverySelection, KEKSelection, CertificateSelection},
				func() (string, error) { calls++; return "run-witness", nil })
			if tc.admitted {
				if err != nil || run != "run-witness" || calls != 1 {
					t.Fatalf("admission = %q, %v, %d calls", run, err, calls)
				}
			} else if err == nil || errors.Is(err, errDisabled) != tc.skip || run != "" || calls != 0 {
				t.Fatalf("refusal = %q, %v, %d calls", run, err, calls)
			}
		})
	}
}

// Two callers share the same fixture build or its failure. A retry cannot
// rebuild another executable in the same run.
func TestBuildOnce(t *testing.T) {
	for _, failure := range []error{nil, errors.New("build failed")} {
		var build BuildOnce
		attempts := 0
		for i := 0; i < 3; i++ {
			path, err := build.Get(func() (string, error) {
				attempts++
				return "base", failure
			})
			if path != "base" || err != failure {
				t.Fatalf("build result = %q, %v", path, err)
			}
		}
		if attempts != 1 {
			t.Fatalf("expected one build, got %d", attempts)
		}
	}
}

// Competing descriptors contend on the same inode. Linux also verifies
// cross-process contention here. The Darwin runner does that in the opt-in lane.
// Unsafe lock or directory modes refuse without opening a lane.
func TestLockContention(t *testing.T) {
	const child = "KEYVAULT_TEST_LOCK_WITNESS"
	if dir := os.Getenv(child); dir != "" {
		f, err := Lock(dir)
		if f != nil {
			f.Close()
		}
		if err != nil && !errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
		t.Logf("busy=%t", errors.Is(err, ErrBusy))
		return
	}
	dir := filepath.Join(t.TempDir(), "state")
	f, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(busy bool) {
		t.Helper()
		if runtime.GOOS == "darwin" {
			other, err := Lock(dir)
			if other != nil {
				other.Close()
			}
			if (busy && !errors.Is(err, ErrBusy)) || (!busy && err != nil) {
				t.Fatalf("second lock, busy=%v: %v", busy, err)
			}
			return
		}
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(self, "-test.run=^TestLockContention$", "-test.v")
		cmd.Env = append(os.Environ(), child+"="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "busy="+strconv.FormatBool(busy)) {
			t.Fatalf("lock child: %v, %s", err, out)
		}
	}
	probe(true)
	f.Close()
	probe(false)
	after, err := os.Stat(filepath.Join(dir, "lock"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("lock inode changed: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "lock"), 0666); err != nil {
		t.Fatal(err)
	}
	requireUnsafeLock(t, dir, "mode-0600")
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	requireUnsafeLock(t, dir, "unsafe codesign directory")
}

func requireUnsafeLock(t *testing.T, dir, want string) {
	t.Helper()
	f, err := Lock(dir)
	if f != nil {
		f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("unsafe state refusal = %v", err)
	}
}

// The process-group probe sees an actual live owned child and its exit.
func TestGroupExit(t *testing.T) {
	cmd := exec.Command("/bin/cat")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	gone, checkErr := groupGone(cmd.Process.Pid)
	stdin.Close()
	waitErr := cmd.Wait()
	if checkErr != nil || waitErr != nil || gone {
		t.Fatalf("live group: gone=%v, probe=%v, wait=%v", gone, checkErr, waitErr)
	}
	if gone, err := groupGone(cmd.Process.Pid); err != nil || !gone {
		t.Fatalf("exited group: gone=%v, probe=%v", gone, err)
	}
}

// Age, live/unknown group, interrupted state, observed-only runs and degraded
// health each prevent deletion. The nearby positives delete the exact tree
// with the lock held, including recovery after an actual boot change.
func TestRetainedCleanup(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, currentBoot                                    string
		observedRun, observedCleanup, finish, degraded, gone bool
		age                                                  time.Duration
		probeErr                                             error
		want                                                 string
	}{
		{name: "too young", finish: true, gone: true, age: time.Minute, want: "10-minute"},
		{name: "live", finish: true, age: time.Hour, want: "live or unknown"},
		{name: "unknown group", finish: true, age: time.Hour, probeErr: syscall.EPERM, want: "live or unknown"},
		{name: "interrupted", gone: true, age: time.Hour, want: "no known finish"},
		{name: "observed pending", observedRun: true, finish: true, gone: true, age: time.Hour, want: "cleanup mode"},
		{name: "routine through observed", observedCleanup: true, finish: true, gone: true, want: "cleanup mode"},
		{name: "observed live", observedRun: true, observedCleanup: true, want: "live or unknown"},
		{name: "degraded", finish: true, degraded: true, gone: true, age: time.Hour, want: "host-degraded"},
		{name: "observed degraded", observedRun: true, observedCleanup: true, degraded: true, gone: true, want: "host-degraded"},
		{name: "eligible routine", finish: true, gone: true, age: minimumRetention},
		{name: "eligible observed", observedRun: true, observedCleanup: true, gone: true},
		{name: "interrupted previous boot", currentBoot: "next-boot", age: time.Hour, want: "10-minute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			lane := openTestLane(t, dir, "boot")
			run, err := lane.Begin(os.Getpid(), tc.observedRun, false, now.Add(-tc.age-time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if tc.finish {
				if err := lane.Finish(run, now.Add(-tc.age)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "eligible routine" {
				record, err := readRun(run)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := lane.exitBoundary(run, record, now.Add(-tc.age), func(int) (bool, error) { return true, nil }); err != nil {
					t.Fatal(err)
				}
			}
			if err := lane.Close(); err != nil {
				t.Fatal(err)
			}
			boot := tc.currentBoot
			if boot == "" {
				boot = "boot"
			}
			lane = openTestLane(t, dir, boot)
			if tc.degraded {
				if err := os.WriteFile(filepath.Join(dir, DegradedFile), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err = lane.cleanup(filepath.Base(run), tc.observedCleanup, now, func(group int) (bool, error) {
				if group != os.Getpid() || boot != "boot" {
					t.Fatal("cleanup probed a different process group or a different boot")
				}
				return tc.gone, tc.probeErr
			}, func(path string) error {
				calls++
				if path != run {
					t.Fatalf("cleanup target = %s", path)
				}
				second, err := Lock(dir)
				if second != nil {
					second.Close()
				}
				if !errors.Is(err, ErrBusy) {
					t.Fatalf("cleanup released lock before deletion: %v", err)
				}
				return os.RemoveAll(path)
			})
			_, statErr := os.Stat(run)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || calls != 0 || statErr != nil {
					t.Fatalf("cleanup refusal = %v, %d removals, stat = %v", err, calls, statErr)
				}
			} else if err != nil || calls != 1 || !os.IsNotExist(statErr) {
				t.Fatalf("cleanup success = %v, %d removals, stat = %v", err, calls, statErr)
			}
		})
	}
}

// A lost descriptor does not lose the interlock. Unknown record data and a
// path outside the lane cannot be removed by routine or observed commands.
func TestRetainedInterlock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	now := time.Now()
	run, err := lane.Begin(syscall.Getpgrp(), false, false, now)
	if err != nil {
		t.Fatal(err)
	}
	lane.Close()
	lane = openTestLane(t, dir, "boot")
	if _, err := lane.Begin(syscall.Getpgrp(), false, false, now); err == nil || !strings.Contains(err.Error(), "process group") {
		t.Fatalf("second Begin = %v", err)
	}
	if err := os.WriteFile(filepath.Join(run, "run.json"), []byte("bad state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := lane.Cleanup(filepath.Base(run), true, now); err == nil || !strings.Contains(err.Error(), "unknown state") {
		t.Fatalf("unknown cleanup = %v", err)
	}
	if err := lane.Cleanup("../"+filepath.Base(run), true, now); err == nil || !strings.Contains(err.Error(), "exact retained run name") {
		t.Fatalf("path escape cleanup = %v", err)
	}
	if _, err := os.Stat(run); err != nil {
		t.Fatal(err)
	}
}

// A deletion failure after the cleanup decision leaves a resumable tombstone.
func TestCleanupResumes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	now := time.Now()
	run, err := lane.Begin(os.Getpid(), true, false, now)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(run)
	refused := errors.New("injected cleanup interruption")
	err = lane.cleanup(name, true, now, func(int) (bool, error) { return true, nil }, func(path string) error {
		if err := os.Remove(filepath.Join(path, "run.json")); err != nil {
			t.Fatal(err)
		}
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("cleanup interruption = %v", err)
	}
	if err := lane.Close(); err != nil {
		t.Fatal(err)
	}
	lane = openTestLane(t, dir, "boot")
	if err := lane.Cleanup(name, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, cleanupPrefix+name+".json")); !os.IsNotExist(err) {
		t.Fatalf("cleanup state remains: %v", err)
	}
}

// A completed direct command does not age the fixture while a descendant
// lives. The full window starts when group exit is first verified.
func TestRetentionStartsAfterGroupExit(t *testing.T) {
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	run, err := lane.Begin(os.Getpid(), false, false, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.Finish(run, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(run)
	removeCalls := 0
	remove := func(path string) error {
		removeCalls++
		return os.RemoveAll(path)
	}
	gone := false
	probe := func(int) (bool, error) { return gone, nil }
	if err := lane.cleanup(name, false, now, probe, remove); err == nil || !strings.Contains(err.Error(), "live or unknown") || removeCalls != 0 {
		t.Fatalf("live descendant = %v, removals=%d", err, removeCalls)
	}
	gone = true
	if err := lane.cleanup(name, false, now, probe, remove); err == nil || !strings.Contains(err.Error(), "10-minute") || removeCalls != 0 {
		t.Fatalf("newly exited group = %v, removals=%d", err, removeCalls)
	}
	if err := lane.cleanup(name, false, now.Add(minimumRetention), probe, remove); err != nil || removeCalls != 1 {
		t.Fatalf("quiet group = %v, removals=%d", err, removeCalls)
	}
}

// An unrecognized reap directory remains intact. A new directory at the
// original path also cannot inherit a real interrupted cleanup authorization.
func TestCleanupRefusesUnrecognizedIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	unknown := filepath.Join(dir, "reap-run-example")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := lane.Begin(os.Getpid(), false, false, now); err == nil || !strings.Contains(err.Error(), "unknown cleanup state") {
		t.Fatalf("unknown cleanup directory = %v", err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	run, err := lane.Begin(os.Getpid(), true, false, now)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(run)
	interrupted := errors.New("interrupted")
	if err := lane.cleanup(name, true, now, func(int) (bool, error) { return true, nil }, func(string) error { return interrupted }); !errors.Is(err, interrupted) {
		t.Fatalf("prepare cleanup = %v", err)
	}
	if err := os.Rename(run, run+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	if err := lane.Cleanup(name, true, now); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement directory = %v", err)
	}
	if _, err := os.Stat(run); err != nil {
		t.Fatal(err)
	}
}

// Admission distinguishes the inherited held description from a free lock
// or an independent descriptor on the same inode.
func TestAdmissionRequiresHeldLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	if err := lane.Close(); err != nil {
		t.Fatal(err)
	}
	independent, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer independent.Close()
	if err := checkHeldLock(dir, int(independent.Fd())); err == nil || !strings.Contains(err.Error(), "parent did not hold") {
		t.Fatalf("unlocked descriptor = %v", err)
	}
	lane = openTestLane(t, dir, "boot")
	if err := checkHeldLock(dir, int(lane.ChildLock().Fd())); err != nil {
		t.Fatal(err)
	}
	if err := checkHeldLock(dir, int(independent.Fd())); err == nil || !strings.Contains(err.Error(), "did not inherit") {
		t.Fatalf("independent descriptor = %v", err)
	}
}

// A correct-looking active run refuses a degraded lane, a symlink and
// any competing retained or cleanup state.
func TestAdmissionChecksActiveState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	run, err := lane.Begin(os.Getpid(), false, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkActiveRun(dir, run); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "run-link")
	if err := os.Symlink(run, link); err != nil {
		t.Fatal(err)
	}
	if err := checkActiveRun(dir, link); err == nil || !strings.Contains(err.Error(), "unsafe codesign directory") {
		t.Fatalf("symlink admission = %v", err)
	}
	if err := checkActiveRun(dir, run); err == nil || !strings.Contains(err.Error(), "outstanding state") {
		t.Fatalf("competing run admission = %v", err)
	}
	flag := filepath.Join(dir, DegradedFile)
	if err := os.WriteFile(flag, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkActiveRun(dir, run); err == nil || !strings.Contains(err.Error(), "host-degraded") {
		t.Fatalf("degraded admission = %v", err)
	}
}

// A runner-shaped process still needs the expected actual sandbox evidence.
// The separate certificate lane accepts only the applied init-level gate.
func TestAdmissionRequiresConfinement(t *testing.T) {
	for _, tc := range []struct {
		name, skip                    string
		cert, applied, confined, want bool
	}{
		{"unconfined", "1", false, false, false, false},
		{"init only", "1", false, true, false, false},
		{"opt out", "", false, false, true, false},
		{"exec-level", "1", false, false, true, true},
		{"certificate without gate", "1", true, false, false, false},
		{"certificate exec-level", "1", true, false, true, false},
		{"certificate init-level", "1", true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireConfinement(tc.cert, tc.skip, tc.applied, tc.confined)
			if (err == nil) != tc.want {
				t.Fatalf("confinement = %v", err)
			}
		})
	}
}

// The default transcript rejects a transient native attempt even when the
// test subsequently skips and leaves no fixture on disk.
func TestDefaultControlRejectsTransientAction(t *testing.T) {
	skipped := "--- SKIP: TestFixture (0.00s)\n"
	if err := CheckDefaultOutput([]byte(skipped), "TestFixture"); err != nil {
		t.Fatal(err)
	}
	plant := "fixture_test.go:1: " + NativeAttemptPrefix + "build\n" + skipped
	if err := CheckDefaultOutput([]byte(plant), "TestFixture"); err == nil || !strings.Contains(err.Error(), "attempted a native fixture action") {
		t.Fatalf("transient attempt = %v", err)
	}
}

func openTestLane(t *testing.T, dir, boot string) *Lane {
	t.Helper()
	lane, err := Open(dir, boot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lane.Close() })
	return lane
}
