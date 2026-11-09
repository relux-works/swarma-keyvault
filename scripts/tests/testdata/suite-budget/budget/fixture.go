//go:build darwin || linux

// Package budget supplies isolated fixtures for the hosted step deadline.
package budget

import (
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
)

const work = 25 * time.Second
const binaryLimit = 45 * time.Second

type record struct {
	Parent, Child int
	Completed     bool
	Elapsed       time.Duration
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("KEYVAULT_SUITE_CONTROL")
	if root == "" {
		t.Skip("requires the explicit isolated hosted suite-deadline fixture")
	}
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("fixture root must be an existing private absolute directory")
	}
	return root
}

func writeRecord(path string, r record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".new", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

// Fixture uses real test binaries. Its descendant deliberately owns a separate
// process group, as the retained upstream harness does. The hosting runner must
// clean the whole owned tree rather than only the entry process/group.
func Fixture(t *testing.T, name string) {
	t.Helper()
	root := fixtureRoot(t)
	phase := os.Getenv("KEYVAULT_SUITE_PHASE")
	if phase != "positive" && phase != "deadline" && phase != "native" && phase != "outsider" {
		t.Fatal("fixture phase refused")
	}
	if name != "a" && name != "b" && name != "c" {
		t.Fatal("fixture package refused")
	}
	path := filepath.Join(root, phase, name+".json")
	if os.Getenv("KEYVAULT_SUITE_LEAF") == name {
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
		for {
			if err := os.WriteFile(path+".ready", []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0600); err != nil {
				t.Fatal("leaf heartbeat failed")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	started := time.Now()
	child := exec.Command(os.Args[0], "-test.run=^TestBudgetFixture$", "-test.timeout=45s")
	child.Env = append(os.Environ(), "KEYVAULT_SUITE_LEAF="+name)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal("fixture descendant start failed")
	}
	reaped := false
	defer func() {
		if !reaped {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	r := record{Parent: os.Getpid(), Child: child.Process.Pid}
	if err := writeRecord(path, r); err != nil {
		t.Fatal("fixture PID witness failed")
	}
	readyUntil := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(readyUntil) {
			t.Fatal("fixture descendant readiness timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(work)
	if err := child.Process.Kill(); err != nil {
		t.Fatal("fixture descendant cleanup failed")
	}
	_ = child.Wait() // A deliberately killed child has a nonzero exit status.
	reaped = true
	r.Completed, r.Elapsed = true, time.Since(started)
	if r.Elapsed >= binaryLimit {
		t.Fatal("fixture did not complete within its independent binary limit")
	}
	if err := writeRecord(path, r); err != nil {
		t.Fatal("fixture completion witness failed")
	}
}

func validateRecords(records []record, positive bool) error {
	if len(records) != 3 {
		return errors.New("three binary start witnesses required")
	}
	completed := 0
	for _, r := range records {
		if r.Parent <= 1 || r.Child <= 1 || r.Parent == r.Child {
			return errors.New("invalid owned PID witness")
		}
		if r.Completed {
			completed++
			if r.Elapsed < work || r.Elapsed >= binaryLimit {
				return errors.New("completed binary violated its individual duration contract")
			}
		}
	}
	if positive && completed != 3 {
		return errors.New("roomy suite did not complete all healthy binaries")
	}
	if !positive && completed != 2 {
		return errors.New("short suite must stop during the third healthy binary")
	}
	return nil
}

func ownedGone(pid int) error {
	if pid <= 1 {
		return errors.New("invalid fixture PID")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("owned fixture PID %d survives: %v; %s", pid, err, processState(pid))
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
	f := strings.Fields(string(raw[end+1:]))
	if len(f) < 20 {
		return "state unavailable"
	}
	return fmt.Sprintf("state=%s ppid=%s pgid=%s sid=%s start=%s", f[0], f[1], f[2], f[3], f[19])
}
