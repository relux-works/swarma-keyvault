package codesigntest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The canonical flag blocks work without parsing or modifying its contents.
// Removing it admits the next attempt. An unrelated flag cannot block work.
func TestHostHealthFlag(t *testing.T) {
	home := t.TempDir()
	if err := checkHostHealth(home); err != nil {
		t.Fatalf("absent host-health directory: %v", err)
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) != 0 {
		t.Fatalf("health check changed empty home: %v, %v", entries, err)
	}
	dir := filepath.Join(home, "Library", "Application Support", "host-health")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "exec-degraded"), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err != nil {
		t.Fatalf("unrelated flag: %v", err)
	}
	flag := filepath.Join(dir, "exec-degraded")
	for _, contents := range []string{"", "malformed", `{"reason":"fixture","since":"2026-11-11T00:00:00Z","host_watch_pid":1}` + "\n"} {
		if err := os.WriteFile(flag, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
		if err := checkHostHealth(home); err == nil || !strings.Contains(err.Error(), "exec-degraded is present") {
			t.Fatalf("present flag: %v", err)
		}
		got, err := os.ReadFile(flag)
		if err != nil || string(got) != contents {
			t.Fatalf("flag contents changed: %q, %v", got, err)
		}
		if err := os.Remove(flag); err != nil {
			t.Fatal(err)
		}
		if err := checkHostHealth(home); err != nil {
			t.Fatalf("flag cleared: %v", err)
		}
	}
}

// A flag that would block on read still refuses immediately through stat.
// A symlink at the flag name refuses without following or modifying it.
func TestHostHealthDoesNotReadOrFollowFlag(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Application Support", "host-health")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(dir, "exec-degraded")
	if err := syscall.Mkfifo(flag, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err == nil || !strings.Contains(err.Error(), "exec-degraded is present") {
		t.Fatalf("unreadable flag: %v", err)
	}
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("exec-degraded", flag); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err == nil || !strings.Contains(err.Error(), "exec-degraded is present") {
		t.Fatalf("circular flag symlink: %v", err)
	}
	if target, err := os.Readlink(flag); err != nil || target != "exec-degraded" {
		t.Fatalf("inspection changed the path: %q, %v", target, err)
	}
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", flag); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err == nil || !strings.Contains(err.Error(), "exec-degraded is present") {
		t.Fatalf("dangling flag symlink: %v", err)
	}
	if target, err := os.Readlink(flag); err != nil || target != "missing-target" {
		t.Fatalf("inspection changed dangling flag: %q, %v", target, err)
	}
}

// Missing directories admit without creating them. Existing safe directories
// admit, while writable, inaccessible and symlinked components refuse.
func TestHostHealthDirectorySafety(t *testing.T) {
	for _, component := range []string{"Library", "Application Support", "host-health"} {
		t.Run(component, func(t *testing.T) {
			home := t.TempDir()
			parent := home
			for _, name := range []string{"Library", "Application Support", "host-health"} {
				path := filepath.Join(parent, name)
				if err := checkHostHealth(home); err != nil {
					t.Fatalf("absent component: %v", err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if name == component {
					if err := os.Chmod(path, 0777); err != nil {
						t.Fatal(err)
					}
					if err := checkHostHealth(home); err == nil || !strings.Contains(err.Error(), "without group or world write") {
						t.Fatalf("writable component: %v", err)
					}
					if err := os.Chmod(path, 0000); err != nil {
						t.Fatal(err)
					}
					if os.Getuid() != 0 {
						if err := checkHostHealth(home); !errors.Is(err, syscall.EACCES) {
							t.Fatalf("inaccessible component: %v", err)
						}
					}
					if err := os.Chmod(path, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("missing-directory", path); err != nil {
						t.Fatal(err)
					}
					if err := checkHostHealth(home); err == nil {
						t.Fatal("dangling directory symlink admitted")
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(t.TempDir(), path); err != nil {
						t.Fatal(err)
					}
					if err := checkHostHealth(home); err == nil {
						t.Fatal("existing directory symlink admitted")
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				parent = path
			}
			if err := checkHostHealth(home); err != nil {
				t.Fatalf("safe directories: %v", err)
			}
		})
	}
}

// Raising health after an earlier successful check blocks the next action.
// Healthy execution calls once and preserves action errors. Cached fixture
// reuse cannot bypass the next action's fresh admission.
// Publication after the final check can overlap an already admitted action.
func TestHostHealthRechecksEachAction(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Application Support", "host-health")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(dir, "exec-degraded")
	calls := 0
	actionErr := errors.New("fixture action error")
	action := func() error { calls++; return actionErr }
	if err := os.WriteFile(flag, []byte("raised after setup"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runHealthy(home, action); err == nil || calls != 0 {
		t.Fatalf("degraded action: %v, calls=%d", err, calls)
	}
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	if err := runHealthy(home, action); err != actionErr || calls != 1 {
		t.Fatalf("healthy action: %v, calls=%d", err, calls)
	}
	if err := os.WriteFile(flag, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := runHealthy(home, action); err == nil || calls != 1 {
		t.Fatalf("later action reused admission: %v, calls=%d", err, calls)
	}
}

// An ambient HOME override cannot select a different health directory. The
// fixture flag refuses there, while public admission uses the registered home.
// This control never creates or modifies the real account's health flag.
func TestHostHealthIgnoresEnvironmentHome(t *testing.T) {
	registered, err := AccountHome()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(registered); err != nil {
		t.Fatalf("registered account is unable to start work: %v", err)
	}
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Application Support", "host-health")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exec-degraded"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkHostHealth(home); err == nil {
		t.Fatal("fixture flag did not refuse")
	}
	t.Setenv("HOME", home)
	if got, err := AccountHome(); err != nil || got != registered {
		t.Fatalf("ambient HOME changed account resolution: %v", err)
	}
	calls := 0
	if err := RunHealthy(func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("public admission selected fixture HOME: %v, calls=%d", err, calls)
	}
}
