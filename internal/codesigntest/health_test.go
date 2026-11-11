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

// Account resolution ignores ambient HOME without requiring the real health
// flag to be absent. This control never inspects or modifies that flag.
func TestHostHealthIgnoresEnvironmentHome(t *testing.T) {
	registered, err := AccountHome()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	if got, err := AccountHome(); err != nil || got != registered {
		t.Fatalf("ambient HOME changed account resolution: %v", err)
	}
}

// Public wrappers follow the injected registered home with opposing ambient
// health states. Degradation refuses before callbacks and leaves flags intact.
// Resolution failures also refuse. Every health path here is a temporary fixture.
func TestPublicHostHealthUsesRegisteredHome(t *testing.T) {
	original := accountHomeForHealth
	t.Cleanup(func() { accountHomeForHealth = original })
	for _, degraded := range []bool{false, true} {
		name := "canonical-healthy"
		if degraded {
			name = "canonical-degraded"
		}
		t.Run(name, func(t *testing.T) {
			registered, ambient := t.TempDir(), t.TempDir()
			flagHome := ambient
			if degraded {
				flagHome = registered
			}
			dir := filepath.Join(flagHome, "Library", "Application Support", "host-health")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			flag := filepath.Join(dir, "exec-degraded")
			contents := []byte("temporary degraded fixture")
			if err := os.WriteFile(flag, contents, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", ambient)
			resolutions := 0
			accountHomeForHealth = func() (string, error) {
				resolutions++
				return registered, nil
			}
			checkErr := CheckHostHealth()
			calls := 0
			actionErr := errors.New("temporary action result")
			runErr := RunHealthy(func() error { calls++; return actionErr })
			if degraded {
				if checkErr == nil || !strings.Contains(checkErr.Error(), "exec-degraded is present") || runErr == nil || !strings.Contains(runErr.Error(), "exec-degraded is present") || calls != 0 {
					t.Fatalf("canonical degradation: check=%v, run=%v, calls=%d", checkErr, runErr, calls)
				}
			} else if checkErr != nil || runErr != actionErr || calls != 1 {
				t.Fatalf("canonical healthy: check=%v, run=%v, calls=%d", checkErr, runErr, calls)
			}
			if resolutions != 2 {
				t.Fatalf("public wrappers bypassed registered resolution: %d", resolutions)
			}
			if got, err := os.ReadFile(flag); err != nil || string(got) != string(contents) {
				t.Fatalf("fixture flag changed: %q, %v", got, err)
			}
		})
	}
	t.Run("resolution-refused", func(t *testing.T) {
		resolutionErr := errors.New("temporary account lookup failure")
		accountHomeForHealth = func() (string, error) { return "", resolutionErr }
		calls := 0
		checkErr := CheckHostHealth()
		runErr := RunHealthy(func() error { calls++; return nil })
		if checkErr != resolutionErr || runErr != resolutionErr || calls != 0 {
			t.Fatalf("resolution refusal: check=%v, run=%v, calls=%d", checkErr, runErr, calls)
		}
	})
}
