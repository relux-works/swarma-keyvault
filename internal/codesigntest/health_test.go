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
// An inspection failure preserves its cause and never admits a new lane.
func TestHostHealthDoesNotReadFlagAndRefusesStatError(t *testing.T) {
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
	if err := checkHostHealth(home); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("stat failure: %v", err)
	}
	if target, err := os.Readlink(flag); err != nil || target != "exec-degraded" {
		t.Fatalf("inspection changed the path: %q, %v", target, err)
	}
}
