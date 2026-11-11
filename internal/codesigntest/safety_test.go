package codesigntest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A physical owned home is admitted. A symlink to that same directory is
// refused both at the home leaf and in an earlier path component.
func TestAccountHomeRejectsSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	home := filepath.Join(parent, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := validateAccountHome(home); err != nil || got != home {
		t.Fatalf("physical home = %q, %v", got, err)
	}
	for _, link := range []struct{ name, target, suffix string }{
		{"leaf", home, ""},
		{"ancestor", parent, "home"},
	} {
		path := filepath.Join(root, link.name)
		if err := os.Symlink(link.target, path); err != nil {
			t.Fatal(err)
		}
		if got, err := validateAccountHome(filepath.Join(path, link.suffix)); err == nil || got != "" || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("%s symlink home = %q, %v", link.name, got, err)
		}
	}
}

// An old verified stamp cannot authorize deletion while the same-boot group
// is live or unknown, or when the stamp describes a different run.
func TestCleanupRevalidatesStampedGroup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	now := time.Now()
	run, err := lane.Begin(os.Getpid(), false, false, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	exited := now.Add(-20 * time.Minute)
	if err := lane.Finish(run, exited); err != nil {
		t.Fatal(err)
	}
	record, err := readRun(run)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(run)
	gone := func(int) (bool, error) { return true, nil }
	if _, err := lane.exitBoundary(run, record, exited, gone); err != nil {
		t.Fatal(err)
	}
	removed := 0
	remove := func(path string) error {
		removed++
		return os.RemoveAll(path)
	}
	for _, probeErr := range []error{nil, syscall.EPERM} {
		err := lane.cleanup(name, false, now, func(int) (bool, error) { return false, probeErr }, remove)
		if err == nil || !strings.Contains(err.Error(), "live or unknown") || removed != 0 {
			t.Fatalf("stamped group refusal = %v, removals=%d", err, removed)
		}
	}
	changed := record
	changed.Group++
	writeExit := func(r runRecord) {
		t.Helper()
		raw, err := json.Marshal(exitRecord{Run: r, At: exited})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(run, "exited"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeExit(changed)
	if err := lane.cleanup(name, false, now, gone, remove); err == nil || !strings.Contains(err.Error(), "invalid process exit record") || removed != 0 {
		t.Fatalf("foreign exit stamp = %v, removals=%d", err, removed)
	}
	writeExit(record)
	if err := lane.cleanup(name, false, now, gone, remove); err != nil || removed != 1 {
		t.Fatalf("matching quiet stamp = %v, removals=%d", err, removed)
	}
}

// An interrupted removal refuses conflicting metadata on the same inode.
// Once the original metadata is present and the group is gone, it can resume.
func TestCleanupResumeChecksSurvivingMetadata(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lane := openTestLane(t, dir, "boot")
	now := time.Now()
	run, err := lane.Begin(os.Getpid(), true, false, now)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(run)
	gone := func(int) (bool, error) { return true, nil }
	interrupted := errors.New("injected cleanup interruption")
	if err := lane.cleanup(name, true, now, gone, func(string) error { return interrupted }); !errors.Is(err, interrupted) {
		t.Fatalf("prepare cleanup = %v", err)
	}
	path := filepath.Join(run, "run.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := readRun(run)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Group++
	raw, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	removed := 0
	remove := func(path string) error {
		removed++
		return os.RemoveAll(path)
	}
	if err := lane.cleanup(name, true, now, gone, remove); err == nil || !strings.Contains(err.Error(), "metadata changed") || removed != 0 {
		t.Fatalf("conflicting metadata = %v, removals=%d", err, removed)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lane.cleanup(name, true, now, func(int) (bool, error) { return false, nil }, remove); err == nil || !strings.Contains(err.Error(), "live or unknown") || removed != 0 {
		t.Fatalf("resumed live group = %v, removals=%d", err, removed)
	}
	if err := lane.cleanup(name, true, now, gone, remove); err != nil || removed != 1 {
		t.Fatalf("matching metadata = %v, removals=%d", err, removed)
	}
}
