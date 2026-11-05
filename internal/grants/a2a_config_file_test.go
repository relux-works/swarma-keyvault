package grants

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeA2AConfigFixture(t *testing.T, mode os.FileMode, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "public-config.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// Claim: owner-owned regular files that nobody else can write are admitted
// byte for byte, for the owner-only and read-only modes in use.
func TestA2AConfigFileAdmitsOwnerModes(t *testing.T) {
	body := []byte(`{"type":"fixture"}`)
	for _, mode := range []os.FileMode{0600, 0644, 0400, 0444} {
		raw, err := LoadA2AExecutorConfig(writeA2AConfigFixture(t, mode, body))
		if err != nil || !bytes.Equal(raw, body) {
			t.Fatal("legitimate mode refused", mode, err)
		}
	}
}

// Claim: group/other-writable files, a symlink (even to an admitted file), a
// directory, a FIFO (refused without blocking), an oversized file and a missing
// path are refused. Limit: a foreign-owner file needs another uid and is not
// exercised here.
func TestA2AConfigFileRefusals(t *testing.T) {
	body := []byte(`{"type":"fixture"}`)
	for _, mode := range []os.FileMode{0620, 0602, 0666, 0622} {
		if _, err := LoadA2AExecutorConfig(writeA2AConfigFixture(t, mode, body)); !errors.Is(err, ErrA2AConfigFile) {
			t.Fatal("writable-by-others admitted", mode, err)
		}
	}
	target := writeA2AConfigFixture(t, 0600, body)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadA2AExecutorConfig(link); !errors.Is(err, ErrA2AConfigFile) {
		t.Fatal("symlink admitted", err)
	}
	if _, err := LoadA2AExecutorConfig(t.TempDir()); !errors.Is(err, ErrA2AConfigFile) {
		t.Fatal("directory admitted", err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadA2AExecutorConfig(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrA2AConfigFile) {
			t.Fatal("fifo admitted", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fifo open blocked")
	}
	if _, err := LoadA2AExecutorConfig(writeA2AConfigFixture(t, 0600, bytes.Repeat([]byte{'x'}, A2AConfigLimit+1))); !errors.Is(err, errInputLimit) {
		t.Fatal("oversized config admitted", err)
	}
	if raw, err := LoadA2AExecutorConfig(writeA2AConfigFixture(t, 0600, bytes.Repeat([]byte{'x'}, A2AConfigLimit))); err != nil || len(raw) != A2AConfigLimit {
		t.Fatal("limit-sized config refused", err)
	}
	if _, err := LoadA2AExecutorConfig(filepath.Join(t.TempDir(), "absent.json")); !errors.Is(err, ErrA2AConfigFile) {
		t.Fatal("missing config admitted", err)
	}
}
