package keyvault

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Locker serialises the check-then-create window of Init and Rotate across
// processes so the duplicate refusal is atomic (review F2): the legacy
// keychain accepts duplicate labels, so the tool guarantees uniqueness itself.
type Locker interface {
	// Lock blocks until the lock is held and returns its release.
	Lock() (release func(), err error)
}

// FileLock is an exclusive flock(2) on a file; flock contends between
// processes and between separate descriptors of one process alike.
type FileLock struct {
	Path string
}

// Lock acquires the exclusive lock, creating the file and its directory.
func (l FileLock) Lock() (func(), error) {
	if l.Path == "" {
		return nil, fmt.Errorf("keyvault: lock path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return nil, fmt.Errorf("keyvault: lock dir: %w", err)
	}
	file, err := os.OpenFile(l.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keyvault: lock file: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("keyvault: flock %s: %w", l.Path, err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}

// NoLock performs no locking. It exists for tests that need the positive
// control of the race; production never uses it.
type NoLock struct{}

func (NoLock) Lock() (func(), error) { return func() {}, nil }

// DefaultLockPath is where the production CLI keeps the lock.
func DefaultLockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "mac-infra", "keyvault", "init.lock"), nil
}
