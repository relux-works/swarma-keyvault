package keyvault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/boundedwait"
)

// Locker serialises the check-then-create window of Init and Rotate across
// processes so the duplicate refusal is atomic (review F2): the legacy
// keychain accepts duplicate labels, so the tool guarantees uniqueness itself.
type Locker interface {
	// Lock waits for the lock and returns its release, or an acquisition error.
	Lock() (release func(), err error)
}

// FileLock is an exclusive flock(2) on a file; flock contends between
// processes and between separate descriptors of one process alike.
type FileLock struct {
	Path string
}

// Lock acquires the exclusive lock, waiting at most boundedwait.LockWait.
func (l FileLock) Lock() (func(), error) {
	return l.LockContext(context.Background())
}

// LockContext creates the lock file and directory and waits for ownership until
// ctx is done or the fallback bound expires. A ctx that is done before the
// attempt or while it runs refuses, and the lock is not held on return. A
// failed acquisition closes its file.
func (l FileLock) LockContext(ctx context.Context) (func(), error) {
	if l.Path == "" {
		return nil, fmt.Errorf("keyvault: lock path is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keyvault: flock %s: %w", l.Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return nil, fmt.Errorf("keyvault: lock dir: %w", err)
	}
	file, err := os.OpenFile(l.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keyvault: lock file: %w", err)
	}
	if err := boundedwait.LockFile(ctx, file); err != nil {
		file.Close()
		return nil, fmt.Errorf("keyvault: flock %s: %w", l.Path, err)
	}
	// A ctx cancelled while the lock was being taken still refuses: the lock
	// is released before returning, so a canceled caller never holds it.
	if err := ctx.Err(); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
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
