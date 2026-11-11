package keyvault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// FileLock uses the persistent vault file lock. BootstrapDir is the stable
// existing directory that serializes creation with a no-write first read.
type FileLock struct {
	Path         string
	BootstrapDir string
}

// LockReadOnly takes the same lock as writers without creating prerequisites.
// Before the file exists, the admitted directory remains locked for the read.
func (l FileLock) LockReadOnly() (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), boundedwait.LockWait)
	defer cancel()
	releaseBootstrap, err := l.lockBootstrap(ctx)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(l.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) && releaseBootstrap != nil {
		return releaseBootstrap, nil
	}
	if releaseBootstrap != nil {
		defer releaseBootstrap()
	}
	if err != nil {
		return nil, err
	}
	if err := admitLockFile(file); err != nil {
		file.Close()
		return nil, err
	}
	if err := boundedwait.LockFile(ctx, file); err != nil {
		file.Close()
		return nil, err
	}
	return func() { file.Close() }, nil
}

func (l FileLock) lockBootstrap(ctx context.Context) (func(), error) {
	if l.BootstrapDir == "" {
		return nil, nil
	}
	relative, err := filepath.Rel(l.BootstrapDir, l.Path)
	if err != nil || !filepath.IsAbs(l.BootstrapDir) || filepath.Clean(l.BootstrapDir) != l.BootstrapDir ||
		filepath.Clean(l.Path) != l.Path || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("keyvault: lock path is outside the bootstrap directory")
	}
	dir, err := os.OpenFile(l.BootstrapDir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	st, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		dir.Close()
		return nil, fmt.Errorf("keyvault: bootstrap directory is not admitted")
	}
	if err := boundedwait.LockFile(ctx, dir); err != nil {
		dir.Close()
		return nil, err
	}
	return func() { dir.Close() }, nil
}

func admitLockFile(file *os.File) error {
	st, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("keyvault: lock file is not admitted")
	}
	return nil
}

// Lock acquires the exclusive lock, waiting at most boundedwait.LockWait.
func (l FileLock) Lock() (func(), error) {
	return l.LockContext(context.Background())
}

// LockContext creates the lock file and directory and waits for ownership until
// ctx is done or the fallback bound expires. A ctx that is done before the
// attempt or while it runs refuses, and the lock is not held on return. A
// failed acquisition closes its file.
func (l FileLock) LockContext(parent context.Context) (func(), error) {
	if l.Path == "" {
		return nil, fmt.Errorf("keyvault: lock path is empty")
	}
	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("keyvault: flock %s: %w", l.Path, err)
	}
	ctx, cancel := context.WithTimeout(parent, boundedwait.LockWait)
	defer cancel()
	releaseBootstrap, err := l.lockBootstrap(ctx)
	if err != nil {
		return nil, err
	}
	if releaseBootstrap != nil {
		defer releaseBootstrap()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return nil, fmt.Errorf("keyvault: lock dir: %w", err)
	}
	file, err := os.OpenFile(l.Path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keyvault: lock file: %w", err)
	}
	if err := admitLockFile(file); err != nil {
		file.Close()
		return nil, err
	}
	if err := boundedwait.LockFile(ctx, file); err != nil {
		file.Close()
		return nil, fmt.Errorf("keyvault: flock %s: %w", l.Path, err)
	}
	// A ctx cancelled while the lock was being taken still refuses: the lock
	// is released before returning, so a canceled caller never holds it.
	if err := errors.Join(parent.Err(), ctx.Err()); err != nil {
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

// DefaultFileLock keeps the persistent lock at the existing vault path and
// uses the account's existing home directory for first-use synchronization.
func DefaultFileLock() (FileLock, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FileLock{}, err
	}
	return FileLock{Path: filepath.Join(home, "Library", "Application Support", "mac-infra", "keyvault", "init.lock"), BootstrapDir: home}, nil
}
