package keyvault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/boundedwait"
	"golang.org/x/sys/unix"
)

// rootGrantsExistingGuard owns only the pre-existing mutation lock. It has no
// bootstrap, file creation, namespace mutation or Keychain capability.
type rootGrantsExistingGuard struct {
	file *os.File
	once sync.Once
}

func (g *rootGrantsExistingGuard) Release() {
	if g != nil {
		g.once.Do(func() { _ = g.file.Close() })
	}
}

// lockRootGrantsExisting takes the SAME flock as existing vault writers, but
// never creates their prerequisites. Path is supplied only by package-owned
// vault construction (DefaultFileLock); the private argument also permits
// disposable filesystem tests. Every path component is opened without following
// symlinks. The final descriptor is admitted using the existing file policy.
func lockRootGrantsExisting(parent context.Context, lock FileLock) (*rootGrantsExistingGuard, error) {
	refuse := func() (*rootGrantsExistingGuard, error) { return nil, recoveryRefuse("lock_unavailable") }
	if parent == nil || parent.Err() != nil || !filepath.IsAbs(lock.Path) || filepath.Clean(lock.Path) != lock.Path {
		return refuse()
	}
	parts := strings.Split(strings.TrimPrefix(lock.Path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return refuse()
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return refuse()
	}
	directory := os.NewFile(uintptr(fd), "root-grants-lock-parent")
	defer func() { _ = directory.Close() }()
	for _, part := range parts[:len(parts)-1] {
		if parent.Err() != nil {
			return refuse()
		}
		next, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return refuse()
		}
		_ = directory.Close()
		directory = os.NewFile(uintptr(next), "root-grants-lock-parent")
	}
	// The immediate containing directory must not let another user replace the
	// guard. Root-owned ancestors are traversed by descriptor, never by a
	// subsequent string resolution; the lock directory itself is user-owned.
	st, err := directory.Stat()
	if err != nil {
		return refuse()
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		return refuse()
	}
	name := parts[len(parts)-1]
	fd, err = unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return refuse()
	}
	file := os.NewFile(uintptr(fd), "root-grants-existing-lock")
	owned := true
	defer func() {
		if owned {
			_ = file.Close()
		}
	}()
	if admitLockFile(file) != nil || parent.Err() != nil {
		return refuse()
	}
	ctx, cancel := context.WithTimeout(parent, boundedwait.LockWait)
	defer cancel()
	if boundedwait.LockFile(ctx, file) != nil || parent.Err() != nil || ctx.Err() != nil {
		return refuse()
	}
	// Refuse a replaced/unlinked guard after waiting. Compare the currently
	// named, no-follow file with the exact descriptor carrying the flock.
	var named, held unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(fd, &held) != nil ||
		named.Dev != held.Dev || named.Ino != held.Ino || admitLockFile(file) != nil {
		return refuse()
	}
	owned = false
	return &rootGrantsExistingGuard{file: file}, nil
}
