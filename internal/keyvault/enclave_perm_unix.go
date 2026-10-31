//go:build unix

package keyvault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Every enclave-store file operation works relative to one directory
// descriptor that was opened without following a symlink and checked on the
// descriptor itself, and every file is checked with fstat on the descriptor
// that is then read (review F3): nothing is judged by path and used later.

// openEnclaveDir opens the store directory itself without following it and
// refuses one that is not a directory, belongs to someone else or is open to
// group or other. A missing directory is os.ErrNotExist.
func openEnclaveDir(path string) (*os.File, error) {
	enclaveBeforeOpen("")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s is not a plain directory", path)
		}
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		dir.Close()
		return nil, err
	}
	switch {
	case stat.Mode&unix.S_IFMT != unix.S_IFDIR:
		err = fmt.Errorf("%s is not a plain directory", path)
	case int(stat.Uid) != os.Getuid():
		err = fmt.Errorf("%s is not owned by this user", path)
	case stat.Mode&0o077 != 0:
		err = fmt.Errorf("%s is open to group or other (mode %o)", path, stat.Mode&0o777)
	}
	if err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

// readEnclaveFileAt reads name in dir: a regular file with one link, owned by
// this user, no group or other bits, at most max bytes; judged by fstat on
// the opened descriptor. A missing file is os.ErrNotExist.
func readEnclaveFileAt(dir *os.File, name string, max int) ([]byte, error) {
	enclaveBeforeOpen(name)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink", name)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	switch {
	case stat.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("%s is not a regular file", name)
	case stat.Nlink != 1:
		return nil, fmt.Errorf("%s has %d links", name, stat.Nlink)
	case int(stat.Uid) != os.Getuid():
		return nil, fmt.Errorf("%s is not owned by this user", name)
	case stat.Mode&0o077 != 0:
		return nil, fmt.Errorf("%s is open to group or other (mode %o)", name, stat.Mode&0o777)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, max)
	}
	return data, nil
}

// Test seams: enclaveBeforeOpen runs right before a store path is opened
// (name "" for the directory) so a test can swap what is there; nothing
// judged earlier may decide what is read. enclaveAfterPublish runs right
// after a key file is published, before any cleanup.
var (
	enclaveBeforeOpen   = func(name string) {}
	enclaveAfterPublish = func(dir *os.File, name string) {}
)

// enclaveWriteAll writes data to a temporary key file; tests replace it to
// inject a failed write.
var enclaveWriteAll = func(file *os.File, data []byte) error {
	_, err := file.Write(data)
	return err
}

// writeEnclaveFileAt publishes data as name in dir: a fresh 0600 temporary
// file is written and synced, then renamed to name, exclusively for a create
// (fails if name exists) or over it for a replace, and the directory is
// synced. Either way the published file has one link. Any failure before
// publication leaves name untouched and removes the temporary file.
func writeEnclaveFileAt(dir *os.File, name string, data []byte, replace bool) (err error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmp := ".tmp-" + hex.EncodeToString(random)
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if rmErr := unix.Unlinkat(int(dir.Fd()), tmp, 0); rmErr != nil && !errors.Is(rmErr, unix.ENOENT) && err == nil {
			err = rmErr
		}
	}()
	file := os.NewFile(uintptr(fd), tmp)
	writeErr := enclaveWriteAll(file, data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return writeErr
	}
	if replace {
		err = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name)
	} else {
		err = publishNoReplace(int(dir.Fd()), tmp, name)
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
	}
	if err != nil {
		return err
	}
	enclaveAfterPublish(dir, name)
	return dir.Sync()
}

// removeEnclaveFileAt unlinks name in dir; a missing file is os.ErrNotExist.
func removeEnclaveFileAt(dir *os.File, name string) error {
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return os.ErrNotExist
		}
		return err
	}
	return nil
}

// enclaveFileExistsAt reports whether anything (a symlink included) is named
// name in dir.
func enclaveFileExistsAt(dir *os.File, name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

// requireOwnedFile refuses an executable that is a symlink, not a regular
// file, owned by neither this user nor root, or writable by group or other.
func requireOwnedFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: owner unknown", name)
	}
	if owner := int(stat.Uid); owner != os.Getuid() && owner != 0 {
		return fmt.Errorf("%s is owned by uid %d", name, owner)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %o)", name, info.Mode().Perm())
	}
	return nil
}
