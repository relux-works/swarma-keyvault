//go:build darwin

package main

import (
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// Darwin's fdescfs enumerates this process's open descriptors, independent of
// soft/hard limits (which may have been lowered after inheritance). Refuse if
// that view is unavailable. This runs at trusted startup, before any child or
// owned protocol endpoint exists. Runtime concurrent opens already use CLOEXEC;
// no untrusted native code or concurrent non-CLOEXEC opener is admitted here.
func sanitizeInheritedFDs() error {
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return err
	}
	// fdescfs includes descriptors (such as kqueue handles) that cannot be
	// stat'ed. ReadDir may fall back to fstatat for their unknown entry type
	// and fail with EBADF. We need only names; fcntl below validates each FD
	// and already handles entries that disappeared after enumeration.
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	var descriptors []uintptr
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < 0 {
			return refused
		}
		descriptors = append(descriptors, uintptr(fd))
	}
	return markInheritedFDs(descriptors, unix.FcntlInt)
}
