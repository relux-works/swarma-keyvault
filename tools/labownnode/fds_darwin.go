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
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return err
	}
	var descriptors []uintptr
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 {
			return refused
		}
		descriptors = append(descriptors, uintptr(fd))
	}
	return markInheritedFDs(descriptors, unix.FcntlInt)
}
