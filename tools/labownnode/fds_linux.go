//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Atomic marking covers every descriptor above stderr, including descriptors
// above a subsequently lowered RLIMIT_NOFILE. It does not close runtime FDs.
// An older kernel or any marking failure refuses startup; no partial fallback.
func sanitizeInheritedFDs() error {
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()
	return unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC)
}
