//go:build linux || darwin

package main

import "golang.org/x/sys/unix"

// Startup marking never closes an FD. Reuse of a disappearing runtime handle
// is safe: new Go handles are CLOEXEC already, and marking a reused handle can
// only restrict its inheritance. No child or non-CLOEXEC opener runs concurrently.
func markInheritedFDs(descriptors []uintptr, fcntl func(uintptr, int, int) (int, error)) error {
	for _, fd := range descriptors {
		if fd <= 2 {
			continue
		}
		flags, err := fcntl(fd, unix.F_GETFD, 0)
		if err == unix.EBADF { // enumeration handle or runtime handle closed
			continue
		}
		if err != nil {
			return err
		}
		if flags&unix.FD_CLOEXEC == 0 {
			_, err = fcntl(fd, unix.F_SETFD, flags|unix.FD_CLOEXEC)
			if err != nil && err != unix.EBADF {
				return err
			}
		}
	}
	return nil
}
