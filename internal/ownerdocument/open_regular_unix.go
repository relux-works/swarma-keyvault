//go:build darwin || linux

package ownerdocument

import (
	"os"
	"syscall"
)

// Refuse symlinks atomically and never block on a FIFO swapped in after Lstat.
// The caller checks the opened descriptor's type and identity before reading.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
