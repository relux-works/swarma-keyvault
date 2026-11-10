package main

import "golang.org/x/sys/unix"

func recoveryGetTermios(fd int) (*unix.Termios, error) { return unix.IoctlGetTermios(fd, unix.TCGETS) }
func recoverySetTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}
func recoveryRestoreTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TCSETSF, t)
}
