package main

import "golang.org/x/sys/unix"

func recoveryGetTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}
func recoverySetTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}
func recoveryRestoreTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETAF, t)
}
