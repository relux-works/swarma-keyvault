//go:build darwin

package keyvault

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// Darwin sys/fcntl.h defines FREAD=1 specifically for TIOCFLUSH callers;
// x/sys/unix does not export that macro. No output-draining ioctl is used.
const rootGrantsDarwinFREAD = 1

func rootGrantsFlushTTY(fd int) bool {
	for attempt := 0; attempt < 4; attempt++ {
		err := unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, rootGrantsDarwinFREAD)
		if err == unix.EINTR {
			continue
		}
		return err == nil
	}
	return false
}

// No package initialization, alternate fd, stdin, environment or file source.
// The final qualified custody helper alone may call this production frontend.
func readRootGrantsTTY(ctx context.Context) (phrase []byte, err error) {
	if err = rootGrantsContextError(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, rootGrantsAttemptLimit)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
	defer stop()
	fd, openError := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if openError != nil {
		return nil, recoveryRefuse("terminal_required")
	}
	defer unix.Close(fd)
	if fd < 0 || fd >= unix.FD_SETSIZE {
		return nil, recoveryRefuse("terminal_required")
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return nil, recoveryRefuse("terminal_required")
	}
	original, getError := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	foreground, groupError := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if getError != nil || groupError != nil || foreground <= 0 || foreground != unix.Getpgrp() {
		return nil, recoveryRefuse("terminal_required")
	}
	// Restoration is independent of canceled read context. Flush pending secret
	// input BEFORE echo returns; verify the exact saved attributes. SIGKILL/host
	// loss or an OS refusal cannot be repaired or certified by this source code.
	defer func() {
		flushed := rootGrantsFlushTTY(fd)
		restored := false
		for attempt := 0; attempt < 4; attempt++ {
			setError := unix.IoctlSetTermios(fd, unix.TIOCSETA, original)
			if setError == unix.EINTR {
				continue
			}
			if setError == nil {
				after, readError := unix.IoctlGetTermios(fd, unix.TIOCGETA)
				restored = readError == nil && *after == *original
			}
			break
		}
		if !restored || !flushed {
			clear(phrase)
			phrase = nil
			err = recoveryRefuse("private_protocol_error")
		}
	}()
	hidden := *original
	hidden.Lflag &^= unix.ECHO | unix.ECHONL | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOPRT | unix.ECHOKE | unix.ICANON | unix.IEXTEN
	hidden.Lflag |= unix.ISIG
	// Raw input delegates CR/LF/CRLF solely to our finite tty transport mapper,
	// rather than inherited translation that could count CRLF twice. Preserve
	// non-ASCII bytes so grammar rejects them instead of silently stripping.
	hidden.Iflag &^= unix.ICRNL | unix.INLCR | unix.IGNCR | unix.ISTRIP | unix.IXON | unix.IXOFF | unix.PARMRK
	hidden.Cc[unix.VMIN], hidden.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(fd, unix.TIOCSETA, &hidden) != nil {
		return nil, recoveryRefuse("terminal_required")
	}
	observed, hiddenError := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if hiddenError != nil || *observed != hidden {
		return nil, recoveryRefuse("terminal_required")
	}
	if !rootGrantsFlushTTY(fd) {
		return nil, recoveryRefuse("terminal_required")
	}
	phrase, err = readRootGrantsNumbered(ctx, &rootGrantsTTY{fd: fd})
	if err != nil {
		clear(phrase)
		return nil, err
	}
	if err = rootGrantsContextError(ctx); err != nil {
		clear(phrase)
		return nil, err
	}
	return phrase, nil
}

type rootGrantsTTY struct {
	fd     int
	mapper rootGrantsTTYMapper
}

func (t *rootGrantsTTY) foreground() bool {
	group, err := unix.IoctlGetInt(t.fd, unix.TIOCGPGRP)
	return err == nil && group > 0 && group == unix.Getpgrp()
}

// Darwin's controlling tty is selected, not polled: the existing recovery
// frontend documents POLLNVAL from poll on otherwise working /dev/tty fds.
func (t *rootGrantsTTY) wait(ctx context.Context, writing bool) error {
	for {
		if rootGrantsContextError(ctx) != nil || !t.foreground() {
			return rootGrantsInputError(ctx)
		}
		var set unix.FdSet
		set.Set(t.fd)
		timeout := unix.Timeval{Usec: 100000}
		var n int
		var err error
		if writing {
			n, err = unix.Select(t.fd+1, nil, &set, nil, &timeout)
		} else {
			n, err = unix.Select(t.fd+1, &set, nil, nil, &timeout)
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return rootGrantsInputError(ctx)
		}
		if n > 0 && set.IsSet(t.fd) {
			return nil
		}
	}
}

func (t *rootGrantsTTY) prompt(ctx context.Context, public []byte) error {
	for len(public) > 0 {
		if err := t.wait(ctx, true); err != nil {
			return err
		}
		n, err := unix.Write(t.fd, public)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 {
			return rootGrantsInputError(ctx)
		}
		public = public[n:]
	}
	return nil
}

func (t *rootGrantsTTY) readLine(ctx context.Context, maximum int) ([]byte, error) {
	line := make([]byte, 0, maximum)
	returned := false
	defer func() {
		if !returned {
			clear(line[:cap(line)])
		}
	}()
	for len(line) < maximum {
		if err := t.wait(ctx, false); err != nil {
			return nil, err
		}
		var one [1]byte
		n, readError := unix.Read(t.fd, one[:])
		if readError == unix.EINTR || readError == unix.EAGAIN {
			clear(one[:])
			continue
		}
		if readError != nil || n == 0 || one[0] == 4 {
			clear(one[:])
			return nil, rootGrantsInputError(ctx)
		}
		mapped, emit := t.mapper.mapByte(one[0])
		clear(one[:])
		if !emit {
			continue
		}
		line = append(line, mapped)
		mapped = 0
		if line[len(line)-1] == '\n' {
			returned = true
			return line, nil
		}
	}
	return nil, recoveryRefuse("invalid_word_count")
}
