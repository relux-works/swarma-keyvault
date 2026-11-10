package seedsetup

import (
	"bytes"
	"context"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Only public data is read by the wrapper, one line at a time. Closing this
// descriptor before invoking the actual vault leaves no reader for seed words.
func publicPrompt(parent context.Context, message string, maximum int) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", refused("foreground_tty_required")
	}
	defer unix.Close(fd)
	state, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	group, groupErr := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || groupErr != nil || fd >= unix.FD_SETSIZE || group != unix.Getpgrp() ||
		state.Lflag&unix.ICANON == 0 || state.Lflag&unix.ISIG == 0 {
		return "", refused("foreground_tty_required")
	}
	ready := func(write bool) error {
		for ctx.Err() == nil {
			var set unix.FdSet
			set.Set(fd)
			timeout := unix.Timeval{Usec: 100000}
			var n int
			var selectErr error
			if write {
				n, selectErr = unix.Select(fd+1, nil, &set, nil, &timeout)
			} else {
				n, selectErr = unix.Select(fd+1, &set, nil, nil, &timeout)
			}
			if selectErr == unix.EINTR {
				continue
			}
			if selectErr != nil {
				return refused("foreground_tty_unavailable")
			}
			if n != 0 && set.IsSet(fd) {
				return nil
			}
		}
		return refused("public_confirmation_interrupted")
	}
	for b := []byte(message); len(b) > 0; {
		if err := ready(true); err != nil {
			return "", err
		}
		n, err := unix.Write(fd, b)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil || n < 1 {
			return "", refused("public_confirmation_display_refused")
		}
		b = b[n:]
	}
	raw := make([]byte, 0, maximum)
	defer func() { clear(raw) }()
	for {
		if err := ready(false); err != nil {
			return "", err
		}
		var b [1]byte
		n, err := unix.Read(fd, b[:])
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil || n != 1 {
			return "", refused("public_confirmation_input_refused")
		}
		if b[0] == '\n' {
			return string(raw), nil
		}
		if len(raw) == maximum || b[0] < 32 || b[0] > 126 {
			return "", refused("public_confirmation_input_refused")
		}
		raw = append(raw, b[0])
	}
}

func fixturePTY() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, refused("fixture_pty_unavailable")
	}
	master := os.NewFile(uintptr(fd), "public-fixture-master")
	fail := func() (*os.File, *os.File, error) {
		master.Close()
		return nil, nil, refused("fixture_pty_unavailable")
	}
	if unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0) != nil || unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0) != nil {
		return fail()
	}
	var name [128]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	length := bytes.IndexByte(name[:], 0)
	if errno != 0 || length < 1 {
		return fail()
	}
	slave, err := os.OpenFile(string(name[:length]), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	return master, slave, nil
}

func publicFixtureRestore(parent context.Context, home, binary string, target publicTarget) ([]byte, int) {
	if target.validate() != nil || target.Version != 1 || target.NostrVersion != 1 || target.NamecoinVersion != 1 {
		return nil, -1
	}
	args := append([]string{"--json", "recovery", "restore"}, target.mutationArguments()...)
	args = append(args, "--expected-npub", publicFixtureNPub, "--expected-namecoin-xpub", publicFixtureXPub, "--expected-origin", publicFixtureOrigin)
	master, slave, err := fixturePTY()
	if err != nil {
		return nil, -1
	}
	defer master.Close()
	defer slave.Close()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	cmd := makeCommand(ctx, home, binary, args)
	cmd.Stdin = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	stdout, stderr := &capped{limit: 32768}, &capped{limit: 8192}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if cmd.Start() != nil {
		return nil, -1
	}
	// The Go wrapper owns only this child PID and this separate PTY. Reap it
	// on every branch; never send a signal to another group or process.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stop := func() ([]byte, int) {
		cancel()
		<-done
		return nil, -1
	}
	steps := []struct{ prompt, line string }{
		{"Retype Nostr identity: ", target.NostrIdentity},
		{"Retype Namecoin identity: ", target.NamecoinIdentity},
		{"Restore exactly 24 English words, separated by single spaces. Input is hidden; public pins will be checked before storage: ", publicFixturePhrase},
	}
	var seen [8192]byte
	defer clear(seen[:])
	stage, used := 0, 0
	for {
		select {
		case err := <-done:
			exit := childExit(ctx, err)
			if stage != len(steps) && (exit == 0 || stage < 2) {
				return nil, -1
			}
			return checkCappedOutput(stdout, stderr, exit, false)
		default:
		}
		if ctx.Err() != nil {
			return stop()
		}
		poll := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 100); err != nil && err != unix.EINTR {
			return stop()
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var buf [1024]byte
		n, err := unix.Read(int(master.Fd()), buf[:])
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil || n > len(seen)-used {
			clear(buf[:])
			return stop()
		}
		copy(seen[used:], buf[:n])
		clear(buf[:])
		used += n
		if stage < len(steps) && bytes.Contains(seen[:used], []byte(steps[stage].prompt)) {
			line := []byte(steps[stage].line + "\n")
			written, writeErr := master.Write(line)
			clear(line)
			if writeErr != nil || written != len(steps[stage].line)+1 {
				return stop()
			}
			stage++
			clear(seen[:used])
			used = 0
		}
	}
}
