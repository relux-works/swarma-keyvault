//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"

	"golang.org/x/sys/unix"
)

type ownerRecoveryTerminal interface {
	ConfirmIdentities(keyvault.RecoveryPlan) error
	ConfirmMnemonic([][]byte) error
	ReadMnemonic() ([]byte, error)
	Close() error
}

var newRecoveryTerminal = openRecoveryTerminal

type recoveryTerminal struct {
	fd       int
	original *unix.Termios
	ctx      context.Context
	stop     context.CancelFunc
	random   io.Reader
	closed   bool
}

func openRecoveryTerminal() (ownerRecoveryTerminal, error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("owner controlling terminal required")
	}
	if fd >= unix.FD_SETSIZE {
		unix.Close(fd)
		return nil, errors.New("terminal descriptor out of range")
	}
	state, err := recoveryGetTermios(fd)
	foreground, e := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || e != nil || foreground != unix.Getpgrp() {
		unix.Close(fd)
		return nil, errors.New("owner foreground terminal required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
	t := &recoveryTerminal{fd: fd, original: state, ctx: ctx, stop: stop, random: rand.Reader}
	hidden := *state
	hidden.Lflag &^= unix.ECHO | unix.ECHONL
	hidden.Lflag |= unix.ICANON | unix.ISIG
	if err := recoverySetTermios(fd, &hidden); err != nil {
		stop()
		unix.Close(fd)
		return nil, errors.New("terminal echo protection unavailable")
	}
	return t, nil
}

func (t *recoveryTerminal) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	// Best effort screen clearing is not a guarantee about terminal history,
	// recordings, SIGKILL or host loss. Restore attributes even after cancellation.
	_, _ = unix.Write(t.fd, []byte("\x1b[2J\x1b[3J\x1b[H"))
	err := recoveryRestoreTermios(t.fd, t.original)
	t.stop()
	_ = unix.Close(t.fd)
	return err
}

func (t *recoveryTerminal) write(data []byte) error {
	for len(data) > 0 {
		if t.ctx.Err() != nil {
			return errors.New("terminal interrupted")
		}
		n, err := unix.Write(t.fd, data)
		if err == unix.EINTR || err == unix.EAGAIN {
			_, waitErr := recoveryWait(t.fd, true)
			if waitErr != nil {
				return errors.New("terminal write refused")
			}
			continue
		}
		if err != nil || n == 0 {
			return errors.New("terminal write refused")
		}
		data = data[n:]
	}
	return nil
}

func (t *recoveryTerminal) line(maximum int) ([]byte, error) {
	data := make([]byte, 0, maximum)
	for {
		if t.ctx.Err() != nil {
			clear(data)
			return nil, errors.New("terminal interrupted")
		}
		ready, err := recoveryWait(t.fd, false)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			clear(data)
			return nil, errors.New("terminal read refused")
		}
		if !ready {
			continue
		}

		var b [1]byte
		n, err := unix.Read(t.fd, b[:])
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 {
			clear(data)
			return nil, errors.New("terminal EOF")
		}
		if b[0] == '\n' {
			return data, nil
		}
		if len(data) >= maximum || b[0] < 32 || b[0] > 126 {
			clear(data)
			return nil, errors.New("invalid terminal input")
		}
		data = append(data, b[0])
	}
}

func (t *recoveryTerminal) ConfirmIdentities(p keyvault.RecoveryPlan) error {
	if err := t.write([]byte(fmt.Sprintf("Nostr identity: %s\nNamecoin identity: %s\nGroup: %s\nNostr record: %s\nNamecoin record: %s\n", p.NostrIdentity, p.NamecoinIdentity, p.Group, p.NostrRecord, p.NamecoinRecord))); err != nil {
		return err
	}
	for _, q := range []struct{ label, want string }{{"Nostr", p.NostrIdentity}, {"Namecoin", p.NamecoinIdentity}} {
		if err := t.write([]byte("Retype " + q.label + " identity: ")); err != nil {
			return err
		}
		got, err := t.line(128)
		matches := err == nil && bytes.Equal(got, []byte(q.want))
		clear(got)
		if !matches {
			return errors.New("identity confirmation refused")
		}
		if err := t.write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

func (t *recoveryTerminal) ConfirmMnemonic(words [][]byte) (err error) {
	defer func() {
		if e := t.Close(); err == nil {
			err = e
		}
	}()
	if len(words) != 24 {
		return errors.New("24 words required")
	}
	if err := t.write([]byte("\x1b[2J\x1b[3J\x1b[HRecord these 24 words in order in TWO offline places. Do not copy them to a file, clipboard, chat or agent pane.\n")); err != nil {
		return err
	}
	for i, word := range words {
		if err := t.write([]byte(strconv.Itoa(i+1) + ". ")); err != nil {
			return err
		}
		if err := t.write(word); err != nil {
			return err
		}
		if err := t.write([]byte("\n")); err != nil {
			return err
		}
	}
	if err := t.write([]byte("Type BACKED-UP when both offline backups are complete (input hidden): ")); err != nil {
		return err
	}
	answer, err := t.line(32)
	if err != nil {
		return err
	}
	backed := bytes.Equal(answer, []byte("BACKED-UP"))
	clear(answer)
	if !backed {
		return errors.New("backup not confirmed")
	}
	if err := t.write([]byte("\x1b[2J\x1b[3J\x1b[H")); err != nil {
		return err
	}
	selected := map[int]bool{}
	for len(selected) < 3 {
		position, err := rand.Int(t.random, big.NewInt(24))
		if err != nil {
			return errors.New("confirmation randomness unavailable")
		}
		i := int(position.Int64())
		if selected[i] {
			continue
		}
		selected[i] = true
		if err := t.write([]byte("Retype word " + strconv.Itoa(i+1) + " from the offline backup (hidden): ")); err != nil {
			return err
		}
		answer, err := t.line(16)
		if err != nil {
			return err
		}
		match := bytes.Equal(answer, words[i])
		clear(answer)
		if !match {
			return errors.New("backup confirmation refused")
		}
		if err := t.write([]byte("\n")); err != nil {
			return err
		}
	}
	return t.write([]byte("\x1b[2J\x1b[3J\x1b[HBackup confirmed. Creating separate Nostr and Touch-ID-protected Namecoin wraps. No transaction is signed.\n"))
}

func (t *recoveryTerminal) ReadMnemonic() (phrase []byte, err error) {
	defer func() {
		if e := t.Close(); err == nil {
			err = e
		}
		if err != nil {
			clear(phrase)
			phrase = nil
		}
	}()
	if err := t.write([]byte("Restore exactly 24 English words, separated by single spaces. Input is hidden; public pins will be checked before storage: ")); err != nil {
		return nil, err
	}
	phrase, err = t.line(512)
	if err == nil {
		err = t.write([]byte("\x1b[2J\x1b[3J\x1b[HChecking public recovery pins.\n"))
	}
	if err != nil {
		clear(phrase)
		return nil, err
	}
	return phrase, nil
}

// Darwin poll reports POLLNVAL for /dev/tty even when termios/read work.
// select supports the controlling terminal and provides bounded cancellation.
func recoveryWait(fd int, writing bool) (bool, error) {
	if fd < 0 || fd >= unix.FD_SETSIZE {
		return false, unix.EBADF
	}
	var set unix.FdSet
	set.Set(fd)
	timeout := unix.Timeval{Usec: 100000}
	var n int
	var err error
	if writing {
		n, err = unix.Select(fd+1, nil, &set, nil, &timeout)
	} else {
		n, err = unix.Select(fd+1, &set, nil, nil, &timeout)
	}
	return n > 0 && set.IsSet(fd), err
}
