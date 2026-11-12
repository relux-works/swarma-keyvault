//go:build darwin || linux

package namecoinlocalgate

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Guard owns a non-inherited listener. There is deliberately no descriptor,
// address, port, adoption or traffic API. Do not copy a Guard.
// Acquire in the helper itself before reading any anchor or journal; close only
// after private buffers, durable state, result handling and cleanup finish.
type Guard struct {
	mu  sync.Mutex
	fd  int
	pid int
}

// Acquire attempts exactly one fixed AF_INET bind and listen. A squatter can
// deny service but cannot cause admission through another lock or endpoint.
func Acquire() (*Guard, error) {
	// Protect the socket-to-CLOEXEC interval against concurrent Go fork/exec.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, ErrOperational
	}
	admitted := false
	defer func() {
		if !admitted {
			_ = unix.Close(fd)
		}
	}()
	for _, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, 0) != nil {
			return nil, ErrOperational
		}
	}
	if !reuseDisabled(fd) {
		return nil, ErrOperational
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Port: 47739, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return nil, refusal(err)
	}
	if err = unix.Listen(fd, 1); err != nil {
		return nil, refusal(err)
	}
	if !reuseDisabled(fd) {
		return nil, ErrOperational
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return nil, ErrOperational
	}
	admitted = true
	return &Guard{fd: fd, pid: os.Getpid()}, nil
}

func refusal(err error) error {
	if errors.Is(err, unix.EADDRINUSE) {
		return ErrAccountBusy
	}
	return ErrOperational
}

func reuseDisabled(fd int) bool {
	for _, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
		value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
		if err != nil || value != 0 {
			return false
		}
	}
	return true
}

// Close releases this process's gate once. Never retry a failed close: the
// descriptor may already have been released and reused by another goroutine.
func (g *Guard) Close() error {
	if g == nil {
		return ErrOperational
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pid != os.Getpid() {
		return ErrOperational
	}
	if g.fd < 0 {
		return nil
	}
	fd := g.fd
	g.fd = -1
	if unix.Close(fd) != nil {
		return ErrOperational
	}
	return nil
}
