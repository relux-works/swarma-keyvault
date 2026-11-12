//go:build darwin || linux

package namecoinlocalgate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// No test uses a native key or ECDSA. EFFECT is a public simulated private-call
// counter, not a signature/Touch ID witness. All children acquire independently;
// readiness/completion pipes are unrelated to the never-connected gate socket.
func TestGateProcess(t *testing.T) {
	if os.Getenv("NAMECOIN_GATE_FIXTURE") != "1" {
		return
	}
	args := os.Args
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if len(args) != i+6 {
		os.Exit(90)
	}
	mode, root, audit, request, outpoint := args[i+1], args[i+2], args[i+3], args[i+4], args[i+5]
	if strings.HasPrefix(mode, "raw-") {
		bits, err := strconv.Atoi(strings.TrimPrefix(mode, "raw-"))
		if err != nil {
			os.Exit(91)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			os.Exit(92)
		}
		defer unix.Close(fd)
		for j, option := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT} {
			if unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, (bits>>j)&1) != nil {
				os.Exit(93)
			}
		}
		err = unix.Bind(fd, &unix.SockaddrInet4{Port: 47739, Addr: [4]byte{127, 0, 0, 1}})
		if err == nil {
			err = unix.Listen(fd, 1)
		}
		if err != nil {
			fmt.Println(refusal(err))
			return
		}
		fmt.Println("HELD")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	g, err := Acquire()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer g.Close()
	// Inspect the actual descriptor options, not a cached status boolean.
	if !reuseDisabled(g.fd) {
		os.Exit(94)
	}
	fmt.Println("HELD reuseaddr=0 reuseport=0")
	if mode == "crash" {
		// This public fence is not a protected anchor. Death/reacquisition only is
		// proved here; durable UNKNOWN and authentic restart need journal/native tests.
		if os.WriteFile(filepath.Join(audit, "fence"), []byte("DISPATCHED"), 0600) != nil {
			os.Exit(95)
		}
		os.Exit(31)
	}
	if mode == "holder" {
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			os.Exit(96)
		}
	}
	// The disposable lock/root is deliberately not used for exclusion. Reading it
	// occurs only after acquisition; replacing it cannot create another gate.
	if _, err := os.Stat(root); err != nil {
		os.Exit(97)
	}
	f, err := os.OpenFile(filepath.Join(audit, "effects"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		os.Exit(98)
	}
	if _, err = fmt.Fprintf(f, "EFFECT %s %s\n", request, outpoint); err != nil {
		os.Exit(99)
	}
	if f.Sync() != nil || f.Close() != nil {
		os.Exit(100)
	}
	fmt.Println("COMPLETE")
}

type child struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	lines  chan string
	cancel context.CancelFunc
	stderr bytes.Buffer
	waited bool
}

func startChild(t *testing.T, mode, root, audit, request string, selectedOutpoint ...string) *child {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	c := &child{cancel: cancel, lines: make(chan string, 8)}
	outpoint := "public-outpoint:0"
	if len(selectedOutpoint) == 1 {
		outpoint = selectedOutpoint[0]
	}
	c.cmd = exec.CommandContext(ctx, executable, "-test.run=^TestGateProcess$", "--", mode, root, audit, request, outpoint)
	// Minimal fixture-only environment: no inherited credentials/session data.
	c.cmd.Env = []string{"NAMECOIN_GATE_FIXTURE=1"}
	c.cmd.Stderr = &c.stderr
	c.input, err = c.cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := c.cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = c.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		defer close(c.lines)
		s := bufio.NewScanner(output)
		for s.Scan() {
			c.lines <- s.Text()
		}
	}()
	t.Cleanup(func() {
		_ = c.input.Close()
		if !c.waited {
			// Only this command's recorded child is stopped; never pattern-kill.
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
		cancel()
	})
	return c
}
func (c *child) line(t *testing.T, want string) {
	t.Helper()
	select {
	case got, ok := <-c.lines:
		if !ok || got != want {
			t.Fatalf("child line %q, want %q", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child readiness timeout")
	}
}
func (c *child) wait(t *testing.T, code int) {
	t.Helper()
	err := c.cmd.Wait()
	c.waited = true
	c.cancel()
	if c.cmd.ProcessState.ExitCode() != code {
		t.Fatalf("child exit: %v, want %d; %s", err, code, c.stderr.String())
	}
}
func (c *child) release(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(c.input, "finish\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.input.Close()
}
func fixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	audit := filepath.Join(base, "audit")
	for _, p := range []string{root, audit} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".lock"), []byte("disposable"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, audit
}
func requireEffects(t *testing.T, audit string, count int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(audit, "effects"))
	if count == 0 && errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte("EFFECT ")) != count {
		t.Fatalf("effect count: %q", raw)
	}
}

// Positive completion and paired refusal share a real holder. Different request
// IDs name the same simulated outpoint. No test runs in parallel on the fixed port.
func TestPairedProcessesAndReplacedRoot(t *testing.T) {
	root, audit := fixture(t)
	owner := startChild(t, "holder", root, audit, "request-one")
	owner.line(t, "HELD reuseaddr=0 reuseport=0")
	if err := os.Remove(filepath.Join(root, ".lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".lock"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	contender := startChild(t, "once", root, audit, "request-two")
	contender.line(t, "account_busy")
	contender.wait(t, 0)
	requireEffects(t, audit, 0)
	for _, bits := range []int{0, 1, 2, 3} {
		other := startChild(t, fmt.Sprintf("raw-%d", bits), root, audit, "reuse-probe")
		other.line(t, "account_busy")
		other.wait(t, 0)
	}
	owner.release(t)
	owner.line(t, "COMPLETE")
	owner.wait(t, 0)
	requireEffects(t, audit, 1)
	// Reacquisition is a liveness control only, not replay admission.
	next := startChild(t, "holder", root, audit, "control", "public-control-outpoint:1")
	next.line(t, "HELD reuseaddr=0 reuseport=0")
	next.release(t)
	next.line(t, "COMPLETE")
	next.wait(t, 0)
	requireEffects(t, audit, 2)
}

// A foreign socket holder denies service only; the simulated private boundary
// remains untouched. This does not establish protection from privileged attackers.
func TestSquatterRefusesBeforeState(t *testing.T) {
	root, audit := fixture(t)
	squatter := startChild(t, "raw-3", root, audit, "squatter")
	squatter.line(t, "HELD")
	other := startChild(t, "once", root, audit, "refused")
	other.line(t, "account_busy")
	other.wait(t, 0)
	requireEffects(t, audit, 0)
	squatter.release(t)
	squatter.wait(t, 0)
	control := startChild(t, "once", root, audit, "positive")
	control.line(t, "HELD reuseaddr=0 reuseport=0")
	control.line(t, "COMPLETE")
	control.wait(t, 0)
	requireEffects(t, audit, 1)
}

// A stopped owner retains exclusion; death releases it. The crash fence remains
// public fixture evidence, not an authenticated journal recovery witness.
func TestStoppedOwnerAndCrashRelease(t *testing.T) {
	root, audit := fixture(t)
	owner := startChild(t, "holder", root, audit, "stopped")
	owner.line(t, "HELD reuseaddr=0 reuseport=0")
	if err := owner.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	other := startChild(t, "once", root, audit, "contender")
	other.line(t, "account_busy")
	other.wait(t, 0)
	requireEffects(t, audit, 0)
	if err := owner.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	owner.release(t)
	owner.line(t, "COMPLETE")
	owner.wait(t, 0)
	crash := startChild(t, "crash", root, audit, "crash")
	crash.line(t, "HELD reuseaddr=0 reuseport=0")
	crash.wait(t, 31)
	fence, err := os.ReadFile(filepath.Join(audit, "fence"))
	if err != nil || string(fence) != "DISPATCHED" {
		t.Fatal("lost crash fence")
	}
	control := startChild(t, "once", root, audit, "after-death", "public-control-outpoint:1")
	control.line(t, "HELD reuseaddr=0 reuseport=0")
	control.line(t, "COMPLETE")
	control.wait(t, 0)
}

// Closed classification does not leak raw OS errors. Kernel failures other than
// contention are classified here, not claimed as exercised OS exhaustion.
func TestRefusalAndClose(t *testing.T) {
	if refusal(unix.EADDRINUSE) != ErrAccountBusy || refusal(unix.EACCES) != ErrOperational {
		t.Fatal("refusal vocabulary")
	}
	g, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	if !reuseDisabled(g.fd) {
		t.Fatal("reuse enabled")
	}
	flags, err := unix.FcntlInt(uintptr(g.fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("inheritable descriptor")
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
}
