package kekclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// waitDelay bounds how long Unwrap and Rebind wait for the broker's pipes
// after it was stopped or exited.
const waitDelay = 2 * time.Second

// exitGrace is how long a broker that answered gets to exit by itself.
const exitGrace = time.Second

// answerRead and responseDecoded see the answer buffer and the decoded
// response; tests replace them to check that refused answers are cleared.
var (
	answerRead      = func([]byte) {}
	responseDecoded = func(*Response) {}
)

// killGroup sends SIGKILL to the process group pgid; tests replace it to
// check when it runs.
var killGroup = func(pgid int) { syscall.Kill(-pgid, syscall.SIGKILL) }

// ErrProtocol reports a broker answer outside the contract. The answer is
// not used.
var ErrProtocol = errors.New("mac-keyvault-kek answered outside contract kek-1")

// Options say which broker to run and how to reach it.
type Options struct {
	// Broker is the absolute path of mac-keyvault-kek.
	Broker string
	// SocketDir is an absolute directory owned by the caller with no group
	// or other permissions, such as the service's data directory. The
	// broker's socket is created in it for one request.
	// Preflight refuses it if the generated pathname would exceed 103 bytes.
	SocketDir string
	// Timeout bounds the whole exchange; zero means 30 seconds.
	Timeout time.Duration
}

// Unwrap returns the KEK sealed in envelope. The broker answers only when
// this process's code satisfies the requirement inside the envelope.
func Unwrap(ctx context.Context, opts Options, envelope []byte) ([]byte, error) {
	env, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	res, err := exchange(ctx, opts, OpUnwrap, env, envelope)
	if err != nil {
		return nil, err
	}
	if len(res.KEK) != KEKLen || res.Envelope != nil {
		clear(res.KEK)
		return nil, fmt.Errorf("%w: unwrap result is not one %d-byte KEK", ErrProtocol, KEKLen)
	}
	// Only the KEK sealed in this envelope matches its check value, so a
	// substituted broker cannot choose the KEK for an unchanged envelope.
	// The envelope itself is a same-user file: rewritten together with the
	// broker, it can carry the check value of a chosen KEK. That case is
	// caught by the service's own store check, which must fail closed.
	if !MatchesKCV(res.KEK, env.KCV) {
		clear(res.KEK)
		return nil, fmt.Errorf("%w: the returned KEK does not match the envelope's check value", ErrProtocol)
	}
	return res.KEK, nil
}

// Rebind asks the broker to bind envelope's KEK to the code installed at
// the envelope's install path, and returns the new envelope. Only the code
// the envelope is bound to now may ask; the KEK itself is never returned.
func Rebind(ctx context.Context, opts Options, envelope []byte) ([]byte, error) {
	env, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	res, err := exchange(ctx, opts, OpRebind, env, envelope)
	if err != nil {
		return nil, err
	}
	if res.KEK != nil {
		clear(res.KEK)
		return nil, fmt.Errorf("%w: rebind returned a KEK", ErrProtocol)
	}
	next, err := ParseEnvelope(res.Envelope)
	if err != nil || next.Address != env.Address || next.Generation != env.Generation || next.Fingerprint != env.Fingerprint || !bytes.Equal(next.KCV, env.KCV) {
		return nil, fmt.Errorf("%w: rebind returned an envelope for another key", ErrProtocol)
	}
	return bytes.Clone(res.Envelope), nil
}

func exchange(ctx context.Context, opts Options, op string, env Envelope, envelope []byte) (*Result, error) {
	if err := Preflight(opts); err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	sock := socketPath(opts.SocketDir, nonce)
	defer os.Remove(sock)

	// exec.Command, not CommandContext: a context-driven Cancel would run
	// on its own goroutine and could signal the group after Wait reaped the
	// broker, when its pid may already belong to someone else. The
	// deadline is enforced in talk, and the one group signal below is sent
	// synchronously, before Wait.
	cmd := exec.Command(opts.Broker, op, "--address", env.Address, "--socket", sock)
	cmd.Stdin = nil
	// The broker runs in its own process group, which is killed after every
	// exchange, so a descendant that stays in the group does not outlive
	// it; WaitDelay bounds the wait for pipes. A process that leaves the
	// group on purpose is not contained.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = waitDelay
	var stderr bytes.Buffer
	cmd.Stderr = &limited{w: &stderr, n: 4096}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start broker: %w", err)
	}
	res, err := talk(ctx, stdout, sock, op, env, envelope)
	if err == nil {
		// A broker that answered exits by itself; give it exitGrace to do
		// so, so its own exit status is kept.
		awaitExit(cmd.Process.Pid, exitGrace)
	}
	// The only signal to the group. Until Wait reaps the broker its pid,
	// which is also the group's id, cannot be reused, so this reaches only
	// the broker and its own descendants, whichever way the exchange
	// ended. A broker that has already exited is a zombie and keeps its
	// exit status.
	killGroup(cmd.Process.Pid)
	waitErr := cmd.Wait()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%w (broker: %s)", err, bytes.TrimSpace(stderr.Bytes()))
		}
		return nil, err
	}
	if waitErr != nil {
		clear(res.KEK)
		return nil, fmt.Errorf("broker exited with %v after answering", waitErr)
	}
	return res, nil
}

// talk waits for the broker's ready line, sends the request and reads the
// one answer line.
func talk(ctx context.Context, stdout io.Reader, sock, op string, env Envelope, envelope []byte) (*Result, error) {
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(stdout, 512)).ReadString('\n')
		if err == nil && line != "listening "+sock+"\n" {
			err = fmt.Errorf("%w: broker said %q before listening", ErrProtocol, line)
		}
		ready <- err
		io.Copy(io.Discard, stdout)
	}()
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("broker did not listen: %w", ctx.Err())
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connect to broker: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	// Cancellation before the deadline ends a connected exchange too: it
	// closes only the connection, so the blocked write or read returns. The
	// broker's group is still signalled once, by exchange, before Wait.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	line, err := json.Marshal(Request{Contract: Contract, Op: op, Address: env.Address, Envelope: envelope})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	// The answer is read into one buffer of fixed size that this code owns
	// and clears in full on every path, including an error after a whole
	// answer arrived without its newline. No bufio reader: its internal
	// buffer would keep a copy of the KEK-bearing line.
	buf := make([]byte, 2*maxEnvelopeBytes)
	defer clear(buf)
	answer, err := readLine(conn, buf)
	answerRead(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: no answer line: %v", ErrProtocol, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("exchange cancelled: %w", err)
	}
	return checkResponse(answer, env)
}

// readLine reads from r into buf until a newline, and returns the line,
// newline included, as a view into buf. It never grows buf, so no copy of
// what it read is left elsewhere; a line longer than buf is an error.
func readLine(r io.Reader, buf []byte) ([]byte, error) {
	n := 0
	for {
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			return buf[:i+1], nil
		}
		if n == len(buf) {
			return nil, errors.New("answer line too long")
		}
		k, err := r.Read(buf[n:])
		n += k
		if err != nil {
			if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
				return buf[:i+1], nil
			}
			return nil, err
		}
	}
}

// checkResponse admits only a contract answer about the envelope's key. A
// KEK decoded from an answer it refuses is cleared on every refusal path.
func checkResponse(line []byte, env Envelope) (res *Result, err error) {
	resp, perr := parseResponse(bytes.TrimSuffix(line, []byte("\n")))
	responseDecoded(&resp)
	defer func() {
		if err != nil && resp.Result != nil {
			clear(resp.Result.KEK)
		}
	}()
	if perr != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, perr)
	}
	if resp.Contract != Contract {
		return nil, fmt.Errorf("%w: contract %q", ErrProtocol, resp.Contract)
	}
	if !resp.OK {
		if !declared(resp.Error.Code) {
			return nil, fmt.Errorf("%w: undeclared error code %q", ErrProtocol, resp.Error.Code)
		}
		return nil, resp.Error
	}
	res = resp.Result
	if res.Address != env.Address || res.Generation != env.Generation || res.Fingerprint != env.Fingerprint {
		return nil, fmt.Errorf("%w: answer is about another key", ErrProtocol)
	}
	return res, nil
}

// checkSocketDir requires a real directory owned by this user with no group
// or other permissions, so no other user can reach or replace the socket.
func checkSocketDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("socket dir %q is not a clean absolute path", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	return checkSocketDirMetadata(dir, info, uint32(os.Getuid()))
}

func checkSocketDirMetadata(dir string, info os.FileInfo, uid uint32) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return fmt.Errorf("socket dir %s is not a directory", dir)
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("socket dir %s has group or other permissions", dir)
	case !ok || st.Uid != uid:
		return fmt.Errorf("socket dir %s is not owned by this user", dir)
	}
	return nil
}

// limited keeps the first n bytes written and drops the rest.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
