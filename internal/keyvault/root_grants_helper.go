package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const rootGrantsHelperGrace = 2 * time.Second

// The private driver seam permits inert process/IO fault fixtures. It is never
// a product option: the Darwin factory fixes the executable, pin and verifier.
type rootGrantsHelperHost interface {
	verify(int, []byte) error
	start() (*rootGrantsHelperChild, error)
}
type rootGrantsHelperChild struct {
	pid    int
	input  io.WriteCloser
	output io.ReadCloser
	term   func() error
	kill   func() error
	wait   func() error
}
type rootGrantsExecHost struct{ path string }

func (rootGrantsExecHost) verify(pid int, pin []byte) error { return verifyRecoveryCode(pid, pin) }
func (h rootGrantsExecHost) start() (*rootGrantsHelperChild, error) {
	cmd := exec.Command(h.path, "--root-grants-private-v2")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	// Bounds os/exec's stderr copier if a descendant retains the descriptor.
	cmd.WaitDelay = rootGrantsHelperGrace
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	return &rootGrantsHelperChild{pid: cmd.Process.Pid, input: input, output: output,
		term: func() error { return cmd.Process.Signal(syscall.SIGTERM) }, kill: cmd.Process.Kill, wait: cmd.Wait}, nil
}

func rootGrantsHelperPin() ([]byte, error) {
	pin, err := hex.DecodeString(recoveryHelperCDHash)
	if err != nil || (len(pin) != 20 && len(pin) != 32) || hex.EncodeToString(pin) != recoveryHelperCDHash {
		return nil, recoveryRefuse("code_not_admitted")
	}
	return pin, nil
}
func rootGrantsHelperPath() (string, error) {
	exe, err := os.Executable()
	if err != nil || !filepath.IsAbs(exe) {
		return "", recoveryRefuse("operation_unavailable")
	}
	return filepath.Join(filepath.Dir(exe), "mac-keyvault-enclave"), nil
}

func rootGrantsWriteFrame(w io.Writer, raw []byte) error {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
	for _, part := range [][]byte{length[:], raw} {
		n, err := w.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Completion binds the EXACT exchanged public buffers, not reserialized JSON.
// This public lifetime message confers no presence, consent or store authority.
// Call only after bounded frame/full binding validation and live PID admission.
func rootGrantsCompletionACK(request, sealed []byte) [36]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("keyvault-root-grants-completion/2\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(request)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(request)
	_, _ = h.Write([]byte{0}) // exact success status
	binary.BigEndian.PutUint32(length[:], uint32(len(sealed)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(sealed)
	var ack [36]byte
	copy(ack[:4], "KVG2")
	copy(ack[4:], h.Sum(nil))
	return ack
}

// The fixed codes are ROOT ABI52 for grant signing; attach remains bounded to
// ABI51 statuses 1..20. Neither uses Namecoin's enum or raw stderr.
func rootGrantsHelperRefusal(code uint32) error {
	names := [...]string{"", "invalid_arguments", "terminal_required", "invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "invalid_derivation", "retained_record_mismatch", "public_pin_mismatch", "operation_unavailable", "wrapping_policy_refused", "invalid_envelope", "binding_mismatch", "canceled", "timeout", "private_protocol_error", "limit_exceeded", "unsupported_version", "unsupported_operation", "input_canceled", "code_not_admitted", "acl_refused", "lock_unavailable", "inventory_changed"}
	if code == 0 || code >= uint32(len(names)) {
		return recoveryRefuse("private_protocol_error")
	}
	return recoveryRefuse(names[code])
}

type rootGrantsHelperFrame struct {
	status  byte
	payload []byte
	err     error
}

func rootGrantsReadFrame(r io.Reader) rootGrantsHelperFrame {
	return rootGrantsReadFrameThrough(r, 20)
}

// The grant-sign helper adds only the stored-vault read refusals 21..24. Keep
// the attach helper's existing 1..20 status domain unchanged.
func rootGrantsReadGrantV3Frame(r io.Reader) rootGrantsHelperFrame {
	return rootGrantsReadFrameThrough(r, 24)
}

func rootGrantsReadFrameThrough(r io.Reader, maxStatus uint32) rootGrantsHelperFrame {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return rootGrantsHelperFrame{err: recoveryRefuse("private_protocol_error")}
	}
	n := binary.BigEndian.Uint32(header[1:])
	if (header[0] == 0 && (n == 0 || n > 131072)) || (header[0] == 1 && n != 4) || header[0] > 1 {
		return rootGrantsHelperFrame{err: recoveryRefuse("private_protocol_error")}
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		clear(payload)
		return rootGrantsHelperFrame{err: recoveryRefuse("private_protocol_error")}
	}
	if header[0] == 1 {
		code := binary.BigEndian.Uint32(payload)
		if code == 0 || code > maxStatus {
			clear(payload)
			return rootGrantsHelperFrame{err: recoveryRefuse("private_protocol_error")}
		}
	}
	return rootGrantsHelperFrame{status: header[0], payload: payload}
}

// The channel is buffered: an eventual reaper never waits for a returned caller.
func rootGrantsWaitChild(child *rootGrantsHelperChild) <-chan error {
	done := make(chan error, 1)
	go func() { done <- child.wait() }()
	return done
}

// Terminate only this invocation's process, with one TERM and fixed grace. Pipe
// closure unblocks owned IO. After the grace only that os.Process is killed;
// its already-started waiter remains responsible for eventual kernel reaping.
// A kill/wait failure never produces a plan or a cleanup/TTY-success claim.
func rootGrantsStopChild(child *rootGrantsHelperChild, waited <-chan error) {
	rootGrantsStopChildWithClock(child, waited, rootGrantsWallClock{})
}

// Private deterministic cleanup seam; production always uses the actual clock.
func rootGrantsStopChildWithClock(child *rootGrantsHelperChild, waited <-chan error, clock rootGrantsClock) {
	_ = child.input.Close()
	_ = child.output.Close()
	_ = child.term()
	if waited == nil {
		waited = rootGrantsWaitChild(child)
	}
	expired := make(chan struct{})
	timer := clock.AfterFunc(rootGrantsHelperGrace, func() { close(expired) })
	defer timer.Stop()
	select {
	case <-waited:
	case <-expired:
		_ = child.kill()
	}
}

func rootGrantsHelperExchange(parent context.Context, raw, pin []byte, host rootGrantsHelperHost) ([]byte, int, error) {
	if parent == nil {
		return nil, 0, recoveryRefuse("invalid_arguments")
	}
	ctx, cancel := context.WithTimeout(parent, rootGrantsAttemptLimit)
	defer cancel()
	if _, err := rootGrantsHelperRequest(raw); err != nil {
		return nil, 0, err
	}
	if len(pin) != 20 && len(pin) != 32 {
		return nil, 0, recoveryRefuse("code_not_admitted")
	}
	if err := rootGrantsBudgetError(ctx); err != nil {
		return nil, 0, err
	}
	if host.verify(0, nil) != nil {
		return nil, 0, recoveryRefuse("code_not_admitted")
	}
	if err := rootGrantsBudgetError(ctx); err != nil {
		return nil, 0, err
	}
	child, err := host.start()
	if err != nil {
		return nil, 0, recoveryRefuse("operation_unavailable")
	}
	// start's private contract guarantees complete owned pipes/process hooks.
	if child == nil {
		return nil, 0, recoveryRefuse("operation_unavailable")
	}
	if host.verify(child.pid, pin) != nil || child.pid <= 0 {
		rootGrantsStopChild(child, nil)
		return nil, 0, recoveryRefuse("code_not_admitted")
	}
	if err := rootGrantsBudgetError(ctx); err != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, err
	}
	// Own exact public bytes until the IO goroutine exits, even on cancellation.
	request := bytes.Clone(raw)
	frames := make(chan rootGrantsHelperFrame, 1)
	go func() {
		defer clear(request)
		if err := rootGrantsWriteFrame(child.input, request); err != nil {
			frames <- rootGrantsHelperFrame{err: recoveryRefuse("private_protocol_error")}
			return
		}
		// v2 keeps stdin open. The helper has closed all private/TTY state
		// before this frame and stays alive for the public completion ACK.
		frame := rootGrantsReadFrame(child.output)
		if frame.err == nil && frame.status == 0 {
			// Pure validation cannot certify ciphertext authenticity, but ALL
			// original request/result bindings must pass before any ACK.
			if _, _, err := rootGrantsCheckSealed(request, frame.payload); err != nil {
				frame.err = err
			} else if err := rootGrantsBudgetError(ctx); err != nil {
				frame.err = err
			} else if host.verify(child.pid, pin) != nil {
				// SAME actual live PID and fixed build pin; no path fallback.
				frame.err = recoveryRefuse("code_not_admitted")
			} else if err := rootGrantsBudgetError(ctx); err != nil {
				frame.err = err
			} else {
				ack := rootGrantsCompletionACK(request, frame.payload)
				n, err := child.input.Write(ack[:])
				if err != nil || n != len(ack) {
					frame.err = recoveryRefuse("private_protocol_error")
				}
			}
		}
		if frame.err == nil {
			// Success: ACK THEN stdin EOF. Refusal: stdin EOF with NO ACK.
			if err := child.input.Close(); err != nil {
				frame.err = recoveryRefuse("private_protocol_error")
			} else if err := rootGrantsBudgetError(ctx); err != nil {
				frame.err = err
			} else {
				// This is the FIRST post-frame read, only AFTER ACK/close.
				// No pre-ACK EOF wait, buffered extra byte or second frame.
				var extra [1]byte
				n, err := child.output.Read(extra[:])
				if n != 0 || err != io.EOF {
					frame.err = recoveryRefuse("private_protocol_error")
				}
			}
		}
		if frame.err != nil {
			clear(frame.payload)
			frame.payload = nil
		}
		frames <- frame
	}()
	var frame rootGrantsHelperFrame
	select {
	case frame = <-frames:
	case <-ctx.Done():
		rootGrantsStopChild(child, nil)
		// Closed pipes release normal readers/writers. Drain eventual public
		// output without blocking this canceled caller if an OS check stalls.
		go func() { f := <-frames; clear(f.payload) }()
		return nil, 0, rootGrantsBudgetError(ctx)
	}
	if err := rootGrantsBudgetError(ctx); err != nil {
		clear(frame.payload)
		rootGrantsStopChild(child, nil)
		return nil, 0, err
	}
	if frame.err != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, frame.err
	}
	waited := rootGrantsWaitChild(child) // only after stdout EOF, not while reading
	select {
	case exitErr := <-waited:
		_ = child.output.Close()
		if err := rootGrantsBudgetError(ctx); err != nil {
			clear(frame.payload)
			return nil, 0, err
		}
		if exitErr != nil {
			clear(frame.payload)
			return nil, 0, recoveryRefuse("private_protocol_error")
		}
		if frame.status == 1 {
			code := binary.BigEndian.Uint32(frame.payload)
			clear(frame.payload)
			return nil, 0, rootGrantsHelperRefusal(code)
		}
		return frame.payload, child.pid, nil
	case <-ctx.Done():
		clear(frame.payload)
		rootGrantsStopChild(child, waited)
		return nil, 0, rootGrantsBudgetError(ctx)
	}
}

// One finite caller holds the already accepted preflight guard through helper
// work and transfers it directly to commit. The backend/CLI are separate; this
// function cannot bootstrap a vault or manufacture a missing real backend.
func attachRootGrantsWithHelper(parent context.Context, vault rootGrantsAttachVault, raw []byte) (RootGrantsAttachResult, error) {
	var empty RootGrantsAttachResult
	if parent == nil {
		return empty, rootGrantsAttachFailed("invalid_arguments", "preflight", "not_applied", nil)
	}
	ctx, cancel := context.WithTimeout(parent, rootGrantsAttemptLimit)
	defer cancel()
	if len(raw) > 262144 {
		return empty, rootGrantsAttachFailed("limit_exceeded", "preflight", "not_applied", nil)
	}
	owned := bytes.Clone(raw)
	defer clear(owned)
	q, err := rootGrantsHelperRequest(owned)
	if err != nil {
		return empty, rootGrantsHelperAttachErrorAt(err, "preflight")
	}
	preflight, err := beginRootGrantsAttach(ctx, vault, RootGrantsAddress{Service: q.Service, Version: q.Version}, q.Pair)
	if err != nil {
		return empty, err
	}
	defer preflight.cancel()
	result, err := invokeRootGrantsHelper(ctx, owned)
	if err != nil {
		return empty, rootGrantsHelperAttachError(err)
	}
	plan, err := result.plan()
	if err != nil {
		return empty, rootGrantsHelperAttachError(err)
	}
	return preflight.commit(ctx, plan)
}
func rootGrantsHelperAttachError(err error) error {
	return rootGrantsHelperAttachErrorAt(err, "helper")
}
func rootGrantsHelperAttachErrorAt(err error, phase string) error {
	code := "private_protocol_error"
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal != nil {
		// Only our fixed refusals escape; no OS/parser/child diagnostics.
		for _, known := range []string{"code_not_admitted", "invalid_arguments", "terminal_required", "invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "invalid_derivation", "retained_record_mismatch", "public_pin_mismatch", "operation_unavailable", "wrapping_policy_refused", "invalid_envelope", "binding_mismatch", "canceled", "timeout", "private_protocol_error", "limit_exceeded", "unsupported_version", "unsupported_operation", "input_canceled"} {
			if refusal.Code == "recovery_"+known {
				code = known
				break
			}
		}
	}
	return rootGrantsAttachFailed(code, phase, "not_applied", nil)
}
