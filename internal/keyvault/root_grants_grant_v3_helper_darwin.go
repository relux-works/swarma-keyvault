//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"syscall"
)

type rootGrantsGrantV3ProductionHelper struct{}

func (rootGrantsGrantV3ProductionHelper) ReviewSignGrantV3(ctx context.Context, request []byte) ([]byte, error) {
	return invokeRootGrantsGrantV3Helper(ctx, request)
}

func newRootGrantsGrantV3SigningHelper() RootGrantsGrantV3SigningHelper {
	return rootGrantsGrantV3ProductionHelper{}
}

type rootGrantsGrantV3ExecHost struct{ path string }

func (rootGrantsGrantV3ExecHost) verify(pid int, pin []byte) error {
	return verifyRecoveryCode(pid, pin)
}
func (h rootGrantsGrantV3ExecHost) start() (*rootGrantsHelperChild, error) {
	cmd := exec.Command(h.path, "--root-grants-sign-grant-v3")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
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

func invokeRootGrantsGrantV3Helper(parent context.Context, raw []byte) ([]byte, error) {
	if parent == nil {
		return nil, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	if _, err := rootGrantsGrantV3PlanFromHelperRequest(raw); err != nil {
		return nil, err
	}
	pin, err := rootGrantsHelperPin()
	if err != nil {
		return nil, rootGrantsGrantV3Failed("code_not_admitted", "preflight", false)
	}
	path, err := rootGrantsHelperPath()
	if err != nil {
		return nil, rootGrantsGrantV3Failed("operation_unavailable", "preflight", false)
	}
	payload, _, err := rootGrantsGrantV3HelperExchange(parent, raw, pin, rootGrantsGrantV3ExecHost{path: path})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// This operation has its own 120-second budget and entry point; it does not
// inherit attach's 900-second lifetime or response validator.
func rootGrantsGrantV3HelperExchange(parent context.Context, raw, pin []byte, host rootGrantsHelperHost) ([]byte, int, error) {
	if parent == nil || host == nil {
		return nil, 0, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	if len(pin) != 20 && len(pin) != 32 {
		return nil, 0, rootGrantsGrantV3Failed("code_not_admitted", "preflight", false)
	}
	ctx, cancel := context.WithTimeout(parent, rootGrantsGrantV3AttemptLimit)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, 0, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "preflight", false)
	}
	if host.verify(0, nil) != nil {
		return nil, 0, rootGrantsGrantV3Failed("code_not_admitted", "preflight", false)
	}
	child, err := host.start()
	if err != nil || child == nil {
		return nil, 0, rootGrantsGrantV3Failed("operation_unavailable", "preflight", false)
	}
	if child.pid <= 0 || host.verify(child.pid, pin) != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, rootGrantsGrantV3Failed("code_not_admitted", "preflight", false)
	}
	owned := bytes.Clone(raw)
	frames := make(chan rootGrantsHelperFrame, 1)
	go func() {
		defer clear(owned)
		if err := rootGrantsWriteFrame(child.input, owned); err != nil {
			frames <- rootGrantsHelperFrame{err: rootGrantsGrantV3Failed("private_protocol_error", "sign", true)}
			return
		}
		frame := rootGrantsReadGrantV3Frame(child.output)
		refusalFrame := frame.err == nil && frame.status == 1
		if frame.err == nil && frame.status == 0 {
			if len(frame.payload) != 64 {
				frame.err = rootGrantsGrantV3Failed("private_protocol_error", "verify", true)
			} else if plan, planErr := rootGrantsGrantV3PlanFromHelperRequest(owned); planErr != nil || plan.VerifySignature(frame.payload) != nil {
				frame.err = rootGrantsGrantV3Failed("signature_verification_failed", "verify", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "sign", true)
			} else if host.verify(child.pid, pin) != nil {
				frame.err = rootGrantsGrantV3Failed("code_not_admitted", "verify", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "verify", true)
			} else {
				ack := rootGrantsCompletionACK(owned, frame.payload)
				n, writeErr := child.input.Write(ack[:])
				if writeErr != nil || n != len(ack) {
					frame.err = rootGrantsGrantV3Failed("private_protocol_error", "receipt", true)
				}
			}
		} else if frame.err == nil && frame.status == 1 {
			code := binary.BigEndian.Uint32(frame.payload)
			if code == 14 || code == 15 || code == 16 {
				frame.err = rootGrantsGrantV3Failed(rootGrantsGrantV3HelperRefusalName(code), "sign", true)
			} else {
				frame.err = rootGrantsGrantV3HelperRefusalFailure(code)
			}
		}
		if frame.err == nil {
			if err := child.input.Close(); err != nil {
				frame.err = rootGrantsGrantV3Failed("private_protocol_error", "receipt", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "receipt", true)
			} else {
				var trailing [1]byte
				n, readErr := child.output.Read(trailing[:])
				if n != 0 || readErr != io.EOF {
					frame.err = rootGrantsGrantV3Failed("private_protocol_error", "receipt", true)
				}
			}
		} else if refusalFrame {
			if err := child.input.Close(); err != nil {
				frame.err = rootGrantsGrantV3Failed("private_protocol_error", "receipt", false)
			} else {
				var trailing [1]byte
				n, readErr := child.output.Read(trailing[:])
				if n != 0 || readErr != io.EOF {
					frame.err = rootGrantsGrantV3Failed("private_protocol_error", "receipt", false)
				}
			}
		} else {
			_ = child.input.Close()
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
		go func() { f := <-frames; clear(f.payload) }()
		return nil, 0, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(ctx.Err()), "sign", true)
	}
	if err := ctx.Err(); err != nil {
		clear(frame.payload)
		rootGrantsStopChild(child, nil)
		return nil, 0, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "receipt", true)
	}
	if frame.err != nil {
		rootGrantsStopChild(child, nil)
		var failure *RootGrantsGrantV3Failure
		if errors.As(frame.err, &failure) && failure != nil {
			return nil, 0, failure
		}
		return nil, 0, rootGrantsGrantV3Failed("private_protocol_error", "sign", true)
	}
	waited := rootGrantsWaitChild(child)
	select {
	case exitErr := <-waited:
		_ = child.output.Close()
		if err := ctx.Err(); err != nil {
			clear(frame.payload)
			return nil, 0, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "receipt", true)
		}
		if exitErr != nil {
			clear(frame.payload)
			return nil, 0, rootGrantsGrantV3Failed("private_protocol_error", "receipt", true)
		}
		return frame.payload, child.pid, nil
	case <-ctx.Done():
		clear(frame.payload)
		rootGrantsStopChild(child, waited)
		return nil, 0, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(ctx.Err()), "receipt", true)
	}
}

func rootGrantsGrantV3HelperRefusalName(code uint32) string {
	if code == 14 {
		return "canceled"
	}
	if code == 15 {
		return "timeout"
	}
	return "private_protocol_error"
}

func rootGrantsGrantV3HelperRefusalFailure(code uint32) error {
	if refusal := rootGrantsHelperRefusal(code); refusal != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(refusal), "sign", false)
	}
	return rootGrantsGrantV3Failed("private_protocol_error", "sign", false)
}
