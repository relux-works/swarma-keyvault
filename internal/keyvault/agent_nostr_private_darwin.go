//go:build darwin && cgo

package keyvault

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const agentNostrPrivateTimeout = 120 * time.Second

type agentNostrProcessPrivate struct{}

func NewAgentNostrPrivate() AgentNostrPrivate { return agentNostrProcessPrivate{} }

func (agentNostrProcessPrivate) CreateWrap() (AgentNostrWrap, error) {
	request, err := agentNostrCreateWrapRequest()
	if err != nil {
		clear(request)
		return AgentNostrWrap{}, &AgentNostrPrivateError{Code: "unavailable"}
	}
	response, err := agentNostrCall("create-wrap", request, 24576)
	clear(request)
	if err != nil {
		return AgentNostrWrap{}, err
	}
	defer clear(response)
	return parseAgentNostrWrapResponse(response)
}

func (agentNostrProcessPrivate) UnwrapAgentNostr(envelope AgentNostrEnvelope) ([]byte, error) {
	request, err := agentNostrUnwrapRequest(envelope)
	if err != nil {
		return nil, &AgentNostrPrivateError{Code: "bad_request"}
	}
	defer clear(request)
	response, err := agentNostrCall("unwrap-agent-nostr", request, AgentNostrPlaintextSize)
	if err != nil {
		return nil, err
	}
	if len(response) != AgentNostrPlaintextSize {
		clear(response)
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	return response, nil
}

func agentNostrCall(operation string, request []byte, maxSuccess int) ([]byte, error) {
	if !agentNostrPrivateRequestWithinLimit(request) || (operation != "create-wrap" && operation != "unwrap-agent-nostr") {
		return nil, &AgentNostrPrivateError{Code: "bad_request"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentNostrPrivateTimeout)
	defer cancel()
	path, pin, err := NamecoinProcessHelper()
	if err != nil {
		var refusal *Refusal
		if errors.As(err, &refusal) && refusal.Code == "helper_not_admitted" {
			return nil, &AgentNostrPrivateError{Code: "not_admitted"}
		}
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	fd, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	syscall.CloseOnExec(fd[0])
	syscall.CloseOnExec(fd[1])
	parentFile := os.NewFile(uintptr(fd[0]), "agent-nostr-parent-socket")
	childFile := os.NewFile(uintptr(fd[1]), "agent-nostr-child-socket")
	if parentFile == nil || childFile == nil {
		if parentFile != nil {
			_ = parentFile.Close()
		} else {
			_ = syscall.Close(fd[0])
		}
		if childFile != nil {
			_ = childFile.Close()
		} else {
			_ = syscall.Close(fd[1])
		}
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	connValue, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	conn, ok := connValue.(*net.UnixConn)
	if !ok {
		_ = connValue.Close()
		_ = childFile.Close()
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	command := exec.CommandContext(ctx, path, "--agent-nostr-private-v1")
	command.ExtraFiles = []*os.File{childFile}
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = 500 * time.Millisecond
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := command.Process.Signal(syscall.SIGTERM)
		if errors.Is(err, os.ErrProcessDone) {
			return os.ErrProcessDone
		}
		return err
	}
	if err := command.Start(); err != nil {
		_ = childFile.Close()
		_ = conn.Close()
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	_ = childFile.Close()
	stop := func() {
		_ = conn.Close()
		cancel()
		_ = command.Wait()
	}
	if err := VerifyNamecoinProcessHelper(command.Process.Pid, pin); err != nil {
		stop()
		return nil, &AgentNostrPrivateError{Code: "not_admitted"}
	}
	deadline, ok := ctx.Deadline()
	if !ok || conn.SetDeadline(deadline) != nil {
		stop()
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(request)))
	copy(frame[4:], request)
	written, writeErr := writeAgentNostrFrame(conn, frame)
	clear(frame)
	if writeErr != nil {
		stop()
		if written > 0 {
			return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
		}
		return nil, &AgentNostrPrivateError{Code: "unavailable"}
	}
	if err := conn.CloseWrite(); err != nil {
		stop()
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	return receiveAgentNostrResult(conn, conn.Close, maxSuccess,
		func() (int, error) {
			err := command.Wait()
			return helperExitCode(err), err
		}, cancel, func() bool { return ctx.Err() != nil })
}

func writeAgentNostrFrame(conn *net.UnixConn, frame []byte) (int, error) {
	written := 0
	for written < len(frame) {
		n, err := conn.Write(frame[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func helperExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
