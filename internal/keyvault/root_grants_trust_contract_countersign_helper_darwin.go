//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"syscall"
)

type rootGrantsTrustContractCountersignProductionHelper struct{}

func (rootGrantsTrustContractCountersignProductionHelper) ReviewSignTrustContractCountersign(ctx context.Context, request []byte) ([]byte, error) {
	return invokeRootGrantsTrustContractCountersignHelper(ctx, request)
}

func newRootGrantsTrustContractCountersignHelper() RootGrantsTrustContractCountersignHelper {
	return rootGrantsTrustContractCountersignProductionHelper{}
}

type rootGrantsTrustContractCountersignExecHost struct{ path string }

func (rootGrantsTrustContractCountersignExecHost) verify(pid int, pin []byte) error {
	return verifyRecoveryCode(pid, pin)
}

func (h rootGrantsTrustContractCountersignExecHost) start() (*rootGrantsHelperChild, error) {
	cmd := exec.Command(h.path, "--root-grants-sign-trust-contract-countersign-v1")
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
	return &rootGrantsHelperChild{
		pid:    cmd.Process.Pid,
		input:  input,
		output: output,
		term:   func() error { return cmd.Process.Signal(syscall.SIGTERM) },
		kill:   cmd.Process.Kill,
		wait:   cmd.Wait,
	}, nil
}

func invokeRootGrantsTrustContractCountersignHelper(parent context.Context, raw []byte) ([]byte, error) {
	if parent == nil {
		return nil, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
	if err != nil {
		return nil, err
	}
	parsed.clear()
	pin, err := rootGrantsHelperPin()
	if err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("code_not_admitted", "preflight", false)
	}
	defer clear(pin)
	path, err := rootGrantsHelperPath()
	if err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("operation_unavailable", "preflight", false)
	}
	vault := newRootGrantsGrantV3SigningVault()
	ownedRequest := bytes.Clone(raw)
	defer clear(ownedRequest)
	check := func(ctx context.Context, _ rootGrantsTrustContractCountersignHelperRequestData) error {
		// The exchange binds its parsed clone to ownedRequest before recheck.
		// The policy checker consumes wire bytes, so preserve its full parse semantics.
		return rootGrantsTrustContractCountersignCheckForHelperWithContext(ctx, ownedRequest, vault, LoadRootGrantsAuthority)
	}
	signature, _, err := rootGrantsTrustContractCountersignHelperExchange(parent, ownedRequest, pin,
		rootGrantsTrustContractCountersignExecHost{path: path}, check)
	if err != nil {
		clear(signature)
		return nil, err
	}
	return signature, nil
}
