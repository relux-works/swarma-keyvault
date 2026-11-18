//go:build darwin && cgo

package keyvault

import (
	"context"
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
	vault := newRootGrantsGrantV3SigningVault()
	check := func(ctx context.Context, request []byte) error {
		return rootGrantsGrantV3CheckForHelperWithContext(ctx, request, vault, LoadRootGrantsAuthority)
	}
	payload, _, err := rootGrantsGrantV3HelperExchange(parent, raw, pin,
		rootGrantsGrantV3ExecHost{path: path}, check)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// This operation has its own 120-second budget and entry point; it does not
// inherit attach's 900-second lifetime or response validator.
func rootGrantsGrantV3HelperExchange(parent context.Context, raw, pin []byte, host rootGrantsHelperHost,
	check func(context.Context, []byte) error) ([]byte, int, error) {
	return rootGrantsPrivateSigningExchange(parent, raw, pin, host, rootGrantsPrivateSigningPurpose{
		verifySignature: func(raw, signature []byte) error {
			plan, err := rootGrantsGrantV3PlanFromHelperRequest(raw)
			if err != nil {
				return err
			}
			return plan.VerifySignature(signature)
		},
		check:            check,
		controlResponse:  rootGrantsGrantV3ControlResponse,
		refusalFailure:   rootGrantsGrantV3HelperRefusalFailure,
		refusalCode:      rootGrantsGrantV3RefusalCode,
		uncertainRefusal: rootGrantsGrantV3HelperRefusalName,
		contextCode:      rootGrantsGrantV3ContextCode,
		verificationCode: func(error) string { return "signature_verification_failed" },
		failure:          rootGrantsGrantV3Failed,
	})
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
