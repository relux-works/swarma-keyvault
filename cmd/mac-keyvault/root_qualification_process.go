package main

import (
	"context"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// The exchange layer has no code/native provider. Production calls it ONLY
// after authenticating the actual live fixed-role child and artifact pin.
// Tests can exercise public transport behavior without claiming ACL evidence.
func rootQualificationExchange(input io.WriteCloser, output io.Reader, request rootqualification.Request) (rootqualification.Result, error) {
	if rootqualification.WriteRequest(input, request) != nil {
		_ = input.Close()
		return rootqualification.Unqualified, errRootQualification
	}
	if input.Close() != nil {
		return rootqualification.Unqualified, errRootQualification
	}
	return rootqualification.ReadResponse(output)
}

func rootQualificationControl(ctx context.Context, observed *rootqualification.ObservedCandidate, role codesignpolicy.Role, request rootqualification.Request) (rootqualification.Result, error) {
	if ctx == nil || ctx.Err() != nil || (role != codesignpolicy.Helper && role != codesignpolicy.Qualification) {
		return rootqualification.Unqualified, errRootQualification
	}
	path, pin, err := observed.Child(role)
	if err != nil {
		return rootqualification.Unqualified, errRootQualification
	}
	args := []string{"--root-grants-qualification-read"}
	if role == codesignpolicy.Qualification {
		args = []string{"--json", "root-grants", "qualify-storage", "--case", "child-read"}
	}
	cmd := exec.Command(path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = rootQualificationReapGrace
	input, err := cmd.StdinPipe()
	if err != nil {
		return rootqualification.Unqualified, errRootQualification
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return rootqualification.Unqualified, errRootQualification
	}
	if ctx.Err() != nil {
		_ = input.Close()
		_ = output.Close()
		return rootqualification.Unqualified, errRootQualification
	}
	if cmd.Start() != nil {
		_ = input.Close()
		_ = output.Close()
		return rootqualification.Unqualified, errRootQualification
	}
	defer input.Close()
	defer output.Close()
	// No frame/ref bytes have been written when native identity checks fail.
	if keyvault.RootQualificationCode(role, cmd.Process.Pid, pin) != nil || ctx.Err() != nil {
		_ = input.Close()
		_ = output.Close()
		rootQualificationTerminate(cmd, nil)
		return rootqualification.Unqualified, errRootQualification
	}
	type exchanged struct {
		result rootqualification.Result
		err    error
	}
	done := make(chan exchanged, 1)
	go func() {
		result, err := rootQualificationExchange(input, output, request)
		done <- exchanged{result, err}
	}()
	var result exchanged
	select {
	case result = <-done:
	case <-ctx.Done():
		_ = input.Close()
		_ = output.Close()
		rootQualificationTerminate(cmd, nil)
		return rootqualification.Unqualified, errRootQualification
	}
	if result.err != nil {
		_ = input.Close()
		_ = output.Close()
		rootQualificationTerminate(cmd, nil)
		return rootqualification.Unqualified, errRootQualification
	}
	// EOF precedes Wait, so os/exec cannot close stdout before its final bytes
	// are read. A well-formed result still requires the actual child exit0.
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err := <-wait:
		if err != nil || ctx.Err() != nil {
			return rootqualification.Unqualified, errRootQualification
		}
		return result.result, nil
	case <-ctx.Done():
		rootQualificationTerminate(cmd, wait)
		return rootqualification.Unqualified, errRootQualification
	}
}

// Stop only this owned cmd.Process, TERM first, then bounded exact-PID kill
// and reap. No pattern kill, retry, descendant/session control or time renewal.
func rootQualificationTerminate(cmd *exec.Cmd, wait <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	if wait == nil {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		wait = done
	}
	first := time.NewTimer(rootQualificationReapGrace)
	defer first.Stop()
	select {
	case <-wait:
		return
	case <-first.C:
	}
	_ = cmd.Process.Kill()
	second := time.NewTimer(rootQualificationReapGrace)
	defer second.Stop()
	select {
	case <-wait:
		return
	case <-second.C:
		return
	}
}
