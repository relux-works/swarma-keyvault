//go:build darwin || linux

package scripts_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type upstreamSpec struct {
	name, path string
	args, env  []string
	budget     time.Duration
}

type upstreamResult struct {
	name                                      string
	pid                                       int
	output                                    []byte
	elapsed                                   time.Duration
	startErr, waitErr, contextErr, cleanupErr error
}

func (r upstreamResult) failed() bool {
	return r.startErr != nil || r.waitErr != nil || r.contextErr != nil || r.cleanupErr != nil
}

// A failure never skips another selected module. Each invocation owns a new
// process group; the direct child is waited, and remaining group members must
// disappear within the cleanup bound. Descendants that deliberately escape the
// group are outside this harness contract; retained go test children inherit it.
func runUpstreamModules(specs []upstreamSpec) []upstreamResult {
	results := make([]upstreamResult, 0, len(specs))
	for _, spec := range specs {
		results = append(results, runUpstreamModule(spec))
	}
	return results
}

func runUpstreamModule(spec upstreamSpec) upstreamResult {
	started := time.Now()
	result := upstreamResult{name: spec.name}
	ctx, cancel := context.WithTimeout(context.Background(), spec.budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, spec.path, spec.args...)
	cmd.Env = spec.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	result.startErr = cmd.Start()
	if result.startErr == nil {
		result.pid = cmd.Process.Pid
		result.waitErr = cmd.Wait() // Reap the direct child, including cancellation.
	}
	// Snapshot the command's cause before cleanup; a later cleanup delay must
	// not relabel a completed command as a test deadline.
	result.contextErr = ctx.Err()
	cancel()
	if result.pid > 1 {
		result.cleanupErr = drainUpstreamGroup(result.pid)
	}
	result.output = append([]byte(nil), output.Bytes()...)
	result.elapsed = time.Since(started)
	return result
}

func drainUpstreamGroup(pgid int) error {
	if pgid <= 1 {
		return errors.New("invalid owned process group")
	}
	err := syscall.Kill(-pgid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned process group: %w", err)
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill owned process group: %w", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect draining process group: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("owned process group did not disappear within cleanup bound")
}
