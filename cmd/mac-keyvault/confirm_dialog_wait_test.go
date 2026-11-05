package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the production command configuration without invoking osascript.
// An exact grant string is insufficient when pipe cleanup reports failure.
func TestConfirmDialogInheritedPipesRefused(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(strconv.FormatBool(stall), func(t *testing.T) {
			stubDialog(t, signRequest(), "", nil)
			pidPath := filepath.Join(t.TempDir(), "pid")
			t.Cleanup(func() {
				data, err := os.ReadFile(pidPath)
				if err != nil {
					return
				}
				pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
				if err == nil && pid > 1 {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			})
			var commandErr error
			runOSAScript = func(ctx context.Context, args ...string) ([]byte, error) {
				if stall {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancel()
				}
				cmd := dialogCommand(ctx, args...)
				if cmd.Path != "/usr/bin/osascript" {
					t.Fatalf("unexpected production command: %s", cmd.Path)
				}
				script := "/bin/sleep 6 &\nprintf '%s' $! > '" + pidPath + "'\nprintf 'Sign|false\\n'\n"
				if stall {
					script += "wait\n"
				}
				cmd.Path, cmd.Args = "/bin/sh", []string{"/bin/sh", "-c", script}
				data, err := cmd.Output()
				commandErr = err
				return data, err
			}
			var stdout, stderr bytes.Buffer
			start := time.Now()
			code := run([]string{"confirm-dialog"}, &stdout, &stderr)
			if code != exitRefused {
				t.Fatalf("dialog pipe failure refusal predicate: code=%d, err=%v", code, commandErr)
			}
			if !stall && !errors.Is(commandErr, exec.ErrWaitDelay) {
				t.Fatalf("dialog pipe failure predicate: %v", commandErr)
			}
			if commandErr == nil {
				t.Fatal("dialog cleanup falsely succeeded")
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("dialog pipe wait not bounded: %v", elapsed)
			}
		})
	}
}
