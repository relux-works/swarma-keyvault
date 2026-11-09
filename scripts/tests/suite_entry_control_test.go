//go:build darwin || linux

package scripts_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The workflow's no-op signal traps retain the shell entry while a child tree
// is active, allowing a hosting runner to escalate to the complete tree. The
// untrapped neighbor loses that entry on TERM. This tests Bash behavior locally,
// not the hosted step timer or the runner's descendant-kill implementation.
func TestSuiteEntrySignalRetention(t *testing.T) {
	for _, trapped := range []bool{true, false} {
		t.Run(map[bool]string{true: "retained", false: "untrapped-control"}[trapped], func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "owned.json")
			script := `"$1" -test.run=^TestUpstreamProcessFixture$`
			if trapped {
				script = `trap ':' INT TERM; ` + script
			}
			cmd := exec.Command("/bin/bash", "-c", script, "suite-entry-fixture", os.Args[0])
			cmd.Env = append(os.Environ(), "KEYVAULT_UPSTREAM_FIXTURE=timeout", "KEYVAULT_UPSTREAM_PID_FILE="+pidFile)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pgid := cmd.Process.Pid
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			waited := false
			var pids []int
			t.Cleanup(func() {
				// Release the known leaf first, allowing its parent to Wait and
				// exit normally. A negative-group kill is emergency cleanup only.
				if len(pids) == 2 {
					_ = syscall.Kill(pids[1], syscall.SIGKILL)
				} else {
					_ = syscall.Kill(-pgid, syscall.SIGKILL)
				}
				if !waited {
					select {
					case <-exited:
					case <-time.After(3 * time.Second):
						_ = syscall.Kill(-pgid, syscall.SIGKILL)
						t.Error("suite-entry direct child was not reaped")
					}
				}
				for _, pid := range pids {
					until := time.Now().Add(2 * time.Second)
					for !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
						if time.Now().After(until) {
							t.Error("owned suite-entry fixture PID survives cleanup")
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			})
			readyUntil := time.Now().Add(5 * time.Second)
			for {
				raw, err := os.ReadFile(pidFile)
				if err == nil && json.Unmarshal(raw, &pids) == nil && len(pids) == 2 {
					break
				}
				if time.Now().After(readyUntil) {
					t.Fatal("suite-entry fixture did not start its complete owned tree")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			if trapped {
				time.Sleep(100 * time.Millisecond)
				for _, pid := range append([]int{pgid}, pids...) {
					if syscall.Kill(pid, 0) != nil {
						t.Fatal("trapped entry lost its active child tree before escalation")
					}
				}
			} else {
				select {
				case err := <-exited:
					waited = true
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						t.Fatal("untrapped entry did not retain its signal failure")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("untrapped entry did not demonstrate the cancellation gap")
				}
			}
		})
	}
}
