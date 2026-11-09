//go:build darwin || linux

package scripts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func upstreamFixtureSpec(name, mode, pidFile string) upstreamSpec {
	return upstreamSpec{
		name: name, path: os.Args[0],
		args:   []string{"-test.run=^TestUpstreamProcessFixture$"},
		env:    append(os.Environ(), "KEYVAULT_UPSTREAM_FIXTURE="+mode, "KEYVAULT_UPSTREAM_PID_FILE="+pidFile),
		budget: 10 * time.Second,
	}
}

// These exercise real child/grandchild processes in isolated groups. A successful
// tree is reaped; early exit and deadline with an inherited-pipe descendant both
// fail the aggregate, preserve the next module's success, and leave no PID alive.
// This does not cover descendants that deliberately change their process group.
func TestUpstreamProcessLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			firstPIDs := filepath.Join(dir, "first.json")
			secondPIDs := filepath.Join(dir, "second.json")
			cleanupNeeded := true
			// Emergency cleanup names only fixture PIDs captured by this test.
			// Assertions below, before cleanup, establish the runner's behavior.
			t.Cleanup(func() {
				if !cleanupNeeded {
					return
				}
				for _, path := range []string{firstPIDs, secondPIDs} {
					data, _ := os.ReadFile(path)
					var pids []int
					_ = json.Unmarshal(data, &pids)
					for _, pid := range pids {
						if pid > 1 {
							_ = syscall.Kill(pid, syscall.SIGKILL)
						}
					}
				}
			})
			results := runUpstreamModules([]upstreamSpec{
				upstreamFixtureSpec("first", mode, firstPIDs),
				upstreamFixtureSpec("second", "success", secondPIDs),
			})
			if len(results) != 2 || results[1].name != "second" || results[1].failed() || !strings.Contains(string(results[1].output), "fixture complete") {
				t.Fatal("later module did not run successfully after first result")
			}
			first := results[0]
			if first.startErr != nil || first.cleanupErr != nil {
				t.Fatalf("fixture startup or cleanup failed: start=%v cleanup=%v", first.startErr, first.cleanupErr)
			}
			switch mode {
			case "success":
				if first.failed() {
					t.Fatalf("successful tree refused: %+v", first)
				}
			case "failure":
				var exit *exec.ExitError
				if !first.failed() || !errors.As(first.waitErr, &exit) || exit.ExitCode() != 7 || first.contextErr != nil {
					t.Fatal("early failure lost its exit cause or became a deadline")
				}
			case "timeout":
				if !first.failed() || !errors.Is(first.contextErr, context.DeadlineExceeded) {
					t.Fatal("timeout did not retain its actual deadline cause")
				}
			}
			anyFailed := false
			for _, result := range results {
				anyFailed = anyFailed || result.failed()
			}
			if anyFailed != (mode != "success") {
				t.Fatal("aggregate did not retain required failure/success")
			}
			for _, path := range []string{firstPIDs, secondPIDs} {
				data, err := os.ReadFile(path)
				var pids []int
				if err != nil || json.Unmarshal(data, &pids) != nil || len(pids) != 2 {
					t.Fatal("fixture did not witness both owned generations")
				}
				for _, pid := range pids {
					if pid <= 1 || !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
						t.Fatal("owned child or descendant survives runner return")
					}
				}
			}
			cleanupNeeded = false
		})
	}
}

// A missing executable is a setup refusal, distinct from a test failure or
// deadline, and does not prevent the next selected command from succeeding.
func TestUpstreamStartRefusal(t *testing.T) {
	dir := t.TempDir()
	results := runUpstreamModules([]upstreamSpec{
		{name: "missing", path: filepath.Join(dir, "missing"), budget: time.Second},
		upstreamFixtureSpec("next", "success", filepath.Join(dir, "next.json")),
	})
	if len(results) != 2 || results[0].startErr == nil || results[0].contextErr != nil || results[0].pid != 0 || !results[0].failed() || results[1].failed() {
		t.Fatal("setup refusal misclassified or prevented later command")
	}
}

// Subprocess entry point, exercised only by the real lifecycle fixtures above.
func TestUpstreamProcessFixture(t *testing.T) {
	mode := os.Getenv("KEYVAULT_UPSTREAM_FIXTURE")
	if mode == "" {
		return
	}
	pidFile := os.Getenv("KEYVAULT_UPSTREAM_PID_FILE")
	if mode == "leaf" {
		signal.Ignore(syscall.SIGTERM)
		if os.WriteFile(pidFile+".ready", []byte("ready"), 0600) != nil {
			os.Exit(93)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	leaf := exec.Command(os.Args[0], "-test.run=^TestUpstreamProcessFixture$")
	leaf.Env = append(os.Environ(), "KEYVAULT_UPSTREAM_FIXTURE=leaf")
	leaf.Stdout, leaf.Stderr = os.Stdout, os.Stderr
	if leaf.Start() != nil {
		os.Exit(94)
	}
	pids, _ := json.Marshal([]int{os.Getpid(), leaf.Process.Pid})
	if os.WriteFile(pidFile, pids, 0600) != nil {
		_ = leaf.Process.Kill()
		_ = leaf.Wait()
		os.Exit(95)
	}
	readyBy := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(pidFile + ".ready"); err == nil {
			break
		}
		if time.Now().After(readyBy) {
			_ = leaf.Process.Kill()
			_ = leaf.Wait()
			os.Exit(96)
		}
		time.Sleep(10 * time.Millisecond)
	}
	switch mode {
	case "success":
		_ = leaf.Process.Kill()
		_ = leaf.Wait()
		fmt.Println("fixture complete")
		os.Exit(0)
	case "failure":
		os.Exit(7) // Deliberate pipe-holding orphan inside this owned group.
	case "timeout":
		_ = leaf.Wait()
		os.Exit(97)
	default:
		_ = leaf.Process.Kill()
		_ = leaf.Wait()
		os.Exit(98)
	}
}
