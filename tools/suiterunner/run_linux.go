//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const cleanupBudget = 5 * time.Second

type completion struct {
	err error
	at  time.Time
}

func run(parent context.Context, timeout time.Duration, args []string, in, out, diagnostic *os.File) result {
	return supervise(parent, timeout, args, in, out, diagnostic, drain)
}

func supervise(parent context.Context, timeout time.Duration, args []string, in, out, diagnostic *os.File, cleanup func(time.Time) error) result {
	return superviseWithSetup(parent, timeout, args, in, out, diagnostic, func() error { return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, cleanup)
}

func superviseWithSetup(parent context.Context, timeout time.Duration, args []string, in, out, diagnostic *os.File, setup func() error, cleanup func(time.Time) error) result {
	return superviseWithMaintenance(parent, timeout, args, in, out, diagnostic, setup, cleanup, reapExitedChildren)
}

func superviseWithMaintenance(parent context.Context, timeout time.Duration, args []string, in, out, diagnostic *os.File, setup func() error, cleanup func(time.Time) error, maintain func(context.Context, int) error) result {
	return superviseWithOwnership(parent, timeout, args, in, out, diagnostic, setup, cleanup, maintain, directChildren)
}

func superviseWithOwnership(parent context.Context, timeout time.Duration, args []string, in, out, diagnostic *os.File, setup func() error, cleanup func(time.Time) error, maintain func(context.Context, int) error, enumerate func() (map[int]bool, error)) (r result) {
	r = result{Reason: "start-refused", Cause: "start-refused", ExitCode: 127, RootExit: -1}
	defer func() { r.observeSignals(parent); r.observe(r.Cause); r.observe(r.Reason) }()
	// This executable starts exactly one root and owns no unrelated children.
	// Subreaping keeps orphaned grandchildren in that custody after root death,
	// including children whose process groups differ from the root's group.
	if setup() != nil {
		r.Reason, r.ExitCode = "subreaper-refused", 125
		r.Cause = r.Reason
		return r
	}
	if _, err := enumerate(); err != nil {
		r.Reason, r.Cause, r.ExitCode = "ownership-refused", "ownership-refused", 125
		return r
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if parent.Err() != nil {
		r.Reason, r.ExitCode, r.Reaped = "canceled", 130, true
		r.Cause = r.Reason
		return r
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, diagnostic
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := ctx.Err(); err != nil {
		r.Reason, r.ExitCode, r.Reaped = "canceled", 130, true
		if errors.Is(err, context.DeadlineExceeded) {
			r.Reason, r.ExitCode = "deadline", 124
		}
		r.Cause = r.Reason
		r.ElapsedNS = time.Since(started).Nanoseconds()
		return r
	}
	if err := cmd.Start(); err != nil {
		until := time.Now().Add(cleanupBudget)
		r.Reaped = cleanup(until) == nil && time.Now().Before(until)
		if !r.Reaped {
			r.Reason, r.ExitCode = "cleanup-refused", 125
		}
		r.ElapsedNS = time.Since(started).Nanoseconds()
		return r
	}
	done := make(chan completion, 1)
	go func() { err := cmd.Wait(); done <- completion{err, time.Now()} }()
	var finished completion
	cleanupUntil := time.Time{}
	activeRefused := false
	observe := func() {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || (!finished.at.IsZero() && finished.at.Sub(started) >= timeout) {
			r.observe("deadline")
		}
		if parent.Err() != nil {
			r.observe("canceled")
		}
		r.observeSignals(parent)
		if !finished.at.IsZero() {
			if finished.err != nil {
				r.observe("exit")
			} else {
				r.observe("success")
			}
		}
	}
	freeze := func() {
		observe()
		r.Cause = primaryCause(r.ObservedCauses)
	}
	// This same goroutine owns maintenance and final draining. It never waits
	// for the root: only cmd.Wait above owns that exact process's status.
	maintenance := time.NewTicker(25 * time.Millisecond)
	defer maintenance.Stop()
waiting:
	for {
		select {
		case finished = <-done:
			freeze()
			break waiting
		case <-ctx.Done():
			freeze()
			break waiting
		case <-maintenance.C:
			if ctx.Err() != nil {
				freeze()
				break waiting
			}
			if maintain(ctx, cmd.Process.Pid) != nil {
				// Preserve a root/deadline/signal already observed at this
				// transition. Otherwise this refusal initiates shutdown.
				select {
				case finished = <-done:
				default:
				}
				r.observe("active-reap-refused")
				freeze()
				activeRefused = true
				break waiting
			}
		}
	}
	// No maintenance owner remains active across the root/final transition.
	cleanupUntil = time.Now().Add(cleanupBudget)
	maintenance.Stop()
	if finished.at.IsZero() {
		_ = cmd.Process.Kill() // Exact owned root; Wait below has one owner.
		select {
		case finished = <-done:
		case <-time.After(time.Until(cleanupUntil)):
			r.Reason, r.ExitCode = "cleanup-refused", 125
			observe()
			r.ElapsedNS = time.Since(started).Nanoseconds()
			return r
		}
	}
	r.RootExit = 0
	if finished.err != nil {
		r.RootExit = -1
		var exit *exec.ExitError
		if errors.As(finished.err, &exit) {
			r.RootExit = exit.ExitCode()
		}
	}
	observe() // Retain later root/signal/deadline observations without relabeling the frozen cause.
	r.Reason = r.Cause
	switch r.Cause {
	case "deadline":
		r.Reason, r.ExitCode = "deadline", 124
	case "canceled":
		r.Reason, r.ExitCode = "canceled", 130
	case "exit":
		r.Reason, r.ExitCode = "exit", r.RootExit
		if r.ExitCode < 1 {
			r.ExitCode = 1
		}
	case "active-reap-refused":
		r.Reason, r.ExitCode = "active-reap-refused", 125
	default:
		r.Reason, r.ExitCode = "success", 0
	}
	if activeRefused {
		r.Reason, r.ExitCode = "active-reap-refused", 125
	}
	// The root's exec.Cmd.Wait is finished before wait4(-1) can reap an orphan.
	// No other wait loop competes for this process's sole command tree.
	r.Reaped = cleanup(cleanupUntil) == nil && time.Now().Before(cleanupUntil)
	if !r.Reaped {
		r.Reason, r.ExitCode = "cleanup-refused", 125
	}
	observe()
	r.ElapsedNS = time.Since(started).Nanoseconds()
	return r
}

// Reap only exited adopted children while the root remains alive. A live
// adopted daemon is left alone, and per-child ECHILD never proves tree absence.
func reapExitedChildren(ctx context.Context, root int) error {
	return reapExitedChildrenWith(ctx, root, directChildren, unix.Wait4)
}

type childWait func(int, *unix.WaitStatus, int, *unix.Rusage) (int, error)

func reapExitedChildrenWith(ctx context.Context, root int, enumerate func() (map[int]bool, error), wait childWait) error {
	children, err := enumerate()
	if err != nil {
		return err
	}
	for child := range children {
		if child == root {
			continue
		}
		for {
			if ctx.Err() != nil {
				return nil
			}
			var status unix.WaitStatus
			pid, err := wait(child, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ECHILD) {
				fresh, refreshErr := enumerate()
				if refreshErr != nil {
					return refreshErr
				}
				if fresh[child] {
					return errors.New("contradictory owned-child wait")
				}
				break // A refreshed no-longer-owned witness is not whole-tree absence.
			}
			if err != nil {
				return err
			}
			if pid != 0 && (pid != child || (!status.Exited() && !status.Signaled())) {
				return errors.New("unexpected adopted-child wait status")
			}
			break
		}
	}
	return nil
}

func drain(until time.Time) error {
	return drainWithOperations(until, directChildren, unix.Wait4, unix.Kill)
}

func drainWithOperations(until time.Time, enumerate func() (map[int]bool, error), wait childWait, kill func(int, syscall.Signal) error) error {
	for {
		if !time.Now().Before(until) {
			return context.DeadlineExceeded
		}
		// Even ECHILD is accepted only with a working ownership enumerator.
		if _, err := enumerate(); err != nil {
			return err
		}
		for {
			if !time.Now().Before(until) {
				return context.DeadlineExceeded
			}
			var status unix.WaitStatus
			pid, err := wait(-1, &status, unix.WNOHANG, nil)
			if !time.Now().Before(until) {
				return context.DeadlineExceeded
			}
			if errors.Is(err, unix.ECHILD) {
				return nil
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return err
			}
			if pid == 0 {
				break
			}
		}
		if !time.Now().Before(until) {
			return context.DeadlineExceeded
		}
		// Refresh after the last wait: never kill from a reaped PID snapshot.
		children, err := enumerate()
		if err != nil {
			return err
		}
		for pid := range children {
			if !time.Now().Before(until) {
				return context.DeadlineExceeded
			}
			if err := kill(pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func directChildren() (map[int]bool, error) {
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil, err
	}
	children := make(map[int]bool)
	for _, thread := range threads {
		if !thread.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc/self/task", thread.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) { // A runtime thread may exit mid-read.
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, word := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(word)
			if err != nil || pid <= 1 || pid == os.Getpid() {
				return nil, errors.New("invalid direct-child witness")
			}
			children[pid] = true
		}
	}
	return children, nil
}
