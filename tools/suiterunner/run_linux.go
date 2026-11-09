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
	r := result{Reason: "start-refused", Cause: "start-refused", ExitCode: 127, RootExit: -1}
	// This executable starts exactly one root and owns no unrelated children.
	// Subreaping keeps orphaned grandchildren in that custody after root death,
	// including children whose process groups differ from the root's group.
	if setup() != nil {
		r.Reason, r.ExitCode = "subreaper-refused", 125
		r.Cause = r.Reason
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
		r.Reaped = cleanup(time.Now().Add(cleanupBudget)) == nil
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
	select {
	case finished = <-done:
		// Freeze the primary observed trigger when cleanup begins. Root status
		// remains separate even if deadline/signal observations coincide here.
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded) || finished.at.Sub(started) >= timeout:
			r.Cause = "deadline"
		case parent.Err() != nil:
			r.Cause = "canceled"
		case finished.err != nil:
			r.Cause = "exit"
		default:
			r.Cause = "success"
		}
		cleanupUntil = time.Now().Add(cleanupBudget)
	case <-ctx.Done():
		cleanupUntil = time.Now().Add(cleanupBudget)
		r.Cause = "canceled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			r.Cause = "deadline"
		}
		_ = cmd.Process.Kill() // Exact owned root; Wait below has one owner.
		select {
		case finished = <-done:
		case <-time.After(time.Until(cleanupUntil)):
			r.Reason, r.ExitCode = "cleanup-refused", 125
			r.ElapsedNS = time.Since(started).Nanoseconds()
			return r
		}
	}
	if cleanupUntil.IsZero() {
		cleanupUntil = time.Now().Add(cleanupBudget)
	}
	r.RootExit = 0
	if finished.err != nil {
		r.RootExit = -1
		var exit *exec.ExitError
		if errors.As(finished.err, &exit) {
			r.RootExit = exit.ExitCode()
		}
	}
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
	default:
		r.Reason, r.ExitCode = "success", 0
	}
	// The root's exec.Cmd.Wait is finished before wait4(-1) can reap an orphan.
	// No other wait loop competes for this process's sole command tree.
	r.Reaped = cleanup(cleanupUntil) == nil
	if !r.Reaped {
		r.Reason, r.ExitCode = "cleanup-refused", 125
	}
	r.ElapsedNS = time.Since(started).Nanoseconds()
	return r
}

func drain(until time.Time) error {
	for {
		if time.Now().After(until) {
			return context.DeadlineExceeded
		}
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
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
		if time.Now().After(until) {
			return context.DeadlineExceeded
		}
		children, err := directChildren()
		if err != nil {
			return err
		}
		for pid := range children {
			// Only unreaped direct children of this dedicated process are used.
			// They cannot have their PID reused before our own next wait4 call.
			if err := unix.Kill(pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
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
