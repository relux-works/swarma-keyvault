//go:build darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinInheritedFDHelper(t *testing.T) {
	if os.Getenv("LAB_FD_HELPER") != "1" {
		return
	}
	// A kqueue is a valid open descriptor whose fdescfs entry cannot be
	// stat'ed. Plant it explicitly rather than depending on lazy runtime
	// poller initialization to expose the ReadDir regression.
	kqueue, err := unix.Kqueue()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(kqueue)
	// ExtraFiles supplies a real inherited descriptor without CLOEXEC. Keep
	// another copy above a subsequently lowered limit, as the startup contract
	// promises to cover those too. Change only this isolated child process.
	high, err := unix.FcntlInt(3, unix.F_DUPFD, 256)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(high)
	var limits unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limits); err != nil {
		t.Fatal(err)
	}
	lowered := limits
	lowered.Cur = 128
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatal(err)
	}
	defer unix.Setrlimit(unix.RLIMIT_NOFILE, &limits)
	var standard [3]int
	for fd := range standard {
		standard[fd], err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := sanitizeInheritedFDs(); err != nil {
		t.Fatalf("actual fdescfs enumeration and marking: %v", err)
	}
	for _, fd := range []int{3, high, kqueue} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("inherited fd %d not retained and marked: flags=%d err=%v", fd, flags, err)
		}
	}
	for fd, before := range standard {
		after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || before != after {
			t.Fatalf("standard fd %d changed: before=%d after=%d err=%v", fd, before, after, err)
		}
	}
}

func TestDarwinInheritedFDEnumeration(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDarwinInheritedFDHelper$")
	cmd.Env = append(os.Environ(), "LAB_FD_HELPER=1")
	cmd.ExtraFiles = []*os.File{file}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("descriptor startup: %v\n%s", err, output)
	}
}
