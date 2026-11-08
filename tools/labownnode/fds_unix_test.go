//go:build linux || darwin

package main

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestInheritedFDMarkingFailuresAndReuse(t *testing.T) {
	for _, scenario := range []string{"mark", "already-marked", "closed-before-get", "closed-before-set", "get-error", "set-error"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			err := markInheritedFDs([]uintptr{0, 1, 2, 77, 4097}, func(fd uintptr, cmd, arg int) (int, error) {
				calls++
				if fd <= 2 {
					t.Fatal("standard stream touched")
				}
				if cmd == unix.F_GETFD {
					if scenario == "closed-before-get" {
						return 0, unix.EBADF
					}
					if scenario == "get-error" {
						return 0, unix.EIO
					}
					if scenario == "already-marked" {
						return unix.FD_CLOEXEC, nil
					}
					return 0, nil
				}
				if cmd != unix.F_SETFD || arg&unix.FD_CLOEXEC == 0 {
					t.Fatal("missing close-on-exec flag")
				}
				if scenario == "closed-before-set" {
					return 0, unix.EBADF
				}
				if scenario == "set-error" {
					return 0, unix.EPERM
				}
				return 0, nil
			})
			wantError := scenario == "get-error" || scenario == "set-error"
			if (err != nil) != wantError {
				t.Fatalf("error=%v want refusal=%v", err, wantError)
			}
			if calls == 0 {
				t.Fatal("no descriptors checked")
			}
		})
	}
}
