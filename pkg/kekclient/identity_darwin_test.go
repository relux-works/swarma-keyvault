//go:build darwin

package kekclient

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// processIdentity names a live or zombie process by pid, start time and
// command, so a test never mistakes a reused pid for its own fixture.
func processIdentity(pid int) (string, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp.Proc.P_pid != int32(pid) {
		return "", false
	}
	comm := kp.Proc.P_comm[:]
	for i, c := range comm {
		if c == 0 {
			comm = comm[:i]
			break
		}
	}
	return fmt.Sprintf("%d %d.%06d %s", pid, kp.Proc.P_starttime.Sec, kp.Proc.P_starttime.Usec, comm), true
}
