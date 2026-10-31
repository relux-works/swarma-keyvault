//go:build darwin

package kekclient

import (
	"time"

	"golang.org/x/sys/unix"
)

// zombie is SZOMB in <sys/proc.h>: the process has exited and waits to be
// reaped.
const zombie = 5

// awaitExit returns once pid has exited (it is then a zombie until Wait
// reaps it) or grace has passed. It never reaps.
func awaitExit(pid int, grace time.Duration) {
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || kp.Proc.P_pid != int32(pid) || kp.Proc.P_stat == zombie {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
