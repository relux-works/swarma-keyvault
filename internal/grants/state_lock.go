package grants

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// subprocessWaitDelay bounds how long Run waits for the child's stdout/stderr
// to close after the child exits or its context kills it. Without it, a
// descendant that inherited a pipe keeps Run blocked past the deadline.
const subprocessWaitDelay = time.Second

// stateLockWait bounds the wait for another holder of a grant state lock when
// the caller's context carries no earlier deadline. A holder keeps the lock
// through one provider call (30s) plus subprocessWaitDelay and journal writes,
// so the cap is set above that; it still fails closed if exceeded.
const stateLockWait = 45 * time.Second

// stateLockPoll is the retry interval while another process holds the lock.
const stateLockPoll = 5 * time.Millisecond

var errStateLockUnavailable = errors.New("grant state lock unavailable")

// lockStateFile takes an exclusive flock on f. It waits for another holder
// while ctx is live and at most stateLockWait, then refuses. It never takes a
// shared lock and never steals one; any other flock error refuses at once.
func lockStateFile(ctx context.Context, f *os.File) error {
	if ctx == nil || f == nil {
		return errStateLockUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, stateLockWait)
	defer cancel()
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return errStateLockUnavailable
		}
		timer := time.NewTimer(stateLockPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errStateLockUnavailable
		case <-timer.C:
		}
	}
}
