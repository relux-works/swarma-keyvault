// Package boundedwait contains the bounded file-lock wait shared by keyvault
// and its audit log. It does not change lock ownership or file contents.
package boundedwait

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// LockWait caps contention; a caller's earlier deadline wins. Expiry refuses
// without stealing the lock from a live holder.
const LockWait = 45 * time.Second

// flock is syscall.Flock; tests replace it to interrupt an attempt.
var flock = syscall.Flock

// LockFile takes an exclusive flock, retrying contention and interrupted calls
// while ctx is live, for at most LockWait. A done ctx bounds only waiting: an
// uncontended lock is still taken by the first attempt, so a refusal reached
// at its deadline can still be written to an audit log. The caller owns and
// closes f, including on failure; closing a successfully locked descriptor
// releases it.
func LockFile(ctx context.Context, f *os.File) error {
	ctx, cancel := context.WithTimeout(ctx, LockWait)
	defer cancel()
	for {
		err := flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		// An interrupted attempt is not contention: retry it at once, also
		// under a done ctx, so a free lock is still taken.
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
