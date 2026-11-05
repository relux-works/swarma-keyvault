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

// LockFile takes an exclusive flock, retrying contention and interrupted calls
// while ctx is live, for at most LockWait. The caller owns and closes f,
// including on failure; closing a successfully locked descriptor releases it.
func LockFile(ctx context.Context, f *os.File) error {
	ctx, cancel := context.WithTimeout(ctx, LockWait)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
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
