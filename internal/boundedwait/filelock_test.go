package boundedwait

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Claim: a closed descriptor returns its error without waiting for the context deadline.
func TestLockFileReportsDescriptorError(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := LockFile(ctx, f); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("descriptor error must refuse immediately: %v", err)
	}
}

// Claim: a done context takes a free lock immediately and refuses contention without taking the held lock.
func TestLockFileDoneContext(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := LockFile(ctx, f); err != nil {
		t.Fatal("free lock refused under a done context", err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	start := time.Now()
	if err := LockFile(ctx, other); !errors.Is(err, context.Canceled) {
		t.Fatal("held lock taken or wrong refusal under a done context", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatal("done context waited", elapsed)
	}
	f.Close()
	if err := LockFile(context.Background(), other); err != nil {
		t.Fatal("lock not free after the holder closed", err)
	}
}

// Claim: a free lock succeeds on the first attempt or after two interruptions, even under a done context.
func TestLockFileRetriesInterruptedAttempt(t *testing.T) {
	t.Parallel()
	for _, interruptions := range []int{0, 2} {
		calls := 0
		flock := func(fd int, how int) error {
			calls++
			if calls <= interruptions {
				return syscall.EINTR
			}
			return syscall.Flock(fd, how)
		}
		f, err := os.CreateTemp(t.TempDir(), "lock")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := lockFile(ctx, f, flock); err != nil || calls != interruptions+1 {
			t.Fatal("free lock not taken at first successful attempt", interruptions, calls, err)
		}
		// The lock is really held: another descriptor cannot take it.
		other, err := os.OpenFile(f.Name(), os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatal("lock not held after an interrupted retry", interruptions, err)
		}
		other.Close()
	}
}

// Claim: consecutive interruptions return EINTR at the fixed attempt bound with either a live or a done context.
func TestLockFileBoundsInterruptedAttempts(t *testing.T) {
	t.Parallel()
	for _, done := range []bool{false, true} {
		calls := 0
		sentinel := errors.New("attempt after interruption bound")
		flock := func(int, int) error {
			calls++
			if calls > maxConsecutiveInterrupts {
				return sentinel // An unbounded retry fails observably without hanging.
			}
			return syscall.EINTR
		}
		f, err := os.CreateTemp(t.TempDir(), "lock")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		if done {
			cancel()
		}
		err = lockFile(ctx, f, flock)
		cancel()
		if !errors.Is(err, syscall.EINTR) || calls != maxConsecutiveInterrupts {
			t.Fatalf("interruption bound violated: done=%v calls=%d want=%d err=%v", done, calls, maxConsecutiveInterrupts, err)
		}
	}
}

// Claim: contention resets the consecutive interruption count, so two shorter interruption runs still acquire a free lock.
func TestLockFileResetsInterruptedAttempts(t *testing.T) {
	t.Parallel()
	calls := 0
	flock := func(fd int, how int) error {
		calls++
		switch calls {
		case maxConsecutiveInterrupts:
			return syscall.EWOULDBLOCK
		case 2 * maxConsecutiveInterrupts:
			return syscall.Flock(fd, how)
		default:
			return syscall.EINTR
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := lockFile(context.Background(), f, flock); err != nil || calls != 2*maxConsecutiveInterrupts {
		t.Fatal("interruption count not reset after contention", calls, err)
	}
}
