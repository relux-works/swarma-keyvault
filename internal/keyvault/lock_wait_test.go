package keyvault

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The holder is released after 800ms even in a planted blocking-flock build:
// failure must be the acquisition/deadline predicate, not a suite timeout.
func TestFileLockDeadlineAndRecovery(t *testing.T) {
	lock := FileLock{Path: filepath.Join(t.TempDir(), "lock")}
	release, err := lock.Lock()
	if err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(800*time.Millisecond, release)
	defer func() {
		if timer.Stop() {
			release()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	second, err := lock.LockContext(ctx)
	if second != nil {
		second()
	}
	if !errors.Is(err, context.DeadlineExceeded) || second != nil {
		t.Fatalf("lock deadline predicate: release present=%t, err=%v", second != nil, err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("lock deadline exceeded bound: %v", elapsed)
	}
	if timer.Stop() {
		release()
	}
	second, err = lock.Lock()
	if err != nil {
		t.Fatalf("recovery after refusal: %v", err)
	}
	second()
	ctx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if release, err := lock.LockContext(ctx); !errors.Is(err, context.Canceled) || release != nil {
		if release != nil {
			release()
		}
		t.Fatalf("canceled uncontended lock acquired: %v", err)
	}
}
