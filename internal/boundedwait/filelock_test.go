package boundedwait

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockFileReportsDescriptorError(t *testing.T) {
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

// Claim: a done context bounds only waiting. With the lock free, the first
// attempt still takes it (so a deadline refusal can be audited); with the
// lock held by another descriptor, it refuses with the context error at once,
// without waiting and without taking the lock.
func TestLockFileDoneContext(t *testing.T) {
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
