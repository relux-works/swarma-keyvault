package boundedwait

import (
	"context"
	"errors"
	"os"
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
