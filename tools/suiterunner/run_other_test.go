//go:build !linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An unsupported host refuses without dispatch, rather than claiming a weaker
// process-group approximation provides Linux subreaper custody.
func TestUnsupportedHost(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	r := run(context.Background(), time.Second, []string{"touch", marker}, nil, nil, nil)
	if r.Reason != "unsupported" || r.ExitCode != 125 || r.Reaped {
		t.Fatal("unsupported platform did not refuse")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unsupported runner dispatched a command")
	}
}
