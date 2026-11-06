// Package sockettest gives tests short directories for Unix domain sockets.
//
// Darwin limits a socket path to 104 bytes including the terminating NUL, and
// testing.T.TempDir includes the full test name, so socket tests need a short
// base. The base is the process temporary directory when a socket path below it
// fits, so a run with a private TMPDIR stays inside its own writable area; /tmp
// is used only when the temporary directory is too long or not absolute.
package sockettest

import (
	"os"
	"path/filepath"
	"testing"
)

// MaxPath is the longest socket path accepted on every supported platform.
const MaxPath = 103

// Reserve is the room kept below the base for a directory name (a prefix of up
// to 12 bytes and a random suffix of up to 10 digits) and a relative socket
// path of up to 24 bytes, such as "private/agent.sock".
const Reserve = 48

// Fallback is the base used when the temporary directory is unsuitable.
const Fallback = "/tmp"

// Base returns tmp when a socket path below it fits MaxPath, and Fallback
// otherwise.
func Base(tmp string) string {
	if tmp != "" && filepath.IsAbs(tmp) && len(tmp)+Reserve <= MaxPath {
		return tmp
	}
	return Fallback
}

// Dir creates a fresh directory below Base(os.TempDir()) and removes it when
// the test ends.
func Dir(t testing.TB, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp(Base(os.TempDir()), prefix)
	if err != nil {
		t.Fatalf("socket temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
