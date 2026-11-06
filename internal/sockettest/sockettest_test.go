package sockettest

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Claim: Base keeps an absolute temporary directory exactly up to the length
// that leaves Reserve bytes, and falls back to /tmp one byte past it, for a
// relative path and for an empty value.
func TestBaseBudget(t *testing.T) {
	fits := "/" + strings.Repeat("a", MaxPath-Reserve-1)
	over := fits + "b"
	for _, tc := range []struct {
		tmp, want string
	}{
		{"/tmp/private-run/tmp", "/tmp/private-run/tmp"},
		{fits, fits},
		{over, Fallback},
		{"relative/tmp", Fallback},
		{"", Fallback},
	} {
		if got := Base(tc.tmp); got != tc.want {
			t.Errorf("Base(%q) = %q, want %q", tc.tmp, got, tc.want)
		}
	}
}

// Claim: Dir creates a directory under Base(os.TempDir()) in which the longest
// reserved socket path fits MaxPath and a Unix socket can actually listen.
// Limit: it exercises the temporary directory of the current run only.
func TestDirHoldsReservedSocket(t *testing.T) {
	dir := Dir(t, "kv-sockettest")
	if got, want := filepath.Dir(dir), filepath.Clean(Base(os.TempDir())); got != want {
		t.Fatalf("dir %q is not below base %q", dir, want)
	}
	rel := strings.Repeat("s", Reserve-len("/kv-sockettest")-10-1)
	path := filepath.Join(dir, rel)
	if len(path) > MaxPath {
		t.Fatalf("reserved socket path is %d bytes: %s", len(path), path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

// Claim: on Darwin a Unix socket path one byte past MaxPath is refused, so the
// budget in Base is a real constraint. The positive control is
// TestDirHoldsReservedSocket. Limit: Linux accepts 107 bytes, so it is skipped
// there; the Darwin limit is the binding one.
func TestSocketPathPastLimitRefused(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the 104-byte limit is Darwin's")
	}
	dir := Dir(t, "kv-sockettest")
	path := filepath.Join(dir, strings.Repeat("s", MaxPath-len(dir)))
	if len(path) != MaxPath+1 {
		t.Fatalf("setup: path is %d bytes", len(path))
	}
	ln, err := net.Listen("unix", path)
	if err == nil {
		ln.Close()
		t.Fatalf("socket path of %d bytes was accepted", len(path))
	}
}
