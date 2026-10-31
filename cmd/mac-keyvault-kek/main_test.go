package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o700)
	return dir
}

// The socket must be a new, clean, absolute, short path in a private
// directory of this user; every other shape is refused. A fresh name in a
// 0700 directory is accepted (control).
func TestCheckSocketPath(t *testing.T) {
	dir := privateTemp(t)
	if err := checkSocketPath(filepath.Join(dir, "s.sock")); err != nil {
		t.Fatalf("control: %v", err)
	}
	open := privateTemp(t)
	os.Chmod(open, 0o755)
	existing := filepath.Join(dir, "taken")
	os.WriteFile(existing, nil, 0o600)
	link := filepath.Join(privateTemp(t), "l")
	os.Symlink(dir, link)
	bad := map[string]string{
		"relative":       "run/s.sock",
		"unclean":        dir + "/../" + filepath.Base(dir) + "/s.sock",
		"exists":         existing,
		"open directory": filepath.Join(open, "s.sock"),
		"symlinked dir":  filepath.Join(link, "s.sock"),
		"missing dir":    filepath.Join(dir, "none", "s.sock"),
		"too long":       filepath.Join(dir, strings.Repeat("x", 110)),
	}
	for name, path := range bad {
		if err := checkSocketPath(path); err == nil {
			t.Fatalf("%s: %s accepted", name, path)
		}
	}
}

// Usage errors exit 2 before anything is opened: no command, an unknown
// command, a malformed address, a missing or unsafe socket, extra
// arguments. They never reach the Keychain: disableUI and the vault are
// replaced by failing stand-ins that would turn the exit into 1.
func TestUsageErrorsExitTwoBeforeTheVault(t *testing.T) {
	saved := host
	t.Cleanup(func() { host = saved })
	host.disableUI = func() error { t.Fatal("reached the Keychain"); return nil }
	cases := [][]string{
		nil,
		{"export"},
		{"create"},
		{"create", "--address", "Network/Store"},
		{"pub", "--address", "a/b/c"},
		{"unwrap", "--address", "network-proxy/store-kek"},
		{"unwrap", "--address", "network-proxy/store-kek", "--socket", "relative.sock"},
		{"rebind", "--address", "network-proxy/store-kek", "--socket", "/tmp"},
		{"pub", "--address", "network-proxy/store-kek", "extra"},
		{"create", "--address", "network-proxy/store-kek", "--not-after", "tomorrow"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 || out.Len() != 0 {
			t.Fatalf("%q: exit %d, stdout %q, stderr %q", args, code, out.String(), errOut.String())
		}
	}
}
