//go:build darwin || linux

package keyvault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The actual loader admits both enrolled permission forms and refuses links,
// special files, wide permissions, wrong addresses and noncanonical policy.
// All files are synthetic and task-local; no installed policy is opened.
func TestRootGrantsGrantV3AuthorityFile(t *testing.T) {
	f := grantV3FullFixture(t)
	raw := rootGrantsRaw13(t, f.p)
	address := RootGrantsAddress{Service: f.r.Service, Version: f.r.Version}
	dir := t.TempDir()
	path := filepath.Join(dir, "authority.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0600, 0400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		got, err := rootGrantsLoadAuthorityFile(path, address)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("legitimate mode %o refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0644, 0444, 0660, 0700, 0000} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		got, err := rootGrantsLoadAuthorityFile(path, address)
		rootGrantsWantRefusal(t, err, "operation_unavailable")
		if got != nil {
			t.Fatal("refused permissions returned policy")
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.json")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{link, fifo, dir, filepath.Join(dir, "missing")} {
		got, err := rootGrantsLoadAuthorityFile(name, address)
		rootGrantsWantRefusal(t, err, "operation_unavailable")
		if got != nil {
			t.Fatal("special path returned policy")
		}
	}
	got, err := rootGrantsLoadAuthorityFile(path, RootGrantsAddress{Service: address.Service, Version: address.Version + 1})
	rootGrantsWantRefusal(t, err, "authority_mismatch")
	if got != nil {
		t.Fatal("wrong generation returned policy")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(raw), '\n'), []byte(strings.Repeat(" ", 32769))} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := rootGrantsLoadAuthorityFile(path, address); err == nil || got != nil {
			t.Fatal("invalid policy file accepted")
		}
	}
}
