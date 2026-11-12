//go:build darwin || linux

package namecoinjournal

import (
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

// Actual disposable fd-relative checks accept missing dedicated prefixes or a
// missing selected locator, and create nothing. Existing objects, unsafe prefix
// modes, symlinks and missing required ancestors refuse and cannot revive the
// held reservation. No native item, secret, owner-home or biometric is involved.
func TestInitializationPublicAbsence(t *testing.T) {
	for _, mode := range []string{"absent-prefix", "absent-locator", "selected-directory", "selected-file", "selected-symlink", "partial-state", "prefix-file", "prefix-symlink", "unsafe-prefix", "missing-library", "unsafe-home"} {
		t.Run(mode, func(t *testing.T) {
			home, sidecar, root := storageFixture(t)
			parent := filepath.Dir(root)
			if mode != "absent-prefix" && mode != "missing-library" && mode != "unsafe-home" {
				if err := os.MkdirAll(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "selected-directory":
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "selected-file":
				if err := os.WriteFile(root, []byte("existing public object"), 0600); err != nil {
					t.Fatal(err)
				}
			case "selected-symlink":
				if err := os.Symlink(parent, root); err != nil {
					t.Fatal(err)
				}
			case "partial-state":
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "sidecar"), []byte("incomplete"), 0600); err != nil {
					t.Fatal(err)
				}
			case "prefix-file", "prefix-symlink":
				target := filepath.Join(home, "Library", "Application Support", "mac-keyvault")
				if err := os.Rename(target, target+"-preserved"); err != nil {
					t.Fatal(err)
				}
				if mode == "prefix-file" {
					if err := os.WriteFile(target, []byte("file"), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Symlink(target+"-preserved", target); err != nil {
						t.Fatal(err)
					}
				}
			case "unsafe-prefix":
				target := filepath.Join(home, "Library", "Application Support", "mac-keyvault")
				if err := os.Chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
				st, e := os.Stat(target)
				if e != nil || st.Mode().Perm() != 0755 {
					t.Fatal("mode plant absent")
				}
			case "missing-library":
				if err := os.Rename(filepath.Join(home, "Library"), filepath.Join(home, "Library-preserved")); err != nil {
					t.Fatal(err)
				}
			case "unsafe-home":
				if err := os.Chmod(home, 0777); err != nil {
					t.Fatal(err)
				}
				st, e := os.Stat(home)
				if e != nil || st.Mode().Perm() != 0777 {
					t.Fatal("mode plant absent")
				}
			}
			r, err := reserveInitializationAt(home, sidecar)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			err = r.CheckPublicAbsent()
			valid := mode == "absent-prefix" || mode == "absent-locator"
			if valid {
				if err != nil {
					t.Fatal("valid absence refused", err)
				}
				if again := r.CheckPublicAbsent(); again != nil {
					t.Fatal("read-only repeat refused", again)
				}
				if _, e := os.Lstat(root); !os.IsNotExist(e) {
					t.Fatal("absence check wrote selected state")
				}
				if mode == "absent-prefix" {
					if _, e := os.Lstat(filepath.Join(home, "Library", "Application Support", "mac-keyvault")); !os.IsNotExist(e) {
						t.Fatal("check created prefix")
					}
				}
			} else {
				if !errors.Is(err, ErrUnknown) {
					t.Fatal("expected exact public-state refusal", err)
				}
				// The failed check consumes the reservation even if the obstacle changes.
				if mode == "selected-file" {
					if err := os.Remove(root); err != nil {
						t.Fatal(err)
					}
				}
				if !errors.Is(r.CheckPublicAbsent(), ErrUnknown) {
					t.Fatal("failed reservation revived")
				}
				if s, e := r.CreatePublicState(); s != nil || !errors.Is(e, ErrUnknown) {
					t.Fatal("failed check reached create")
				}
			}
			if g, e := namecoinlocalgate.Acquire(); g != nil || !errors.Is(e, namecoinlocalgate.ErrAccountBusy) {
				if g != nil {
					g.Close()
				}
				t.Fatal("check released actual gate")
			}
			if r.Close() != nil {
				t.Fatal("close")
			}
		})
	}
}

// The actual production ancestry predicate detects a renamed/replaced directory
// with its old descriptor still held. The wrong-UID case tests the real owner
// predicate without changing any OS account or fixture ownership.
func TestInitializationPublicAbsenceAncestryWitness(t *testing.T) {
	home, _, _ := storageFixture(t)
	fd, e := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	links := []directoryLink{{parent: -1, name: home, fd: fd}}
	if !initializationPrefixValid(links, uint32(os.Getuid())) {
		t.Fatal("valid actual prefix refused")
	}
	if initializationPrefixValid(links, uint32(os.Getuid())+1) {
		t.Fatal("foreign owner predicate accepted")
	}
	if err := os.Rename(home, home+"-old"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(home); os.Rename(home+"-old", home) })
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if initializationPrefixValid(links, uint32(os.Getuid())) {
		t.Fatal("replaced prefix admitted")
	}
}
