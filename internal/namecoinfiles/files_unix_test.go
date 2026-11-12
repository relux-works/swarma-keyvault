//go:build darwin || linux

package namecoinfiles

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func privateFixture(t *testing.T) (string, string) {
	t.Helper()
	// Use the OS account home: writable ancestors such as /tmp are deliberately
	// refused by the production reader. Only this new directory is mutated.
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	owned, err := os.MkdirTemp(account.HomeDir, ".namecoin-files-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(owned); err != nil {
			t.Error(err)
		}
	})
	base, err := filepath.EvalSymlinks(owned)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "request.json")
	if err = os.WriteFile(path, []byte("public request fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	return base, path
}

// Real files under safe0700/0750/0755 owner directories pass; private owned
// snapshots stay unchanged after the input file is later edited. Max-size and
// empty-input rejection is paired with the same bounded valid input.
func TestPrivateInputSnapshotAndDirectoryCompatibility(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o750, 0o755} {
		base, path := privateFixture(t)
		if os.Chmod(base, mode) != nil {
			t.Fatal("fixture mode")
		}
		raw, err := ReadInput(path, 64)
		if err != nil || string(raw) != "public request fixture" {
			t.Fatal("valid input refused", err)
		}
		if os.WriteFile(path, []byte("changed public fixture"), 0o600) != nil {
			t.Fatal("fixture edit")
		}
		if string(raw) != "public request fixture" {
			t.Fatal("borrowed snapshot")
		}
		if _, err = ReadInput(path, 1); !errors.Is(err, ErrUnsafe) {
			t.Fatal("oversize admitted")
		}
		if os.WriteFile(path, nil, 0o600) != nil {
			t.Fatal("fixture empty")
		}
		if _, err = ReadInput(path, 64); !errors.Is(err, ErrUnsafe) {
			t.Fatal("empty admitted")
		}
	}
}

// Symlink/hardlink/FIFO/permissions and unsafe ancestors, including writable
// sticky directories, reject without modifying input or writing output. FIFO opens are nonblocking;
// all mutations are isolated disposable fixtures, never real user state.
func TestInputAndOutputFilesystemRefusals(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "mode", "ancestor", "sticky-ancestor", "relative", "traversal"} {
		t.Run(kind, func(t *testing.T) {
			base, path := privateFixture(t)
			if raw, err := ReadInput(path, 64); err != nil || string(raw) != "public request fixture" {
				t.Fatal("positive control refused", err)
			}
			selected := path
			switch kind {
			case "symlink":
				selected = filepath.Join(base, "alias")
				if os.Symlink(path, selected) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(base, "hard")) != nil {
					t.Fatal("fixture hardlink")
				}
			case "fifo":
				selected = filepath.Join(base, "fifo")
				if unix.Mkfifo(selected, 0o600) != nil {
					t.Fatal("fixture FIFO")
				}
			case "mode":
				if os.Chmod(path, 0o640) != nil {
					t.Fatal("fixture mode")
				}
			case "ancestor":
				if os.Chmod(base, 0o770) != nil {
					t.Fatal("fixture ancestor")
				}
			case "sticky-ancestor":
				if os.Chmod(base, os.ModeSticky|0o777) != nil {
					t.Fatal("fixture sticky ancestor")
				}
			case "relative":
				selected = "request.json"
			case "traversal":
				selected = base + "/../" + filepath.Base(base) + "/request.json"
			}
			if _, err := ReadInput(selected, 64); !errors.Is(err, ErrUnsafe) {
				t.Fatal("unsafe input admitted")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if output, err := CreateOutput(selected); !errors.Is(err, ErrUnsafe) || output != nil {
				t.Fatal("existing/unsafe output admitted")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal modified existing input")
			}
		})
	}
}

// A real exclusive output is0600/CLOEXEC, can be inherited via the owned file,
// and yields exact bounded public bytes without changing offset. An existing
// output is never truncated/replaced; Close releases only owned descriptors once.
func TestExclusiveOutputAndExactReadback(t *testing.T) {
	base, _ := privateFixture(t)
	path := filepath.Join(base, "result.json")
	output, err := CreateOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	file, err := output.FileForChild()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags != unix.FD_CLOEXEC {
		t.Fatal("descriptor leaks across exec")
	}
	expected := []byte("exact public result\n")
	if _, err = file.Write(expected); err != nil || file.Sync() != nil {
		t.Fatal("public fixture output")
	}
	before, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := output.ReadResult(64)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("readback", err)
	}
	after, err := file.Seek(0, 1)
	if err != nil || after != before {
		t.Fatal("parent changed shared offset")
	}
	if _, err = CreateOutput(path); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overwrote existing result")
	}
	if _, err = output.FileForChild(); !errors.Is(err, ErrUnsafe) {
		t.Fatal("nonempty reused as child output")
	}
	if _, err = output.ReadResult(1); !errors.Is(err, ErrUnsafe) {
		t.Fatal("result size bound")
	}
	if output.Close() != nil || output.Close() != nil {
		t.Fatal("close-once")
	}
	if _, err = output.ReadResult(64); !errors.Is(err, ErrUnsafe) {
		t.Fatal("read after close")
	}
	persisted, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(persisted, expected) {
		t.Fatal("close removed result")
	}
}

// Directory replacement, final-path substitution and new hardlinks cannot
// promote bytes through a stale held descriptor; a nonreplaced positive result
// is exercised above. Failure preserves files for explicit reconciliation.
func TestOutputRejectsChangedAncestryAndAliases(t *testing.T) {
	for _, kind := range []string{"directory", "file", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			base, _ := privateFixture(t)
			parent := filepath.Join(base, "held")
			if os.Mkdir(parent, 0o700) != nil {
				t.Fatal("fixture directory")
			}
			path := filepath.Join(parent, "result")
			output, err := CreateOutput(path)
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			file, err := output.FileForChild()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write([]byte("public bytes")); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				if os.Rename(parent, parent+"-old") != nil || os.Mkdir(parent, 0o700) != nil {
					t.Fatal("fixture replacement")
				}
			case "file":
				if os.Rename(path, path+"-old") != nil || os.WriteFile(path, []byte("replacement"), 0o600) != nil {
					t.Fatal("fixture file replacement")
				}
			case "hardlink":
				if os.Link(path, path+"-hard") != nil {
					t.Fatal("fixture link")
				}
			case "permissions":
				if os.Chmod(parent, 0o770) != nil {
					t.Fatal("fixture mode")
				}
			}
			if _, err = output.ReadResult(64); !errors.Is(err, ErrUnsafe) {
				t.Fatal("stale/unsafe output admitted")
			}
		})
	}
}
