//go:build darwin || linux

package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"golang.org/x/sys/unix"
)

func storageFixture(t *testing.T) (string, Sidecar, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support"), 0700); err != nil {
		t.Fatal(err)
	}
	sidecar := Sidecar{Binding: fixtureBinding(), NostrAccount: "fixture/nostr@2", GroupID: [16]byte{1}, NostrPublicPin: [32]byte{8}, MetadataHash: sha256.Sum256([]byte("public metadata")), PairedValueHash: sha256.Sum256([]byte("public opaque ciphertext fixture"))}
	locator, err := Locator(sidecar.Binding)
	if err != nil {
		t.Fatal(err)
	}
	return home, sidecar, filepath.Join(home, "Library", "Application Support", "mac-keyvault", "namecoin-journal", "v1", locator)
}
func createStorageFixture(t *testing.T, home string, sidecar Sidecar) *Storage {
	t.Helper()
	s, err := openStorageAt(home, sidecar, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Actual disposable files survive close/reopen with exact frame/result bytes,
// while the protected authority exists only in this public-fixture test anchor.
// No Keychain durability, biometric authorization or private signing is claimed.
func TestStorageDurabilityAndProtectedReplay(t *testing.T) {
	home, sidecar, root := storageFixture(t)
	s := createStorageFixture(t, home, sidecar)
	a := fixtureAnchor(t)
	l, err := a.RestoreLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := AttemptID{1}
	descriptor := []byte("exact public request/selection fixture")
	commitment := sha256.Sum256(descriptor)
	if err = s.PutDescriptor(id, descriptor); err != nil {
		t.Fatal(err)
	}
	tr, err := l.DispatchBound(id, []Outpoint{fixtureInput()}, commitment)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := a.Append(tr.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Append(frame); err != nil {
		t.Fatal(err)
	}
	result := []byte("exact complete public result fixture\n")
	if err = s.PutResult(id, result); err != nil {
		t.Fatal(err)
	}
	tr, err = tr.Ledger.Complete(id, result)
	if err != nil {
		t.Fatal(err)
	}
	frame, err = a.Append(tr.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Append(frame); err != nil {
		t.Fatal(err)
	}
	for _, link := range s.links {
		flags, e := unix.FcntlInt(uintptr(link.fd), unix.F_GETFD, 0)
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("directory inherited")
		}
	}
	f, err := s.openFile("records", unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	_ = f.Close()
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("file inherited", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStorageAt(home, sidecar, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	records, err := s.Records()
	if err != nil || len(records) != 2 {
		t.Fatal("physical history", err)
	}
	l, err = a.RestoreLedger(records)
	if err != nil {
		t.Fatal(err)
	}
	outcome, hash, err := l.Outcome(id)
	if err != nil || outcome != Signed || hash != sha256.Sum256(result) {
		t.Fatal("completion correlation", err)
	}
	if _, err = l.Dispatch(AttemptID{2}, []Outpoint{fixtureInput()}); !errors.Is(err, ErrReplay) {
		t.Fatal("restarted input not fenced", err)
	}
	got, err := s.Descriptor(id)
	if err != nil || !bytes.Equal(got, descriptor) {
		t.Fatal("descriptor", err)
	}
	got, err = s.Result(id)
	if err != nil || !bytes.Equal(got, result) {
		t.Fatal("result", err)
	}
	if err = s.PutResult(id, []byte("replacement")); !errors.Is(err, ErrUnknown) {
		t.Fatal("existing result overwritten", err)
	}
	got, err = s.Result(id)
	if err != nil || !bytes.Equal(got, result) {
		t.Fatal("failed replacement mutated result", err)
	}
	for _, entry := range []string{"sidecar", "records", cacheName("attempt", id), cacheName("result", id)} {
		info, e := os.Lstat(filepath.Join(root, entry))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private mode", entry, e)
		}
	}
}

// Existing non-writable ancestor forms remain compatible. Dedicated state is
// always0700; a failure observed by this handle cannot be silently repaired into
// a writable session, even when disposable fixture bytes later look valid.
func TestStorageAncestorCompatibilityAndStickyFailure(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0750, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			home, sidecar, root := storageFixture(t)
			for _, p := range []string{home, filepath.Join(home, "Library"), filepath.Join(home, "Library", "Application Support")} {
				if err := os.Chmod(p, mode); err != nil {
					t.Fatal(err)
				}
			}
			s := createStorageFixture(t, home, sidecar)
			if _, err := s.Records(); err != nil {
				t.Fatal("valid ancestor", err)
			}
			if err := os.WriteFile(filepath.Join(root, "records"), []byte("interrupted public record"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Records(); !errors.Is(err, ErrUnknown) {
				t.Fatal("damage not observed", err)
			}
			if err := os.WriteFile(filepath.Join(root, "records"), []byte(journalHeader), 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.PutResult(AttemptID{8}, []byte("forbidden retry")); !errors.Is(err, ErrUnknown) {
				t.Fatal("damaged handle reactivated", err)
			}
			if _, err := os.Lstat(filepath.Join(root, cacheName("result", AttemptID{8}))); !os.IsNotExist(err) {
				t.Fatal("retry wrote result", err)
			}
		})
	}
	for _, mode := range []os.FileMode{0770, 0777, 0500} {
		t.Run("reject-"+mode.String(), func(t *testing.T) {
			home, sidecar, root := storageFixture(t)
			if err := os.Chmod(filepath.Join(home, "Library"), mode); err != nil {
				t.Fatal(err)
			}
			// Restore only this disposable permission plant before TempDir cleanup;
			// the product path itself performs no permission repair.
			t.Cleanup(func() {
				if err := os.Chmod(filepath.Join(home, "Library"), 0700); err != nil {
					t.Error(err)
				}
			})
			if _, err := openStorageAt(home, sidecar, true); !errors.Is(err, ErrUnknown) {
				t.Fatal("unsafe ancestor admitted", err)
			}
			if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
				t.Fatal("unsafe ancestor created state", err)
			}
		})
	}
}

// The actual fixed kernel gate excludes a second Store before it can create
// filesystem state; closing the owner admits the same ordinary load again.
func TestStorageOwnsGateBeforeStateRead(t *testing.T) {
	home, sidecar, _ := storageFixture(t)
	s := createStorageFixture(t, home, sidecar)
	other, otherSidecar, otherRoot := storageFixture(t)
	if _, err := openStorageAt(other, otherSidecar, true); !errors.Is(err, namecoinlocalgate.ErrAccountBusy) {
		t.Fatal("second storage gate", err)
	}
	if _, err := os.Lstat(filepath.Dir(otherRoot)); !os.IsNotExist(err) {
		t.Fatal("busy attempt created directories", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := openStorageAt(home, sidecar, false)
	if err != nil {
		t.Fatal("released gate", err)
	}
	_ = loaded.Close()
}

// Missing state, changed sidecar and interrupted records are fixed UNKNOWN;
// ordinary load never creates state and append never repairs/truncates a gap.
func TestStorageMissingMismatchAndPartialPersistence(t *testing.T) {
	t.Run("missing-load", func(t *testing.T) {
		home, sidecar, root := storageFixture(t)
		if _, err := openStorageAt(home, sidecar, false); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
			t.Fatal("load created state", err)
		}
	})
	for _, kind := range []string{"partial-record", "partial-prefix", "sidecar", "missing-records", "missing-sidecar"} {
		t.Run(kind, func(t *testing.T) {
			home, sidecar, root := storageFixture(t)
			s := createStorageFixture(t, home, sidecar)
			if kind == "partial-record" || kind == "partial-prefix" {
				raw := append([]byte(journalHeader), 0, 0, 0, 60, 1, 2)
				if kind == "partial-prefix" {
					raw = append([]byte(journalHeader), 0, 0)
				}
				if err := os.WriteFile(filepath.Join(root, "records"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Records(); !errors.Is(err, ErrUnknown) {
					t.Fatal("partial record accepted", err)
				}
				if err := s.Append([]byte("invalid")); !errors.Is(err, ErrUnknown) {
					t.Fatal("partial record repaired", err)
				}
				after, err := os.ReadFile(filepath.Join(root, "records"))
				if err != nil || !bytes.Equal(after, raw) {
					t.Fatal("partial evidence lost", err)
				}
			} else if kind == "sidecar" {
				if err := os.WriteFile(filepath.Join(root, "sidecar"), []byte("wrong sidecar"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(filepath.Join(root, kind[len("missing-"):])); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := openStorageAt(home, sidecar, false); !errors.Is(err, ErrUnknown) {
				t.Fatal("invalid persisted state loaded", err)
			}
			if _, err := openStorageAt(home, sidecar, true); !errors.Is(err, ErrUnknown) {
				t.Fatal("partial state recreated", err)
			}
		})
	}
}

// These bounded plants use only disposable public files. Each intended
// symlink/hardlink/FIFO/permission/root-replacement refusal has a valid initial
// read, refuses without repair, and preserves the planted evidence.
func TestStorageFilesystemBoundaryRefusals(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "file-mode", "directory-mode", "root-replacement", "ancestor-replacement"} {
		t.Run(kind, func(t *testing.T) {
			home, sidecar, root := storageFixture(t)
			s := createStorageFixture(t, home, sidecar)
			if _, err := s.Records(); err != nil {
				t.Fatal("positive control", err)
			}
			records := filepath.Join(root, "records")
			switch kind {
			case "symlink":
				if err := os.Rename(records, records+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(records+"-original", records); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(records, records+"-alias"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(records); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(records, 0600); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(records, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(root, 0755); err != nil {
					t.Fatal(err)
				}
			case "root-replacement":
				if err := os.Rename(root, root+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "ancestor-replacement":
				parent := filepath.Dir(root)
				if err := os.Rename(parent, parent+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Records(); !errors.Is(err, ErrUnknown) {
				t.Fatal("filesystem plant not refused", kind, err)
			}
			if err := s.PutResult(AttemptID{9}, []byte("must not persist")); !errors.Is(err, ErrUnknown) {
				t.Fatal("write after filesystem plant", err)
			}
			// No mode repair or unlink/replacement API runs in Storage.
			if kind == "file-mode" {
				st, err := os.Lstat(records)
				if err != nil || st.Mode().Perm() != 0644 {
					t.Fatal("plant was repaired", err)
				}
			}
		})
	}
}

// Physical sequence/hash mismatches and oversized cache payloads refuse before
// writes; retained frames and results cannot be overwritten by the rejected call.
func TestStorageSequenceLimitsAndNoOverwrite(t *testing.T) {
	home, sidecar, root := storageFixture(t)
	s := createStorageFixture(t, home, sidecar)
	a := fixtureAnchor(t)
	l, err := a.RestoreLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := l.Dispatch(AttemptID{3}, []Outpoint{fixtureInput()})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := a.Append(tr.Body)
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Clone(frame)
	wrong[6+8] ^= 1
	if err = s.Append(wrong); !errors.Is(err, ErrUnknown) {
		t.Fatal("wrong predecessor", err)
	}
	if err = s.Append(frame); err != nil {
		t.Fatal("valid frame", err)
	}
	before, err := os.ReadFile(filepath.Join(root, "records"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Append(frame); !errors.Is(err, ErrUnknown) {
		t.Fatal("duplicate frame", err)
	}
	after, err := os.ReadFile(filepath.Join(root, "records"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected frame changed journal", err)
	}
	if err = s.PutResult(AttemptID{4}, make([]byte, (8<<20)+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized result", err)
	}
	if _, err = os.Lstat(filepath.Join(root, cacheName("result", AttemptID{4}))); !os.IsNotExist(err) {
		t.Fatal("oversized result left file", err)
	}
	if err = s.PutDescriptor(AttemptID{4}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty descriptor", err)
	}
	if err = s.PutDescriptor(AttemptID{4}, []byte("public descriptor")); err != nil {
		t.Fatal(err)
	}
	if err = s.PutDescriptor(AttemptID{4}, []byte("changed descriptor")); !errors.Is(err, ErrUnknown) {
		t.Fatal("descriptor overwritten", err)
	}
}
