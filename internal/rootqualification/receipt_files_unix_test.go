//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The fixture starts at an actual isolated owned directory descriptor. It
// exercises the real file operations/checks; it does not qualify the host's
// complete OS-home ancestry, extended ACLs, native Keychain or item authority.
func receiptFixture(t *testing.T) (*receiptFiles, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	r := &receiptFiles{uid: uint32(os.Getuid()), links: []receiptLink{{fd: fd, parent: unix.AT_FDCWD, name: dir, stat: s}}}
	if r.check() != nil {
		t.Fatal("fixture descriptor mismatch")
	}
	t.Cleanup(func() { _ = r.close() })
	return r, dir
}
func receiptDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fileIdentity(t *testing.T, p string) unix.Stat_t {
	t.Helper()
	var s unix.Stat_t
	if err := unix.Lstat(p, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// A reservation persists across Close and process-style reopen; publishing
// preserves it and creates the complete file once. This proves only storage,
// not the still-separate completed receipt codec/native binding validation.
func TestReceiptReservePublishAndReopen(t *testing.T) {
	r, dir := receiptFixture(t)
	if err := r.reservePending(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, pendingName))
	if err != nil {
		t.Fatal(err)
	}
	b := []byte("public completed receipt fixture\n")
	if err := r.publish(createdName, b); err != nil {
		t.Fatal(err)
	}
	got, err := r.readCreatedPinned(receiptDigest(b))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("readback %v", err)
	}
	if got, err := r.readCreatedPinned(receiptDigest([]byte("other"))); !errors.Is(err, errReceiptFiles) || got != nil {
		t.Fatal("wrong digest returned bytes")
	}
	after, _ := os.ReadFile(filepath.Join(dir, pendingName))
	if !bytes.Equal(before, after) {
		t.Fatal("pending changed")
	}
	if err := r.publish(createdName, []byte("replacement")); !errors.Is(err, errReceiptFiles) {
		t.Fatal("republish accepted")
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := fileIdentity(t, dir)
	reopened := &receiptFiles{uid: uint32(os.Getuid()), links: []receiptLink{{fd: fd, parent: unix.AT_FDCWD, name: dir, stat: s}}}
	defer reopened.close()
	if got, err := reopened.readCreatedPinned(receiptDigest(b)); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.reservePending(); !errors.Is(err, errReceiptFiles) {
		t.Fatal("reservation reused")
	}
	if err := reopened.publish(cleanupName, []byte("public cleanup fixture\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, createdName)); !bytes.Equal(got, b) {
		t.Fatal("cleanup receipt changed original")
	}
}

// Existing final/pending files, directories and symlinks refuse reservation
// without replacing or reading their data. Explicit chmod preserves the plant
// under the confined runner's restrictive umask.
func TestReceiptReservationCollision(t *testing.T) {
	for _, name := range []string{createdName, pendingName} {
		for _, kind := range []string{"file", "directory", "symlink"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				r, dir := receiptFixture(t)
				p := filepath.Join(dir, name)
				switch kind {
				case "file":
					if err := os.WriteFile(p, []byte("unrelated"), 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(p, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink("missing-target", p); err != nil {
						t.Fatal(err)
					}
				}
				before := fileIdentity(t, p)
				if err := r.reservePending(); !errors.Is(err, errReceiptFiles) {
					t.Fatal("collision accepted")
				}
				if after := fileIdentity(t, p); !sameReceiptObject(before, after) {
					t.Fatal("collided object changed")
				}
				if r.pending != nil {
					t.Fatal("reservation created after collision")
				}
			})
		}
	}
}

// A target planted after reservation is the no-replace regression witness:
// linkat returns the intended storage refusal and preserves unrelated bytes,
// inode and pending record; this layer never deletes/retries a Keychain item.
func TestReceiptPublishDoesNotReplacePlantedTarget(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			r, dir := receiptFixture(t)
			if err := r.reservePending(); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, createdName)
			switch kind {
			case "file":
				if err := os.WriteFile(p, []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("unrelated-target", p); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			before := fileIdentity(t, p)
			pending, _ := os.ReadFile(filepath.Join(dir, pendingName))
			if err := r.publish(createdName, []byte("new receipt")); !errors.Is(err, errReceiptFiles) {
				t.Fatal("target overwritten")
			}
			if !sameReceiptObject(before, fileIdentity(t, p)) {
				t.Fatal("target inode changed")
			}
			if kind == "file" {
				got, _ := os.ReadFile(p)
				if string(got) != "unrelated" {
					t.Fatal("target bytes changed")
				}
			}
			got, _ := os.ReadFile(filepath.Join(dir, pendingName))
			if !bytes.Equal(got, pending) {
				t.Fatal("pending changed")
			}
		})
	}
}

// Pending content/inode/mode/link changes refuse publication without creating
// a final receipt, beside the unchanged pending positive in the first test.
func TestReceiptPendingTampering(t *testing.T) {
	for _, kind := range []string{"truncate", "replace", "mode", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			r, dir := receiptFixture(t)
			if err := r.reservePending(); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, pendingName)
			switch kind {
			case "truncate":
				if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replace":
				if err := os.Rename(p, p+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, r.pendingBytes, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
				if fileIdentity(t, p).Mode&0777 != 0644 {
					t.Fatal("mode plant absent")
				}
			case "hardlink":
				if err := os.Link(p, p+".link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(p, p+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+".old", p); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.publish(createdName, []byte("receipt")); !errors.Is(err, errReceiptFiles) {
				t.Fatal("tampered pending accepted")
			}
			if _, err := os.Lstat(filepath.Join(dir, createdName)); !os.IsNotExist(err) {
				t.Fatal("final created after tamper")
			}
		})
	}
}

// Replaced directory names and changed held-directory permissions invalidate
// the descriptor chain; the fixture mutates only its own temporary directory.
func TestReceiptDirectoryReplacementAndMode(t *testing.T) {
	for _, kind := range []string{"replace", "mode"} {
		t.Run(kind, func(t *testing.T) {
			r, dir := receiptFixture(t)
			if err := r.reservePending(); err != nil {
				t.Fatal(err)
			}
			if kind == "replace" {
				moved := dir + "-moved"
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(moved) })
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.publish(createdName, []byte("receipt")); !errors.Is(err, errReceiptFiles) {
				t.Fatal("changed directory accepted")
			}
			if _, err := os.Lstat(filepath.Join(dir, createdName)); !os.IsNotExist(err) {
				t.Fatal("wrote replacement directory")
			}
		})
	}
}

// An injected directory-fsync failure occurs after the actual successful link.
// The published bytes, temp link and pending record remain; no retry/delete
// hides the uncertain durable outcome. This is not a native UNKNOWN receipt.
func TestReceiptPostPublicationFsyncFailurePreservesFiles(t *testing.T) {
	r, dir := receiptFixture(t)
	if err := r.reservePending(); err != nil {
		t.Fatal(err)
	}
	r.syncDirectory = func(int) error { return unix.EIO }
	b := []byte("receipt after actual link")
	if err := r.publish(createdName, b); !errors.Is(err, errReceiptFiles) {
		t.Fatal("fsync failure accepted")
	}
	got, err := os.ReadFile(filepath.Join(dir, createdName))
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("published witness lost")
	}
	if fileIdentity(t, filepath.Join(dir, createdName)).Nlink != 2 {
		t.Fatal("uncertain temp link removed")
	}
	if _, err := os.Lstat(filepath.Join(dir, pendingName)); err != nil {
		t.Fatal("pending removed")
	}
	if got, err := r.readCreatedPinned(receiptDigest(b)); !errors.Is(err, errReceiptFiles) || got != nil {
		t.Fatal("uncertain two-link receipt admitted")
	}
}

// Pure permission controls cover the finite legitimate directory forms and
// forbidden owner/type/mode changes. They do not inspect extended macOS ACLs.
func TestReceiptDirectoryFinitePolicy(t *testing.T) {
	s := unix.Stat_t{}
	s.Mode = unix.S_IFDIR | 0755
	s.Uid = 501
	if !receiptDirectoryOK(s, 501, 0755) {
		t.Fatal("valid0755 rejected")
	}
	s.Mode = unix.S_IFDIR | 0700
	if !receiptDirectoryOK(s, 501, 0700) {
		t.Fatal("valid0700 rejected")
	}
	for _, bad := range []unix.Stat_t{{Mode: unix.S_IFDIR | 0777}, {Mode: unix.S_IFDIR | 0775}, {Mode: unix.S_IFDIR | 01700}, {Mode: unix.S_IFDIR | 04700}, {Mode: unix.S_IFDIR | 0644}} {
		bad.Uid = 501
		if receiptDirectoryOK(bad, 501, 0700) || receiptDirectoryOK(bad, 501, 0755) {
			t.Fatal("bad mode accepted")
		}
	}
	s.Mode = unix.S_IFDIR | 0700
	s.Uid = 502
	if receiptDirectoryOK(s, 501, 0700) {
		t.Fatal("wrong owner accepted")
	}
	s.Uid = 501
	s.Mode = unix.S_IFREG | 0700
	if receiptDirectoryOK(s, 501, 0700) {
		t.Fatal("file accepted as directory")
	}
}

// Invalid destination/payload/closed state cannot create another named file.
func TestReceiptFixedNamesBoundsAndClose(t *testing.T) {
	r, dir := receiptFixture(t)
	if err := r.reservePending(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"other.json", "../created-item.json", filepath.Join(dir, createdName), pendingName} {
		if err := r.publish(name, []byte("x")); !errors.Is(err, errReceiptFiles) {
			t.Fatal("caller-selected name accepted")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, maxReceiptBytes+1)} {
		if err := r.publish(createdName, b); !errors.Is(err, errReceiptFiles) {
			t.Fatal("invalid size accepted")
		}
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	if err := r.reservePending(); !errors.Is(err, errReceiptFiles) {
		t.Fatal("closed reservation accepted")
	}
	if err := r.publish(createdName, []byte("x")); !errors.Is(err, errReceiptFiles) {
		t.Fatal("closed publication accepted")
	}
}
