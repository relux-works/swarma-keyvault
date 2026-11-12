//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The real exclusive cleanup reservation precedes the one consumable native
// input. Result publication retains both original records and pending audits;
// these outcome-shaped fixtures do not execute or prove a Keychain deletion.
func TestCleanupReservationAndSeparatePublication(t *testing.T) {
	for _, outcome := range []CleanupOutcome{CleanupRefused, CleanupDeleted, CleanupUnknown} {
		r, dir, pub := completeFixture(t)
		loaded, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture())
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(filepath.Join(dir, createdName))
		if err != nil {
			t.Fatal(err)
		}
		creationPending, err := os.ReadFile(filepath.Join(dir, pendingName))
		if err != nil {
			t.Fatal(err)
		}
		capability, err := loaded.BeginCleanup()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loaded.Request(); !errors.Is(err, ErrReceipt) {
			t.Fatal("cleanup reused read capability")
		}
		pending, err := os.ReadFile(filepath.Join(dir, cleanupPendingName))
		if err != nil {
			t.Fatal(err)
		}
		request, projection, err := capability.ConsumeForNativeDelete()
		if err != nil {
			t.Fatal(err)
		}
		defer request.Clear()
		if !bytes.Equal(request.Reference(), []byte{1, 2, 3}) || request.ReceiptSHA256() != pub.SHA256 || projection != literalProjectionSHA {
			t.Fatal("cleanup lost exact original item/projection binding")
		}
		if _, _, err := capability.ConsumeForNativeDelete(); !errors.Is(err, ErrReceipt) {
			t.Fatal("native-delete capability reused")
		}
		if _, err := loaded.BeginCleanup(); !errors.Is(err, ErrReceipt) {
			t.Fatal("cleanup reservation repeated")
		}
		publication, err := capability.Publish(outcome)
		if err != nil || !validSHA256(publication.SHA256) {
			t.Fatal("cleanup publication refused")
		}
		if _, err := capability.Publish(outcome); !errors.Is(err, ErrReceipt) {
			t.Fatal("cleanup result overwritten")
		}
		raw, err := os.ReadFile(filepath.Join(dir, cleanupName))
		if err != nil {
			t.Fatal(err)
		}
		var result cleanupRecord
		if json.Unmarshal(raw, &result) != nil || result.CreatedReceiptSHA256 != pub.SHA256 || result.Candidate != candidateFixture() || result.CleanupPendingSHA256 != receiptSHA256(pending) || result.State != publication.State {
			t.Fatal("separate cleanup result lost binding")
		}
		for name, want := range map[string][]byte{createdName: original, pendingName: creationPending, cleanupPendingName: pending} {
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("audit changed")
			}
		}
		if _, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture()); !errors.Is(err, ErrReceipt) {
			t.Fatal("cleanup audit allowed later item use")
		}
	}
}

// Existing cleanup objects, including symlinks and directories, refuse before
// yielding any native-delete input and preserve their actual inode/bytes.
func TestCleanupCollisionRefusesBeforeNativeCapability(t *testing.T) {
	for _, name := range []string{cleanupPendingName, cleanupName} {
		for _, kind := range []string{"file", "directory", "symlink"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				r, dir, pub := completeFixture(t)
				loaded, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture())
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, name)
				switch kind {
				case "file":
					if err := os.WriteFile(path, []byte("unrelated"), 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink("unrelated", path); err != nil {
						t.Fatal(err)
					}
				}
				before := fileIdentity(t, path)
				if c, err := loaded.BeginCleanup(); !errors.Is(err, ErrReceipt) || c != nil {
					t.Fatal("collision yielded native capability")
				}
				if !sameReceiptObject(before, fileIdentity(t, path)) {
					t.Fatal("collision changed")
				}
				if kind == "file" {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != "unrelated" {
						t.Fatal("collision bytes changed")
					}
				}
			})
		}
	}
}

// Changed cleanup audit latches one-use refusal. A real post-link fsync error
// preserves both original receipts, pending and the linked result; returning
// UNKNOWN remains the caller's obligation, with no publication/delete retry.
func TestCleanupTamperAndPublicationFailure(t *testing.T) {
	r, dir, pub := completeFixture(t)
	loaded, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture())
	if err != nil {
		t.Fatal(err)
	}
	c, err := loaded.BeginCleanup()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cleanupPendingName), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ConsumeForNativeDelete(); !errors.Is(err, ErrReceipt) {
		t.Fatal("changed cleanup reservation consumed")
	}
	if _, _, err := c.ConsumeForNativeDelete(); !errors.Is(err, ErrReceipt) {
		t.Fatal("cleanup refusal revived")
	}
	if _, err := c.Publish(CleanupDeleted); !errors.Is(err, ErrReceipt) {
		t.Fatal("changed pending published success")
	}
	r, dir, pub = completeFixture(t)
	loaded, err = loadCreatedReceipt(r, pub.SHA256, candidateFixture())
	if err != nil {
		t.Fatal(err)
	}
	c, err = loaded.BeginCleanup()
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := c.ConsumeForNativeDelete()
	if err != nil {
		t.Fatal(err)
	}
	request.Clear()
	r.syncDirectory = func(int) error { return unix.EIO }
	if result, err := c.Publish(CleanupDeleted); !errors.Is(err, ErrReceipt) || result.SHA256 != "" {
		t.Fatal("failed publication reported success")
	}
	if _, err := c.Publish(CleanupDeleted); !errors.Is(err, ErrReceipt) {
		t.Fatal("failed publication retried")
	}
	for _, name := range []string{createdName, pendingName, cleanupPendingName, cleanupName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatal("failed publication removed evidence")
		}
	}
	if fileIdentity(t, filepath.Join(dir, cleanupName)).Nlink != 2 {
		t.Fatal("post-link fault did not exercise linked publication")
	}
}
