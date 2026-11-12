//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func completeFixture(t *testing.T) (*receiptFiles, string, Publication) {
	t.Helper()
	r, dir := receiptFixture(t)
	if err := r.reservePending(); err != nil {
		t.Fatal(err)
	}
	c := &CreationReservation{files: r}
	if err := c.ConsumeForNativeCreate(); err != nil {
		t.Fatal(err)
	}
	p, err := c.Publish(candidateFixture(), nativeCreationFixture())
	if err != nil {
		t.Fatal(err)
	}
	if p.State != "created" || !validSHA256(p.SHA256) {
		t.Fatal("wrong publication")
	}
	if _, err := c.Publish(candidateFixture(), nativeCreationFixture()); !errors.Is(err, ErrReceipt) {
		t.Fatal("completion repeated")
	}
	return r, dir, p
}

// Real isolated file operations connect native-result-shaped public fixtures
// to a one-use creation receipt and pinned later request. This does not run
// the OS-home production loader, authenticate code, or touch any Keychain.
func TestCompletedReceiptFilesystemBindings(t *testing.T) {
	r, dir, pub := completeFixture(t)
	original, err := os.ReadFile(filepath.Join(dir, createdName))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture())
	if err != nil {
		t.Fatal(err)
	}
	request, err := loaded.Request()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Clear()
	if !bytes.Equal(request.Reference(), []byte{1, 2, 3}) || request.ReceiptSHA256() != pub.SHA256 {
		t.Fatal("request lost independent binding")
	}
	if err := loaded.CheckProjection(*nativeCreationFixture().After); err != nil {
		t.Fatal(err)
	}
	wrong := *nativeCreationFixture().After
	wrong.OwnerUID++
	if !errors.Is(loaded.CheckProjection(wrong), ErrReceipt) {
		t.Fatal("changed native projection accepted")
	}
	candidate := candidateFixture()
	candidate.SourceTree = strings.Repeat("d", 40)
	if _, err := loadCreatedReceipt(r, pub.SHA256, candidate); !errors.Is(err, ErrReceipt) {
		t.Fatal("changed candidate admitted")
	}
	if _, err := loadCreatedReceipt(r, strings.Repeat("0", 64), candidateFixture()); !errors.Is(err, ErrReceipt) {
		t.Fatal("wrong independent digest admitted")
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Request(); !errors.Is(err, ErrReceipt) {
		t.Fatal("closed receipt produced request")
	}
	got, err := os.ReadFile(filepath.Join(dir, createdName))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("read/control changed original receipt")
	}
}

// Byte-identical pending replacement cannot substitute its inode; corrupt or
// replaced complete files and non-created audit records supply no capability.
// Every plant is confined to this test's actual disposable file directory.
func TestCompletedReceiptReplacementAndUnknownRefusal(t *testing.T) {
	for _, plant := range []string{"pending-replacement", "pending-changed", "created-replacement", "created-changed", "created-mode"} {
		t.Run(plant, func(t *testing.T) {
			r, dir, pub := completeFixture(t)
			loaded, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture())
			if err != nil {
				t.Fatal(err)
			}
			pending := filepath.Join(dir, pendingName)
			complete := filepath.Join(dir, createdName)
			switch plant {
			case "created-replacement":
				b, err := os.ReadFile(complete)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(complete, complete+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(complete, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-replacement":
				b, err := os.ReadFile(pending)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(pending, pending+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pending, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-changed":
				if err := os.WriteFile(pending, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "created-changed":
				if err := os.WriteFile(complete, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "created-mode":
				if err := os.Chmod(complete, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loaded.Request(); !errors.Is(err, ErrReceipt) {
				t.Fatal("changed original supplied request")
			}
			if _, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture()); !errors.Is(err, ErrReceipt) {
				t.Fatal("replacement admitted by loader")
			}
		})
	}
	for _, outcome := range []CreationOutcome{CreationRefused, CreationUnknown} {
		r, _ := receiptFixture(t)
		if err := r.reservePending(); err != nil {
			t.Fatal(err)
		}
		c := &CreationReservation{files: r}
		if err := c.ConsumeForNativeCreate(); err != nil {
			t.Fatal(err)
		}
		pub, err := c.Publish(candidateFixture(), NativeCreation{Outcome: outcome})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loadCreatedReceipt(r, pub.SHA256, candidateFixture()); !errors.Is(err, ErrReceipt) {
			t.Fatal("non-created audit admitted")
		}
	}
}
