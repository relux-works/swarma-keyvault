//go:build darwin || linux

package namecoinjournal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
)

// Reserving the actual kernel gate creates no public state, and busy refusal
// likewise writes nothing. A single explicit create succeeds under that SAME
// held gate without acquiring a fallback lock or another listener.
func TestInitializationReservationGateAndCreateOnce(t *testing.T) {
	home, sidecar, root := storageFixture(t)
	reservation, err := reserveInitializationAt(home, sidecar)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	if _, err = os.Stat(filepath.Join(home, "Library", "Application Support", "mac-keyvault")); !os.IsNotExist(err) {
		t.Fatal("reservation wrote before consent")
	}
	if other, err := reserveInitializationAt(home, sidecar); !errors.Is(err, namecoinlocalgate.ErrAccountBusy) || other != nil {
		t.Fatal("concurrent reservation admitted", err)
	}
	storage, err := reservation.CreatePublicState()
	if err != nil {
		t.Fatal(err)
	}
	if records, err := storage.Records(); err != nil || len(records) != 0 {
		t.Fatal("new public history", err)
	}
	if _, err = os.Stat(filepath.Join(root, "sidecar")); err != nil {
		t.Fatal(err)
	}
	if again, err := reservation.CreatePublicState(); !errors.Is(err, ErrUnknown) || again != nil {
		t.Fatal("repeated initialization")
	}
	// Closing a borrowed public handle never releases the reservation's gate.
	if storage.Close() != nil {
		t.Fatal("storage close")
	}
	if guard, err := namecoinlocalgate.Acquire(); !errors.Is(err, namecoinlocalgate.ErrAccountBusy) || guard != nil {
		t.Fatal("private lifetime gate released early")
	}
	if reservation.Close() != nil || reservation.Close() != nil {
		t.Fatal("reservation close-once")
	}
	guard, err := namecoinlocalgate.Acquire()
	if err != nil {
		t.Fatal("gate leaked", err)
	}
	defer guard.Close()
}

// An existing selected directory refuses without deletion/repair; the gate
// remains held even after that failed create until explicit private cleanup.
// These disposable files do not exercise any native protected storage or UI.
func TestInitializationReservationFailedCreateKeepsGate(t *testing.T) {
	home, sidecar, root := storageFixture(t)
	existing := createStorageFixture(t, home, sidecar)
	if existing.Close() != nil {
		t.Fatal("fixture close")
	}
	before, err := os.ReadFile(filepath.Join(root, "sidecar"))
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := reserveInitializationAt(home, sidecar)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	if storage, err := reservation.CreatePublicState(); err == nil || storage != nil {
		t.Fatal("existing state replaced")
	}
	after, err := os.ReadFile(filepath.Join(root, "sidecar"))
	if err != nil || string(before) != string(after) {
		t.Fatal("failed create modified existing sidecar")
	}
	if guard, err := namecoinlocalgate.Acquire(); !errors.Is(err, namecoinlocalgate.ErrAccountBusy) || guard != nil {
		t.Fatal("failed create released private lifetime gate")
	}
	if storage, err := reservation.CreatePublicState(); !errors.Is(err, ErrUnknown) || storage != nil {
		t.Fatal("failed create retried")
	}
	if reservation.Close() != nil {
		t.Fatal("close")
	}
	if storage, err := reservation.CreatePublicState(); !errors.Is(err, ErrUnknown) || storage != nil {
		t.Fatal("create after close")
	}
}
