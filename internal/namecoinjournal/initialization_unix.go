//go:build darwin || linux

package namecoinjournal

import (
	"sync"

	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
)

// InitializationReservation holds the REAL kernel gate without creating a
// directory/file or reading protected state. It belongs exclusively to the
// separate explicit first-adoption initialization review; ordinary sign/load/
// reconcile may never call it. It is no biometric consent or initialization
// success receipt. Do not copy it or release it while borrowed secrets live.
type InitializationReservation struct {
	mu           sync.Mutex
	home         string
	sidecar      Sidecar
	gate         *namecoinlocalgate.Guard
	storage      *Storage
	used, closed bool
}

func ReserveInitialization(sidecar Sidecar) (*InitializationReservation, error) {
	home, err := loginHome()
	if err != nil {
		return nil, err
	}
	return reserveInitializationAt(home, sidecar)
}
func reserveInitializationAt(home string, sidecar Sidecar) (*InitializationReservation, error) {
	if _, err := EncodeSidecar(sidecar); err != nil {
		return nil, err
	}
	gate, err := namecoinlocalgate.Acquire()
	if err != nil {
		return nil, err
	}
	return &InitializationReservation{home: home, sidecar: sidecar, gate: gate}, nil
}

// CreatePublicState runs ONLY after full native initialization review, fresh
// biometric account correspondence and exact protected-item absence. It creates
// only this new sidecar/directory/empty physical history, once. Missing ancestors
// follow existing create-only rules; collisions/partial failures are not repaired.
// Native protected create/readback must separately complete before success.
// Even on failure the reservation retains the gate until caller clears ALL
// borrowed/owned private material and explicitly closes the reservation.
func (r *InitializationReservation) CreatePublicState() (*Storage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.used || r.gate == nil {
		return nil, ErrUnknown
	}
	r.used = true
	if err := checkInitializationPublicAbsent(r.home, r.sidecar); err != nil {
		return nil, err
	}
	storage, err := openStorageWithGuard(r.home, r.sidecar, true, r.gate, false)
	if err != nil {
		return nil, err
	}
	r.storage = storage
	return storage, nil
}
func (r *InitializationReservation) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var failed bool
	if r.storage != nil && r.storage.Close() != nil {
		failed = true
	}
	if r.gate != nil && r.gate.Close() != nil {
		failed = true
	}
	if failed {
		return ErrUnknown
	}
	return nil
}
