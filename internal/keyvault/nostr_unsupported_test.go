//go:build !darwin || !cgo

package keyvault

import (
	"errors"
	"testing"
)

// Portable cryptography remains usable, while every unsupported custody entry
// point refuses with no key, record or signature and no software-store fallback.
func TestNostrUnsupportedCustody(t *testing.T) {
	r, secret := nostrTestMaterial(t, 3)
	sig, err := signNostrSecret(r, secret, make([]byte, 32))
	if err != nil || VerifyNostr(nostrTestHex(t, r.PublicKey), make([]byte, 32), sig) != nil {
		t.Fatal("portable public control failed")
	}
	store := NewNostrSecurityStore()
	created, err := store.Create(nostrTestRequest())
	if !errors.Is(err, errUnsupported) || created != (NostrRecord{}) {
		t.Fatal("unsupported create returned output")
	}
	records, err := store.List()
	if !errors.Is(err, errUnsupported) || records != nil {
		t.Fatal("unsupported list returned records")
	}
	result, err := store.Sign(r, make([]byte, 32))
	if !errors.Is(err, errUnsupported) || result != nil {
		t.Fatal("unsupported sign returned output")
	}
}
