package keyvault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// The final policy sees the actual resolved generation and an owned public-key
// snapshot. Its rejection reaches no private call; the valid neighbor signs.
func TestSignIfKeyResolvedGate(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "accept", true: "refuse"}[reject], func(t *testing.T) {
			address := addr("resolved-gate", 1)
			store := newFakeStore(address.Label())
			store.installSigner(t, address.Label())
			manager := newTestManager(t, store)
			want := bytes.Clone(store.keys[address.Label()].SPKI)
			digest := sha256.Sum256([]byte("resolved gate fixture"))
			denied := errors.New("fixture gate denied")
			gates := 0
			result, err := manager.SignIfKey(address, digest[:], func(key ResolvedSigningKey) error {
				gates++
				if key.Address != address || key.Store != StoreKeychain || key.UserPresence || !bytes.Equal(key.SPKI, want) {
					t.Fatal("gate did not see the resolved key")
				}
				key.SPKI[0] ^= 1
				if reject {
					return denied
				}
				return nil
			})
			if gates != 1 || !bytes.Equal(store.keys[address.Label()].SPKI, want) {
				t.Fatal("gate count or public-key alias")
			}
			if reject {
				if !errors.Is(err, denied) || len(store.signs) != 0 || result.Key.Label != "" {
					t.Fatal("gate refusal performed a private operation", err)
				}
			} else if err != nil || len(store.signs) != 1 {
				t.Fatal("valid gate did not sign once", err)
			}
		})
	}
}

// A newest-generation address is resolved once before the key-aware gate; an
// earlier generation cannot be reported to the gate while a newer one signs.
func TestSignIfKeyNewestGeneration(t *testing.T) {
	first, newest := addr("resolved-generation", 1), addr("resolved-generation", 2)
	store := newFakeStore(first.Label(), newest.Label())
	store.installSigner(t, first.Label())
	store.installSigner(t, newest.Label())
	manager := newTestManager(t, store)
	digest := sha256.Sum256([]byte("resolved generation fixture"))
	requested := addr("resolved-generation", 0)
	denied := errors.New("generation gate refused")
	_, err := manager.SignIfKey(requested, digest[:], func(key ResolvedSigningKey) error {
		if key.Address != newest {
			t.Fatal("gate did not observe actual newest generation")
		}
		return denied
	})
	if !errors.Is(err, denied) || len(store.signs) != 0 {
		t.Fatal("generation gate was bypassed", err)
	}
}
