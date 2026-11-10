//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/recoveryfixture"
)

// Apple's in-memory SecKey implementation opens BOTH production wire lengths
// and matches the independent Go receiver. A different fixture key or altered
// GCM tag must return the platform's authentication failure. No Keychain,
// hardware, authentication prompt or live private key participates.
func TestRecoveryAppleECIESWireConformance(t *testing.T) {
	m, store, helper := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	pair, err := parseRecoveryCiphertext(store.data[r.Account()], r)
	if err != nil {
		t.Fatal(err)
	}
	for i, envelope := range []recoveryEnvelope{pair.Nostr, pair.Namecoin} {
		key := helper.keys[i]
		representation := append(key.PublicKey().Bytes(), key.Bytes()...)
		defer clear(representation)
		want, err := recoveryTestOpen(key, envelope.Ciphertext)
		if err != nil {
			t.Fatal("software positive fixture failed")
		}
		defer clear(want)
		actual, err := recoveryfixture.Open(representation, envelope.Ciphertext)
		defer clear(actual)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("Apple ECIES wire disagreement for purpose %d: %v", i, err)
		}
		other := helper.keys[1-i]
		wrong := append(other.PublicKey().Bytes(), other.Bytes()...)
		defer clear(wrong)
		corrupt := bytes.Clone(envelope.Ciphertext)
		corrupt[len(corrupt)-1] ^= 1
		for _, bad := range []struct{ key, wire []byte }{{wrong, envelope.Ciphertext}, {representation, corrupt}} {
			plain, err := recoveryfixture.Open(bad.key, bad.wire)
			clear(plain)
			if err == nil || err.Error() != "Apple ECIES refusal: -50" || plain != nil {
				t.Fatalf("wrong-key/tag control did not reach platform authentication refusal: %v", err)
			}
		}
	}
}
