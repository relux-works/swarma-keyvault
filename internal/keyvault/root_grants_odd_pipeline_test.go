package keyvault

import (
	"bytes"
	"crypto/sha512"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/pbkdf2"
)

// The published BIP39 256-bit-zero mnemonic, with the product's empty
// passphrase, derives an originally odd-Y application2/index7 authority. These
// fixed expectations were independently calculated using stdlib HMAC/PBKDF2
// and handwritten affine curve arithmetic, grounded by G/nG/BIP340 scalar3
// controls; they are computed expectations, not official published index7
// vectors. This complete preparation checks that the retained scalar itself
// is normalized. It does not establish native sealing, custody or erasure.
func TestRootGrantsPublishedInputOddYFullPipeline(t *testing.T) {
	phrase := []byte(strings.Repeat("abandon ", 23) + "art")
	defer clear(phrase)
	indices, err := parseMnemonic(phrase)
	defer clear(indices)
	if err != nil || len(indices) != 24 {
		t.Fatal("published mnemonic admission failed")
	}
	seed := pbkdf2.Key(phrase, []byte("mnemonic"), 2048, 64, sha512.New)
	defer clear(seed)
	root, err := masterRecoveryNode(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer root.clear()
	raw := rootGrantsTestHex(t, "52e819236a5ced8269da23d08f3f682e751da24ae0837eb54dc5230485c3dfbd")
	normalized := rootGrantsTestHex(t, "ad17e6dc95a3127d9625dc2f70c097d045913a9bcec52186720d3b884a726184")
	defer clear(raw)
	defer clear(normalized)
	oracle := rootGrantsOracleEntropy(t, &root, []uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
	defer clear(oracle[:])
	if !bytes.Equal(oracle[:32], raw) {
		t.Fatal("independently fixed raw entropy mismatch")
	}
	key, _ := btcec.PrivKeyFromBytes(raw)
	defer key.Zero()
	if key.PubKey().SerializeCompressed()[0] != 3 || bytes.Equal(raw, normalized) {
		t.Fatal("fixture does not exercise original odd Y")
	}
	prepared, err := prepareRootGrantsFromMaster(&root)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.clear()
	view, err := prepared.publicView()
	if err != nil || view.Root.PublicKey != "0348a12235885dae6fdedaac4ea8fc40c4bcf05a712ba1bed96ae50e58a10699" ||
		view.Root.SealPublicKey != "020348a12235885dae6fdedaac4ea8fc40c4bcf05a712ba1bed96ae50e58a10699" ||
		view.Root.SealScript != "76a9144f545f997410af2b4beb5341f168aa381e00718c88ac" ||
		!rootGrantsRetainedScalarMatches(prepared, normalized) {
		t.Fatal("full pipeline did not retain the normalized authority")
	}
	// Known violation: leave all public fields correct but retain original odd-Y
	// bytes. The exact assertion above must detect that route-specific shortcut.
	prepared.state.mu.Lock()
	copy(prepared.state.scalar[:], raw)
	prepared.state.mu.Unlock()
	missed := rootGrantsRetainedScalarMatches(prepared, normalized)
	prepared.state.mu.Lock()
	copy(prepared.state.scalar[:], normalized)
	prepared.state.mu.Unlock()
	if missed || !rootGrantsRetainedScalarMatches(prepared, normalized) {
		t.Fatal("odd-Y retained-scalar control failed")
	}
}
