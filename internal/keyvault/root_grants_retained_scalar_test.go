package keyvault

import (
	"bytes"
	"context"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func rootGrantsRetainedScalarMatches(p *rootGrantsPrepared, expected []byte) bool {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return p.state.ready && bytes.Equal(p.state.scalar[:], expected)
}

// Both complete preparation routes retain the independently expected scalar,
// K and seal script from PUBLIC test authorities. These two original points
// have even Y; their normalized scalar is the first32 entropy bytes. Direct
// odd-Y/invalid-range controls remain in TestRootGrantsParityAndRange. The fixed
// K/script snapshots are independently computed expectations, not published
// official index7 vectors. No native custody or physical erasure is proved.
func TestRootGrantsFullPipelineRetainedScalar(t *testing.T) {
	root := rootGrantsTestMaster(t)
	defer root.clear()
	prepared, err := prepareRootGrantsFromMaster(&root)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.clear()
	expected := rootGrantsTestHex(t, "5ea642d2efed482cf09e869b27dcd82dddff20898c943becadd717d8efa2acc7")
	defer clear(expected)
	check := func(t *testing.T, p *rootGrantsPrepared, scalar []byte, public, script string) {
		t.Helper()
		view, err := p.publicView()
		if err != nil || view.Root.PublicKey != public || view.Root.SealPublicKey != "02"+public || view.Root.SealScript != script || !rootGrantsRetainedScalarMatches(p, scalar) {
			t.Fatal("full derivation retained scalar/public correspondence mismatch")
		}
		// Known violation: preserving every public field while corrupting the
		// retained scalar must fail this exact scalar check, then restore it.
		p.state.mu.Lock()
		p.state.scalar[31] ^= 1
		p.state.mu.Unlock()
		acceptedCorruption := rootGrantsRetainedScalarMatches(p, scalar)
		p.state.mu.Lock()
		p.state.scalar[31] ^= 1
		p.state.mu.Unlock()
		if acceptedCorruption {
			t.Fatal("retained-scalar control missed corruption")
		}
	}
	check(t, prepared, expected, "95ecbb5232c991e459d065c5c20bab30514599d8ea8a85e9e0970f4c4cc8d18d", "76a914a7c0b9f4dc6d033262d2332b7192fc20100b49bc88ac")

	seed := pbkdf2.Key([]byte(recoveryFixturePhrase), []byte("mnemonic"), 2048, 64, sha512.New)
	phraseRoot, err := masterRecoveryNode(seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer phraseRoot.clear()
	entropy := rootGrantsOracleEntropy(t, &phraseRoot, []uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
	defer clear(entropy[:])
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			raw, pair := rootGrantsTestPair(t, schema)
			p, err := prepareRootGrantsAttach(context.Background(), []byte(recoveryFixturePhrase), raw, pair)
			if err != nil {
				t.Fatal(err)
			}
			defer p.clear()
			check(t, p, entropy[:32], "a98cbb1bdb296a1513b0133187dd823922b019835cf47cbc03c450b765346259", "76a914d18031f3319d32f95d68beb7b7fad45bef1b2d2e88ac")
		})
	}
}
