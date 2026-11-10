// Use of this source code is governed by the ISC license in ../LICENSE.

package schnorr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const challengeProbeEnv = "KEYVAULT_TEST_CHALLENGE_PROBE"

// These are synthetic SHA-256 outputs, not preimages or live keys. An isolated
// Go source overlay replaces only the two challenge hashes in signing and
// verification. Production has no hash override. Normal-hash vectors and
// wrong-key/message controls remain necessary: a constant challenge cannot
// establish message/key binding (especially when its residue is zero).
func TestChallengeModuloBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, hash string }{
		{"n-minus-one", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"},
		{"n", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"},
		{"n-plus-one", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"},
		{"max", strings.Repeat("f", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runChallengeProbe(t, tc.hash, false)
			if err != nil {
				t.Fatalf("challenge signing boundary failed: %v\n%s", err, output)
			}
		})
	}
}

// The regression instrument must detect the original overflow refusal at n,
// rather than treating a child setup failure, skipped probe or crash as proof.
func TestChallengeModuloRefusalControl(t *testing.T) {
	output, err := runChallengeProbe(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", true)
	if err == nil || !strings.Contains(output, "BIP340_CHALLENGE_REFUSED: hash of (r || P || m) too big") ||
		!strings.Contains(output, "--- FAIL: TestChallengeModuloProbe") {
		t.Fatalf("original-refusal control did not detect the intended violation: %v\n%s", err, output)
	}
}

func runChallengeProbe(t *testing.T, challenge string, plant bool) (string, error) {
	t.Helper()
	source, err := filepath.Abs("signature.go")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, source, original, 0)
	if err != nil {
		t.Fatal(err)
	}
	type span struct{ start, end int }
	var replacements []span
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != "TaggedHash" {
			return true
		}
		pkg, ok := fun.X.(*ast.Ident)
		tag, tagOK := call.Args[0].(*ast.SelectorExpr)
		if ok && pkg.Name == "chainhash" && tagOK && tag.Sel.Name == "TagBIP0340Challenge" {
			replacements = append(replacements, span{fs.Position(fun.Pos()).Offset, fs.Position(fun.End()).Offset})
		}
		return true
	})
	if len(replacements) != 2 {
		t.Fatalf("expected exactly signing and verification challenge calls, got %d", len(replacements))
	}
	modified := bytes.Clone(original)
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		modified = append(append(append([]byte{}, modified[:r.start]...), []byte("boundaryFixtureHash")...), modified[r.end:]...)
	}
	if plant {
		fixed := []byte("e.SetBytes((*[32]byte)(commitment))")
		if bytes.Count(modified, fixed) != 2 {
			t.Fatal("refusal plant requires exactly two reduced challenge conversions")
		}
		// Replace the last conversion, which belongs to signing. Verification
		// continues reducing normally, as it did in the original implementation.
		i := bytes.LastIndex(modified, fixed)
		refusal := []byte("if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 { k.Zero(); return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, \"hash of (r || P || m) too big\") }")
		modified = append(append(append([]byte{}, modified[:i]...), refusal...), modified[i+len(fixed):]...)
	}
	raw, err := hex.DecodeString(challenge)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid synthetic challenge fixture")
	}
	modified = append(modified, []byte(fmt.Sprintf("\nfunc boundaryFixtureHash(_ []byte, _ ...[]byte) *chainhash.Hash { h := chainhash.Hash{%s}; return &h }\n", byteLiterals(raw)))...)
	dir := t.TempDir()
	overlaySource, overlayPath := filepath.Join(dir, "signature.go"), filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlaySource, modified, 0600); err != nil {
		t.Fatal(err)
	}
	mapping, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{source: overlaySource}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, mapping, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-count=1", "-timeout=30s", "-overlay="+overlayPath, "-run=^TestChallengeModuloProbe$", "-v", ".")
	cmd.Env = append(os.Environ(), challengeProbeEnv+"="+challenge)
	cmd.WaitDelay = 5 * time.Second
	output, runErr := cmd.CombinedOutput()
	after, readErr := os.ReadFile(source)
	if readErr != nil || !bytes.Equal(original, after) {
		t.Fatal("overlay modified the original signing source")
	}
	if ctx.Err() != nil {
		t.Fatalf("challenge probe exceeded its own budget: %v", ctx.Err())
	}
	if len(output) > 8192 {
		t.Fatal("challenge probe exceeded bounded diagnostic output")
	}
	if runErr == nil && !bytes.Contains(output, []byte("--- PASS: TestChallengeModuloProbe")) {
		t.Fatal("challenge probe did not execute successfully")
	}
	return string(output), runErr
}

func byteLiterals(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return strings.Join(parts, ",")
}

// The expected response is independent big.Int arithmetic based on official
// vector 0. Its known signature and independently computed real SHA-256
// challenge recover k; each synthetic output must yield s=(k+3*(hash mod n)) mod
// n and the same r. This tests actual signing/self-verification, not just two
// implementations agreeing. All inspected signer buffers must still be clear.
func TestChallengeModuloProbe(t *testing.T) {
	hexChallenge := os.Getenv(challengeProbeEnv)
	if hexChallenge == "" {
		t.Skip("executed only by the isolated hash-output overlay")
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	n := new(big.Int).SetBytes(decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
	reference := decode("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0")
	pub := decode("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
	digest := make([]byte, 32)
	tag := sha256.Sum256([]byte("BIP0340/challenge"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(reference[:32])
	h.Write(pub)
	h.Write(digest)
	e := new(big.Int).SetBytes(h.Sum(nil))
	k := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).SetBytes(reference[32:]), new(big.Int).Mul(e, big.NewInt(3))), n)
	challenge := decode(hexChallenge)
	if len(challenge) != 32 {
		t.Fatal("challenge fixture must be 32 bytes")
	}
	residue := new(big.Int).Mod(new(big.Int).SetBytes(challenge), n)
	wantS := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(residue, big.NewInt(3))), n)
	want := append(bytes.Clone(reference[:32]), wantS.FillBytes(make([]byte, 32))...)
	key, _ := btcec.PrivKeyFromBytes([]byte{3})
	defer key.Zero()
	var buffers signingBuffers
	sig, err := signWithBuffers(key, digest, &buffers, CustomNonce([32]byte{}))
	assertSigningBuffersCleared(t, &buffers)
	if err != nil {
		t.Fatalf("BIP340_CHALLENGE_REFUSED: %v", err)
	}
	if sig == nil || !bytes.Equal(sig.Serialize(), want) || !sig.Verify(digest, key.PubKey()) {
		t.Fatal("signature differs from independent BIP-340 modulo response")
	}
	// A different response must fail even under the synthetic challenge.
	bad := bytes.Clone(want)
	bad[63] ^= 1
	mutated, err := ParseSignature(bad)
	if err == nil && mutated.Verify(digest, key.PubKey()) {
		t.Fatal("mutated response accepted")
	}
	if sig.Verify(digest[:31], key.PubKey()) {
		t.Fatal("malformed digest accepted")
	}
}
