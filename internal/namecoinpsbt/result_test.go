package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Frozen Core-signed bundles bind every public request/review/signature field.
// The fixture D-head/sequence are FORMAT ONLY; no public check authenticates S.
func TestFrozenPublicResultsAndNonCircularReceipt(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				c := candidate(t, mode, slot)
				context, err := c.ReviewContext(fixtureSelection(t, c))
				if err != nil {
					t.Fatal(err)
				}
				review, err := c.snapshot.ReviewDigest(context)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join("..", "namecoinwire", "testdata", mode, slot+"-result.json"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.VerifyResult(raw, review); err != nil {
					t.Fatal("frozen public bundle refused", err)
				}
				wrong := review
				wrong[0] ^= 1
				_, err = c.VerifyResult(raw, wrong)
				requireCode(t, err, namecoinwire.IntentMismatch)
				sigs, err := c.VerifySignedPSBT(signedFixture(t, mode, slot))
				if err != nil {
					t.Fatal(err)
				}
				dispatch := sha256.Sum256([]byte("literal public dispatch-head fixture"))
				generated, err := c.ResultBytes(sigs, review, 7, dispatch)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := c.VerifyResult(generated, review)
				if err != nil {
					t.Fatal(err)
				}
				if receipt.JournalSequence != 7 || receipt.JournalHeadSHA256 != hex.EncodeToString(dispatch[:]) {
					t.Fatal("result failed to reference the supplied dispatch fence")
				}
				// Complete-result hash is calculated AFTER the immutable D reference;
				// protected history must subsequently bind it, not feed an S head back.
				if err = namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(sha256.Sum256(generated)), generated); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The high-S control remains mathematically valid for the same public key and
// digest, so rejection specifically enforces low-S rather than a wrong signature.
func TestHighSAndNonDERRefusals(t *testing.T) {
	c := candidate(t, "all-four-before-release", "A")
	sigs, err := c.VerifySignedPSBT(signedFixture(t, "all-four-before-release", "A"))
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sigs[0][:len(sigs[0])-1], &pair)
	if err != nil || len(rest) != 0 {
		t.Fatal("control DER invalid")
	}
	order := new(big.Int).SetBytes(decodeHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
	if order.BitLen() != 256 {
		t.Fatal("order fixture malformed")
	}
	pair.S = new(big.Int).Sub(order, pair.S)
	high, err := asn1.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ecdsa.ParseDERSignature(high)
	if err != nil {
		t.Fatal("high-S control failed syntax", err)
	}
	pub, err := btcec.ParsePubKey(c.packet.inputs[0].origin.key[:])
	if err != nil || !parsed.Verify(c.digests[0][:], pub) {
		t.Fatal("high-S control failed independent mathematical verification")
	}
	if bytes.Equal(parsed.Serialize(), high) {
		t.Fatal("control was not high-S")
	}
	requireCode(t, c.VerifySignatures([][]byte{append(high, 1)}), namecoinwire.SighashRefused)
	for _, bad := range [][]byte{nil, {1}, {0x30, 0, 1}, append(bytes.Clone(sigs[0]), 0), append([]byte{0}, sigs[0]...)} {
		requireCode(t, c.VerifySignatures([][]byte{bad}), namecoinwire.SighashRefused)
	}
}
