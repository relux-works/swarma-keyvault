package namecoinpsbt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Published BIP32 test vector1, never owner material. Only this test helper
// derives a root/hardened account; production accepts only the retained account
// and its two explicitly permitted unhardened descendant levels.
func publishedAccountMaterial(t *testing.T) []byte {
	t.Helper()
	seed := decodeHex("000102030405060708090a0b0c0d0e0f")
	defer clear(seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = mac.Write(seed)
	material := mac.Sum(nil)
	defer clear(material)
	var scalar btcec.ModNScalar
	defer scalar.Zero()
	if scalar.SetByteSlice(material[:32]) || scalar.IsZero() {
		t.Fatal("published master invalid")
	}
	var chain [32]byte
	defer clear(chain[:])
	copy(chain[:], material[32:])
	for _, index := range []uint32{0x80000054, 0x80000007, 0x80000000} {
		var data [37]byte
		scalar.PutBytesUnchecked(data[1:33])
		binary.BigEndian.PutUint32(data[33:], index)
		mac := hmac.New(sha512.New, chain[:])
		_, _ = mac.Write(data[:])
		clear(data[:])
		sum := mac.Sum(nil)
		var delta btcec.ModNScalar
		if delta.SetByteSlice(sum[:32]) {
			clear(sum)
			t.Fatal("published child invalid")
		}
		scalar.Add(&delta)
		delta.Zero()
		copy(chain[:], sum[32:])
		clear(sum)
	}
	out := make([]byte, 64)
	scalar.PutBytesUnchecked(out[:32])
	copy(out[32:], chain[:])
	return out
}

// The retained-account-only algorithm produces deterministic valid low-S/ALL
// signatures for all public Core fixtures, independently verified afterward.
// This directly exercises synthetic private math, NOT native consent/fencing.
func TestConfinedSyntheticAccountSigning(t *testing.T) {
	material := publishedAccountMaterial(t)
	defer clear(material)
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				c := candidate(t, mode, slot)
				point, chain := c.AccountPublic()
				a, err := loadSigningAccount(material, point, chain)
				if err != nil {
					t.Fatal("published account/pin mismatch", err)
				}
				defer a.clear()
				first, err := c.signConfined(a, fixtureSelection(t, c))
				if err != nil {
					t.Fatal(err)
				}
				second, err := c.signConfined(a, fixtureSelection(t, c))
				if err != nil {
					t.Fatal(err)
				}
				if len(first) != len(c.digests) {
					t.Fatal("incomplete signature set")
				}
				for i := range first {
					if !bytes.Equal(first[i], second[i]) {
						t.Fatal("ECDSA was not deterministic")
					}
				}
				if err = c.VerifySignatures(first); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Wrong scalar/chain/point and malformed lengths leave no usable account;
// cleared objects have opaque diagnostics and cannot derive/sign afterward.
func TestSecretCorrespondenceClearingAndOpaqueDiagnostics(t *testing.T) {
	c := candidate(t, "all-four-before-release", "A")
	point, chain := c.AccountPublic()
	material := publishedAccountMaterial(t)
	defer clear(material)
	for _, bad := range [][]byte{nil, material[:63], append(bytes.Clone(material), 0), make([]byte, 64), append(make([]byte, 32), material[32:]...)} {
		a, err := loadSigningAccount(bad, point, chain)
		requireCode(t, err, namecoinwire.AccountMismatch)
		if a != nil {
			a.clear()
			t.Fatal("bad material left account")
		}
	}
	wrongChain := chain
	wrongChain[0] ^= 1
	a, err := loadSigningAccount(material, point, wrongChain)
	requireCode(t, err, namecoinwire.AccountMismatch)
	if a != nil {
		a.clear()
		t.Fatal("wrong chain admitted")
	}
	wrongPoint := point
	wrongPoint[0] ^= 1
	a, err = loadSigningAccount(material, wrongPoint, chain)
	requireCode(t, err, namecoinwire.AccountMismatch)
	if a != nil {
		a.clear()
		t.Fatal("wrong point admitted")
	}
	a, err = loadSigningAccount(material, point, chain)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%v/%#v/%x", a, a, a) != "<confined Namecoin account>/<confined Namecoin account>/<confined Namecoin account>" {
		a.clear()
		t.Fatal("account diagnostics were not opaque")
	}
	_, err = a.child(0x80000000)
	requireCode(t, err, namecoinwire.PathRefused)
	a.clear()
	if !a.scalar.IsZero() || a.chain != [32]byte{} || !a.closed {
		t.Fatal("owned account memory survived clear")
	}
	_, err = a.child(0)
	requireCode(t, err, namecoinwire.PathRefused)
	_, err = c.signConfined(a, fixtureSelection(t, c))
	requireCode(t, err, namecoinwire.AccountMismatch)
}

// BIP32's child I_L=0 is valid; >=n and infinity/zero-child refuse without
// skipping to another index. Both public/private functions use literal controls.
func TestBIP32ChildBoundaryControls(t *testing.T) {
	g := decodeHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	var point [33]byte
	copy(point[:], g)
	zero := make([]byte, 64)
	defer clear(zero)
	zero[63] = 7
	got, err := addPublicTweak(point, zero[:32])
	if err != nil || got != point {
		t.Fatal("valid zero child tweak refused", err)
	}
	parent := new(signingAccount)
	parent.scalar.SetInt(1)
	defer parent.clear()
	child, err := addPrivateChild(parent, zero)
	if err != nil {
		t.Fatal(err)
	}
	if !child.scalar.Equals(&parent.scalar) || child.chain[31] != 7 {
		child.clear()
		t.Fatal("zero tweak changed key or lost chain")
	}
	child.clear()
	order := decodeHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	defer clear(order)
	_, err = addPublicTweak(point, order)
	requireCode(t, err, namecoinwire.PathRefused)
	copy(zero[:32], order)
	_, err = addPrivateChild(parent, zero)
	requireCode(t, err, namecoinwire.PathRefused)
	order[31]--
	_, err = addPublicTweak(point, order)
	requireCode(t, err, namecoinwire.PathRefused)
	copy(zero[:32], order)
	_, err = addPrivateChild(parent, zero)
	requireCode(t, err, namecoinwire.PathRefused)
}
