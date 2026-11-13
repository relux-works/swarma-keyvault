package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/tyler-smith/go-bip39"
)

// The root grants profile's fixed identifiers. They restate the agreed contract
// (BIP85 application 2, index 7); they are NOT read from the product source.
const (
	fixtureSchema = "keyvault-root-grants-reference/1"
	profile       = "namecoin-landlord-root/1"
	derivation    = "bip85-hdseed-wif/1"
	pathText      = "m/83696968h/2h/7h"
	// bip85HMACKey is the HMAC key of BIP85 v2.1.0 specification lines 52-62.
	bip85HMACKey = "bip-entropy-from-k"
)

const hardened = hdkeychain.HardenedKeyStart

// rootGrantsPath is m/83696968'/2'/7'. There is no index parameter.
var rootGrantsPath = []uint32{hardened + 83696968, hardened + 2, hardened + 7}

// curveOrder is the secp256k1 group order n, restated from SEC 2 and checked
// against the upstream curve in the tests.
var curveOrder, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

var errInvalidDerivation = errors.New("invalid derivation")

// masterFromPhrase is BIP39 (empty passphrase, checksum enforced) followed by
// the BIP32 master, using the unmodified upstream modules.
func masterFromPhrase(phrase string) (*hdkeychain.ExtendedKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(phrase, "")
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
}

// childScalar derives the BIP32 child at path (upstream hdkeychain, including
// its standard leading-zero handling) and returns its exact 32-byte big-endian
// private scalar.
func childScalar(root *hdkeychain.ExtendedKey, path []uint32) ([32]byte, error) {
	var out [32]byte
	current := root
	release := func() {
		if current != root {
			current.Zero()
		}
	}
	for _, index := range path {
		next, err := current.Derive(index)
		release()
		if err != nil {
			current = root
			return out, err
		}
		current = next
	}
	defer release()
	private, err := current.ECPrivKey()
	if err != nil {
		return out, err
	}
	defer private.Zero()
	scalar := private.Serialize()
	defer clear(scalar)
	if len(scalar) != len(out) {
		return out, errInvalidDerivation
	}
	copy(out[:], scalar)
	return out, nil
}

// bip85Entropy is HMAC-SHA512(key="bip-entropy-from-k", msg=k) over the child's
// 32-byte big-endian scalar k, as published in BIP85 v2.1.0.
func bip85Entropy(child [32]byte) [64]byte {
	h := hmac.New(sha512.New, []byte(bip85HMACKey))
	_, _ = h.Write(child[:])
	var out [64]byte
	h.Sum(out[:0])
	return out
}

// derived carries public values only.
type derived struct {
	PublicKey     string // x-only K, 64 lowercase hex
	SealPublicKey string // 02 || K, 66 lowercase hex
	SealScript    string // OP_DUP OP_HASH160 <hash160(02||K)> OP_EQUALVERIFY OP_CHECKSIG
	OddY          bool   // whether d*G had odd Y before even-Y normalization
}

// publicFromEntropy takes the MOST significant 32 bytes of BIP85 entropy as the
// big-endian scalar d, refuses 0 and anything >= n (no reduction, no index
// skip), and normalizes d to the even-Y representative (d or n-d).
func publicFromEntropy(first32 []byte) (derived, error) {
	if len(first32) != 32 {
		return derived{}, errInvalidDerivation
	}
	d := new(big.Int).SetBytes(first32)
	if d.Sign() == 0 || d.Cmp(curveOrder) >= 0 {
		return derived{}, errInvalidDerivation
	}
	key, _ := btcec.PrivKeyFromBytes(first32) // d < n: no reduction happens
	defer key.Zero()
	odd := key.PubKey().SerializeCompressed()[0] == 0x03
	even := key
	if odd {
		var flipped [32]byte
		new(big.Int).Sub(curveOrder, d).FillBytes(flipped[:])
		defer clear(flipped[:])
		even, _ = btcec.PrivKeyFromBytes(flipped[:])
		defer even.Zero()
	}
	compressed := even.PubKey().SerializeCompressed()
	xonly := schnorr.SerializePubKey(even.PubKey())
	if compressed[0] != 0x02 || len(xonly) != 32 || !bytes.Equal(compressed[1:], xonly) {
		return derived{}, errInvalidDerivation
	}
	return derived{
		PublicKey:     hex.EncodeToString(xonly),
		SealPublicKey: hex.EncodeToString(compressed),
		SealScript:    "76a914" + hex.EncodeToString(btcutil.Hash160(compressed)) + "88ac",
		OddY:          odd,
	}, nil
}

// rootGrants derives the fixed profile's public outputs from a BIP32 master.
func rootGrants(root *hdkeychain.ExtendedKey) (derived, error) {
	child, err := childScalar(root, rootGrantsPath)
	defer clear(child[:])
	if err != nil {
		return derived{}, err
	}
	entropy := bip85Entropy(child)
	defer clear(entropy[:])
	return publicFromEntropy(entropy[:32])
}
