package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Every input in this file is a PUBLISHED TEST AUTHORITY or synthetic public
// entropy. The anchors below are copied from the pinned public specifications,
// never from the product's derivation or its tests:
//   - BIP85 v2.1.0 (SHA256 dcbeb97709eba4751f4af7dc582c35dff37dc831abb5adc5e2e975d708d1cf7e):
//     the published master xprv, the two general vectors and HD-Seed WIF
//     application 2 / index 0 (specification lines 52-82 and 226-248);
//   - BIP340 test-vectors.csv rows 0-3 (secret key -> x-only public key);
//   - NIP-06 (published 12- and 24-word phrases and their public keys);
//   - the classic RIPEMD160(SHA256(pubkey)) example from the Bitcoin wiki.
const bip85Master = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

const bip85WIFIndex0 = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"

type bip85Vector struct {
	name    string
	path    []uint32
	child   string // empty when the specification publishes only the entropy
	entropy string // hex prefix of the published derived entropy
}

var bip85Vectors = []bip85Vector{
	{"general0", []uint32{hardened + 83696968, hardened + 0, hardened + 0},
		"cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
		"efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"},
	{"general1", []uint32{hardened + 83696968, hardened + 0, hardened + 1},
		"503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
		"70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"},
	{"wif-application2-index0", []uint32{hardened + 83696968, hardened + 2, hardened + 0}, "",
		"7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid published fixture")
	}
	return b
}

func publishedMaster(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	root, err := hdkeychain.NewKeyFromString(bip85Master)
	if err != nil || !root.IsPrivate() || root.Depth() != 0 {
		t.Fatal("published BIP85 master refused")
	}
	return root
}

// Claim: the oracle's own BIP32-child and HMAC transform reproduce BOTH official
// BIP85 general vectors (child scalar AND all 64 entropy bytes) and the official
// HD-Seed WIF application 2 / index 0 entropy and published WIF string. This is
// the grounding of the oracle: it does not trust the product, and it does not
// trust this file's agreement with the product. Limit: index 7 itself has no
// published vector; it is anchored only through the same code path.
func TestBIP85PublishedAnchors(t *testing.T) {
	root := publishedMaster(t)
	defer root.Zero()
	for _, v := range bip85Vectors {
		t.Run(v.name, func(t *testing.T) {
			child, err := childScalar(root, v.path)
			if err != nil {
				t.Fatal(err)
			}
			if v.child != "" && !bytes.Equal(child[:], mustHex(t, v.child)) {
				t.Fatal("published BIP85 child mismatch")
			}
			entropy := bip85Entropy(child)
			want := mustHex(t, v.entropy)
			if !bytes.Equal(entropy[:len(want)], want) {
				t.Fatal("published BIP85 entropy mismatch")
			}
			if v.name != "wif-application2-index0" {
				return
			}
			key, _ := btcec.PrivKeyFromBytes(entropy[:32])
			wif, err := btcutil.NewWIF(key, &chaincfg.MainNetParams, true)
			if err != nil || wif.String() != bip85WIFIndex0 {
				t.Fatal("published BIP85 WIF string mismatch")
			}
		})
	}
}

// Claim: the anchors above have teeth. Each plausible wrong transform (wrong
// HMAC key spelling, raw child instead of the HMAC output, the last 32 bytes,
// a non-hardened final edge, a wrong application or index) is applied to the
// SAME published vectors and must disagree, while the correct transform on the
// same inputs agrees. An anchor that every variant satisfies would prove nothing.
// Limit: a bounded set of plants, not exhaustive mutation testing.
func TestPublishedAnchorsRejectWrongTransforms(t *testing.T) {
	root := publishedMaster(t)
	defer root.Zero()
	wifPath := bip85Vectors[2].path
	want := mustHex(t, bip85Vectors[2].entropy)
	child, err := childScalar(root, wifPath)
	if err != nil {
		t.Fatal(err)
	}
	if correct := bip85Entropy(child); !bytes.Equal(correct[:32], want) {
		t.Fatal("positive control: correct transform must match the published entropy")
	}
	hmacWith := func(key string, msg []byte) []byte {
		h := hmac.New(sha512.New, []byte(key))
		_, _ = h.Write(msg)
		return h.Sum(nil)
	}
	plants := map[string][]byte{
		"wrong hmac key case":  hmacWith("bip-entropy-from-K", child[:])[:32],
		"wrong hmac key space": hmacWith("bip-entropy-from-k ", child[:])[:32],
		"raw child":            child[:],
		"last 32 bytes":        hmacWith(bip85HMACKey, child[:])[32:],
		"hmac roles swapped":   hmacWith(string(child[:]), []byte(bip85HMACKey))[:32],
	}
	for name, got := range plants {
		if bytes.Equal(got, want) {
			t.Fatalf("plant %q satisfies the published anchor", name)
		}
	}
	for name, path := range map[string][]uint32{
		"index 1":             {hardened + 83696968, hardened + 2, hardened + 1},
		"application 1":       {hardened + 83696968, hardened + 1, hardened + 0},
		"non-hardened index":  {hardened + 83696968, hardened + 2, 0},
		"wrong purpose":       {hardened + 83696969, hardened + 2, hardened + 0},
		"missing index level": {hardened + 83696968, hardened + 2},
	} {
		other, err := childScalar(root, path)
		if err != nil {
			t.Fatal(err)
		}
		entropy := bip85Entropy(other)
		if bytes.Equal(entropy[:32], want) {
			t.Fatalf("path plant %q satisfies the published anchor", name)
		}
	}
}

// Claim: the secret -> public key step, including even-Y normalization, matches
// BIP340 published rows 0-3 (x-only keys are published for both parities) and
// the algebraic opposite-parity control n-3, which must give the SAME K as the
// published scalar 3 while reporting odd Y before normalization. Limit: the
// curve arithmetic is the upstream module; BIP340 and NIP-06 publish its outputs.
// Rows 0-3 are restated from bitcoin/bips bip-0340/test-vectors.csv at
// 200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb, not regenerated from this oracle.
func TestBIP340PublishedKeysAndParity(t *testing.T) {
	for _, v := range []struct{ secret, public string }{
		{"0000000000000000000000000000000000000000000000000000000000000003", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"},
		{"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"},
		{"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"},
		{"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710", "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517"},
	} {
		got, err := publicFromEntropy(mustHex(t, v.secret))
		if err != nil || got.PublicKey != v.public {
			t.Fatalf("published BIP340 public key mismatch for %s", v.secret)
		}
		if got.SealPublicKey != "02"+got.PublicKey {
			t.Fatal("seal key is not the even-Y lift of K")
		}
	}
	three, err := publicFromEntropy(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000003"))
	if err != nil || three.OddY {
		t.Fatal("published scalar 3 must have even Y")
	}
	var opposite [32]byte
	new(big.Int).Sub(curveOrder, big.NewInt(3)).FillBytes(opposite[:])
	flipped, err := publicFromEntropy(opposite[:])
	if err != nil || !flipped.OddY || flipped.PublicKey != three.PublicKey || flipped.SealPublicKey != three.SealPublicKey || flipped.SealScript != three.SealScript {
		t.Fatal("n-3 must normalize to scalar 3 with the same K, seal key and script")
	}
}

// Claim: 0, n and 2^256-1 are refused (never reduced, never skipped), while the
// range neighbors 1 and n-1 are valid, so the range check rejects the right
// side. Wrong lengths are refused. Limit: oracle-only; production range
// controls live in the product tests.
func TestEntropyRangeRefusal(t *testing.T) {
	var buf [32]byte
	for name, d := range map[string]*big.Int{
		"zero":    big.NewInt(0),
		"n":       curveOrder,
		"n+1":     new(big.Int).Add(curveOrder, big.NewInt(1)),
		"2^256-1": new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		d.FillBytes(buf[:])
		if _, err := publicFromEntropy(buf[:]); !errors.Is(err, errInvalidDerivation) {
			t.Fatalf("out-of-range scalar %s admitted", name)
		}
	}
	for name, d := range map[string]*big.Int{"one": big.NewInt(1), "n-1": new(big.Int).Sub(curveOrder, big.NewInt(1))} {
		d.FillBytes(buf[:])
		if _, err := publicFromEntropy(buf[:]); err != nil {
			t.Fatalf("valid range neighbor %s refused", name)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 64)} {
		if _, err := publicFromEntropy(bad); !errors.Is(err, errInvalidDerivation) {
			t.Fatal("wrong-length entropy admitted")
		}
	}
}

// Claim: the restated group order equals the upstream curve's, and the P2PKH
// hash160 step reproduces the classic published RIPEMD160(SHA256(pubkey))
// example. Limit: constants and a primitive, nothing about the profile.
func TestCurveOrderAndHash160Anchors(t *testing.T) {
	if curveOrder.Cmp(btcec.S256().N) != 0 {
		t.Fatal("restated curve order differs from the upstream curve")
	}
	pub := mustHex(t, "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
	if hex.EncodeToString(btcutil.Hash160(pub)) != "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31" {
		t.Fatal("published hash160 example mismatch")
	}
}

// Claim: phrase -> BIP39 seed -> BIP32 master (this package's masterFromPhrase)
// reproduces the two published NIP-06 public keys at m/44'/1237'/0'/0/0, so the
// phrase-to-master chain used for the index-7 rows is itself anchored by public
// data, and a bad checksum or unknown word is refused. Limit: it anchors the
// chain up to the master, not the BIP85 steps (those are anchored above).
func TestNIP06PhraseAnchorsAndRefusals(t *testing.T) {
	for _, v := range []struct{ phrase, public string }{
		{"leader monkey parrot ring guide accident before fence cannon height naive bean", "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"},
		{nip06Phrase, "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"},
	} {
		root, err := masterFromPhrase(v.phrase)
		if err != nil {
			t.Fatal(err)
		}
		node := root
		for _, index := range []uint32{hardened + 44, hardened + 1237, hardened + 0, 0, 0} {
			next, err := node.Derive(index)
			if err != nil {
				t.Fatal(err)
			}
			node = next
		}
		pub, err := node.ECPubKey()
		if err != nil || hex.EncodeToString(pub.SerializeCompressed()[1:]) != v.public {
			t.Fatal("published NIP-06 public key mismatch")
		}
	}
	for _, bad := range []string{
		"invalid mnemonic",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
	} {
		if _, err := masterFromPhrase(bad); err == nil {
			t.Fatal("invalid phrase admitted")
		}
	}
}

// Independent third-implementation cross-check. These expected values were NOT
// read from this program or from the product. They were computed on 2026-11-13
// by a one-off, stdlib-only Python derivation (own BIP32, BIP85 and secp256k1
// arithmetic) that first reproduced the same published BIP85 / BIP340 / NIP-06
// anchors as this file. Their purpose is to stop a silent drift of the committed
// fixture: regenerating the fixture from a changed oracle cannot move these.
var crossChecked = map[string]derived{
	nip06Phrase: {
		PublicKey:     "a98cbb1bdb296a1513b0133187dd823922b019835cf47cbc03c450b765346259",
		SealPublicKey: "02a98cbb1bdb296a1513b0133187dd823922b019835cf47cbc03c450b765346259",
		SealScript:    "76a914d18031f3319d32f95d68beb7b7fad45bef1b2d2e88ac",
		OddY:          false,
	},
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art": {
		PublicKey:     "0348a12235885dae6fdedaac4ea8fc40c4bcf05a712ba1bed96ae50e58a10699",
		SealPublicKey: "020348a12235885dae6fdedaac4ea8fc40c4bcf05a712ba1bed96ae50e58a10699",
		SealScript:    "76a9144f545f997410af2b4beb5341f168aa381e00718c88ac",
		OddY:          true,
	},
	"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote": {
		PublicKey:     "37dac9e8f3ae20006994f5958bf913db9202de4e39e9082debf38e0095202ab9",
		SealPublicKey: "0237dac9e8f3ae20006994f5958bf913db9202de4e39e9082debf38e0095202ab9",
		SealScript:    "76a91425ca236fc8c018b4b31a778c08bef8c9c4eeea2e88ac",
		OddY:          true,
	},
	"abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware": {
		PublicKey:     "af9f0f967f3629f48227a0fe7af05509b59e024891e300451cf5e85adbf1a0e8",
		SealPublicKey: "02af9f0f967f3629f48227a0fe7af05509b59e024891e300451cf5e85adbf1a0e8",
		SealScript:    "76a91417c583bca41ea25ebe039c1050cb5018ec9187bf88ac",
		OddY:          false,
	},
}

// Claim: for every generated fixture row the index-7 K, 02||K, script and the
// pre-normalization parity equal the independently computed values above, and
// the four rows are exactly the four expected phrases. Both parities occur, so
// the even-Y normalization step is exercised by the fixture. Limit: the four
// phrases are public test inputs; this is not a proof for arbitrary seeds.
func TestGeneratedRowsMatchCrossCheckedValues(t *testing.T) {
	doc, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "keyvault-root-grants-reference/1" || doc.Profile != "namecoin-landlord-root/1" ||
		doc.Derivation != "bip85-hdseed-wif/1" || doc.Path != "m/83696968h/2h/7h" {
		t.Fatal("fixture header changed")
	}
	if len(doc.Rows) != len(crossChecked) {
		t.Fatal("unexpected number of fixture rows")
	}
	seen := map[string]bool{}
	var odd, even int
	for _, r := range doc.Rows {
		want, ok := crossChecked[r.Phrase]
		if !ok || seen[r.Phrase] {
			t.Fatal("unexpected or duplicate fixture phrase")
		}
		seen[r.Phrase] = true
		if r.PublicKey != want.PublicKey || r.SealPublicKey != want.SealPublicKey || r.SealScript != want.SealScript || r.OddYBeforeNormalization != want.OddY {
			t.Fatal("index-7 row disagrees with the independently computed value")
		}
		if r.OddYBeforeNormalization {
			odd++
		} else {
			even++
		}
		if len(strings.Fields(r.Phrase)) != 24 {
			t.Fatal("fixture phrase is not 24 words")
		}
	}
	if odd == 0 || even == 0 {
		t.Fatal("fixture does not exercise both Y parities")
	}
}

// Claim: no row's K equals the K of a wrong-profile derivation of the same
// phrase (index 0 as the official anchor index, index 6/8, the raw child, the
// last 32 bytes), so the fixture distinguishes the permanent index-7 profile
// from every neighbor a careless implementation might produce. Limit: bounded
// neighbors only.
func TestIndex7DiffersFromWrongProfiles(t *testing.T) {
	for phrase, want := range crossChecked {
		root, err := masterFromPhrase(phrase)
		if err != nil {
			t.Fatal(err)
		}
		candidates := map[string]string{}
		for _, index := range []uint32{0, 6, 8} {
			child, err := childScalar(root, []uint32{hardened + 83696968, hardened + 2, hardened + index})
			if err != nil {
				t.Fatal(err)
			}
			entropy := bip85Entropy(child)
			out, err := publicFromEntropy(entropy[:32])
			if err != nil {
				t.Fatal(err)
			}
			candidates[fmt.Sprintf("index %d", index)] = out.PublicKey
		}
		child, err := childScalar(root, rootGrantsPath)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := publicFromEntropy(child[:])
		if err != nil {
			t.Fatal(err)
		}
		candidates["raw child"] = raw.PublicKey
		entropy := bip85Entropy(child)
		last, err := publicFromEntropy(entropy[32:])
		if err != nil {
			t.Fatal(err)
		}
		candidates["last 32"] = last.PublicKey
		root.Zero()
		for name, got := range candidates {
			if got == want.PublicKey {
				t.Fatalf("wrong-profile derivation %s equals the index-7 K", name)
			}
		}
	}
}

// Claim: the fixture's own consistency, derived without the product: each
// seal key is "02"+K, each script is the P2PKH of hash160(seal key), all fields
// are lowercase hex of the exact length, and the encoded document contains only
// the allowed public fields (no scalar, entropy, seed or child key names).
// Limit: field shapes only; the values are checked by the cross-check test.
func TestGeneratedDocumentShapeIsPublicOnly(t *testing.T) {
	var out, errout bytes.Buffer
	if code := run([]string{"rootgrants"}, &out, &errout); code != 0 || errout.Len() != 0 {
		t.Fatal("generator failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil || decoder.More() {
		t.Fatal("generated document is not exactly the documented schema")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, r := range doc.Rows {
		if !hex64.MatchString(r.PublicKey) || r.SealPublicKey != "02"+r.PublicKey {
			t.Fatal("K or seal key malformed")
		}
		hash := btcutil.Hash160(mustHex(t, r.SealPublicKey))
		if r.SealScript != "76a914"+hex.EncodeToString(hash)+"88ac" {
			t.Fatal("seal script is not the P2PKH of the seal key")
		}
	}
	// Only the documented public field names may exist, at both levels.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &generic); err != nil {
		t.Fatal(err)
	}
	if !sameKeys(generic, "schema", "profile", "derivation", "path", "rows") {
		t.Fatal("unexpected top-level field")
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(generic["rows"], &rows); err != nil || len(rows) != len(doc.Rows) {
		t.Fatal("rows are not a list of objects")
	}
	for _, r := range rows {
		if !sameKeys(r, "phrase", "public_key", "seal_public_key", "seal_script", "odd_y_before_normalization") {
			t.Fatal("unexpected row field; only public values may be emitted")
		}
	}
}

func sameKeys(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// Claim: the generator accepts no input. Any argument, including something that
// looks like a mnemonic or a path/index override, is refused with exit 2 and
// writes nothing to stdout; the argument-free run succeeds. Limit: it cannot
// prove the process never reads stdin, which the run signature does not expose.
func TestGeneratorTakesNoInput(t *testing.T) {
	for _, args := range [][]string{
		{"rootgrants", "extra"},
		{"rootgrants", "--index", "0"},
		{"rootgrants", "abandon abandon abandon"},
		{"rootgrants", ""},
	} {
		var out, errout bytes.Buffer
		if code := run(args, &out, &errout); code != 2 || out.Len() != 0 {
			t.Fatalf("argument %q admitted", args[1])
		}
	}
	var out, errout bytes.Buffer
	if code := run([]string{"rootgrants"}, &out, &errout); code != 0 || out.Len() == 0 {
		t.Fatal("argument-free run failed")
	}
}
