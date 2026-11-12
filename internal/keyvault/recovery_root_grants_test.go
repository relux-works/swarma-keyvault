package keyvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// All inputs in this file are PUBLISHED TEST AUTHORITIES, never owner material.
// Fixture source pins and the limits of the independent oracle are documented
// in testdata/recovery/root-grants-vectors.md. No native operation is exercised.
const rootGrantsBIP85Master = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
const rootGrantsCurveOrder = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

func rootGrantsTestHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid published test fixture")
	}
	return b
}

// Test-only decoding, not a product xprv/WIF import/export route.
func rootGrantsTestMaster(t *testing.T) recoveryNode {
	t.Helper()
	raw := base58.Decode(rootGrantsBIP85Master)
	defer clear(raw)
	if len(raw) != 82 || !bytes.Equal(raw[:4], []byte{4, 0x88, 0xad, 0xe4}) ||
		!bytes.Equal(raw[4:13], make([]byte, 9)) || raw[45] != 0 {
		t.Fatal("invalid published BIP85 master encoding")
	}
	h := sha256.Sum256(raw[:78])
	h = sha256.Sum256(h[:])
	if !bytes.Equal(raw[78:], h[:4]) {
		t.Fatal("published master checksum mismatch")
	}
	var root recoveryNode
	copy(root.chain[:], raw[13:45])
	copy(root.key[:], raw[46:78])
	return root
}

// Claim: full BIP32-child/HMAC output matches the TWO official BIP85 general
// vectors; application2/index0 matches its independently published first32/WIF
// payload. Index0 is a PRIMITIVE TEST ONLY, never the root-grants profile.
// Limits: no numbered tty, native custody, zeroization or index7 public vector.
func TestRootGrantsPublishedBIP85(t *testing.T) {
	root := rootGrantsTestMaster(t)
	defer root.clear()
	for _, v := range []struct {
		name    string
		path    []uint32
		child   string
		entropy string
	}{
		{"general0", []uint32{0x80000000 | 83696968, 0x80000000, 0x80000000},
			"cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
			"efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"},
		{"general1", []uint32{0x80000000 | 83696968, 0x80000000, 0x80000001},
			"503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
			"70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"},
		{"wif-index0-primitive-only", []uint32{0x80000000 | 83696968, 0x80000002, 0x80000000}, "",
			"7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"},
	} {
		t.Run(v.name, func(t *testing.T) {
			child, err := root.path(v.path)
			if err != nil {
				t.Fatal(err)
			}
			defer child.clear()
			if v.child != "" && !bytes.Equal(child.key[:], rootGrantsTestHex(t, v.child)) {
				t.Fatal("published BIP85 child mismatch")
			}
			entropy, err := rootGrantsBIP85Entropy(child.key[:])
			defer clear(entropy[:])
			want := rootGrantsTestHex(t, v.entropy)
			if err != nil || !bytes.Equal(entropy[:len(want)], want) {
				t.Fatal("published BIP85 entropy mismatch")
			}
			// Independent arithmetic must itself pass the published expectations.
			oracle := rootGrantsOracleEntropy(t, &root, v.path)
			defer clear(oracle[:])
			if !bytes.Equal(oracle[:len(want)], want) {
				t.Fatal("test oracle disagrees with published BIP85 vector")
			}
			if v.child == "" {
				wif := base58.Decode("Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp")
				defer clear(wif)
				if len(wif) != 38 || wif[0] != 0x80 || wif[33] != 1 || !bytes.Equal(wif[1:33], want) {
					t.Fatal("official WIF fixture does not bind application entropy")
				}
				h := sha256.Sum256(wif[:34])
				h = sha256.Sum256(h[:])
				if !bytes.Equal(wif[34:], h[:4]) {
					t.Fatal("official WIF fixture checksum mismatch")
				}
			}
		})
	}
}

// rootGrantsOracleEntropy uses test-only math/big modular addition for hardened
// BIP32, not recoveryNode.path/recoveryChildKey or the production entropy helper.
// Official general/WIF vectors above anchor it. SHA512 is shared stdlib code;
// curve public multiplication below is shared and separately anchored by BIP340.
// This is NOT a separately published index7 public pin or independent custody.
func rootGrantsOracleEntropy(t *testing.T, root *recoveryNode, path []uint32) [64]byte {
	t.Helper()
	n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
	k := new(big.Int).SetBytes(root.key[:])
	chain := root.chain
	defer clear(chain[:])
	var input [37]byte
	defer clear(input[:])
	for _, index := range path {
		if index&0x80000000 == 0 {
			t.Fatal("oracle admits only hardened published-fixture paths")
		}
		input[0] = 0
		k.FillBytes(input[1:33])
		binary.BigEndian.PutUint32(input[33:], index)
		h := hmac.New(sha512.New, chain[:])
		_, _ = h.Write(input[:])
		material := h.Sum(nil)
		tweak := new(big.Int).SetBytes(material[:32])
		if tweak.Cmp(n) >= 0 {
			t.Fatal("published-fixture oracle invalid child; no skip")
		}
		k.Add(k, tweak).Mod(k, n)
		if k.Sign() == 0 {
			t.Fatal("published-fixture oracle zero child; no skip")
		}
		copy(chain[:], material[32:])
		clear(material)
	}
	var child [32]byte
	defer clear(child[:])
	k.FillBytes(child[:])
	h := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	_, _ = h.Write(child[:])
	var entropy [64]byte
	h.Sum(entropy[:0])
	return entropy
}

// Claim: the product's closed path is app2/index7, transformed rather than raw
// child/last32, and each nearby hardened path mutant produces another public K.
// Limits: test-only oracle agreement plus published primitive anchors; no
// independently published expected index7 K and no qualified helper integration.
func TestRootGrantsFixedIndex7(t *testing.T) {
	root := rootGrantsTestMaster(t)
	defer root.clear()
	p, err := prepareRootGrantsFromMaster(&root)
	if err != nil {
		t.Fatal(err)
	}
	defer p.clear()
	view, err := p.publicView()
	if err != nil || view.Root.Path != "m/83696968h/2h/7h" ||
		view.Root.Profile != "namecoin-landlord-root/1" || view.Root.Derivation != "bip85-hdseed-wif/1" {
		t.Fatal("fixed root profile mismatch")
	}
	entropy := rootGrantsOracleEntropy(t, &root, []uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
	defer clear(entropy[:])
	rootGrantsAssertPublic(t, view.Root, entropy[:32])
	if bytes.Equal(p.state.scalar[:], entropy[32:]) {
		t.Fatal("last32 substituted for most-significant entropy")
	}
	child, err := root.path([]uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
	if err != nil {
		t.Fatal(err)
	}
	defer child.clear()
	raw, err := nostrPrivate(child.key[:])
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Zero()
	if view.Root.PublicKey == hex.EncodeToString(raw.PubKey().SerializeCompressed()[1:]) {
		t.Fatal("raw BIP32 child substituted for BIP85 entropy")
	}
	for _, path := range [][]uint32{
		{0x80000000 | 83696968, 0x80000002, 0x80000000},
		{0x80000000 | 83696968, 0x80000002, 0x80000008},
		{0x80000000 | 83696968, 0x80000001, 0x80000007},
		{0x80000000 | 83696969, 0x80000002, 0x80000007},
	} {
		other := rootGrantsOracleEntropy(t, &root, path)
		key, _ := nostrPrivate(other[:32])
		clear(other[:])
		if key == nil {
			t.Fatal("path mutant unexpectedly invalid")
		}
		public := hex.EncodeToString(key.PubKey().SerializeCompressed()[1:])
		key.Zero()
		if public == view.Root.PublicKey {
			t.Fatal("path mutant matches reserved root K")
		}
	}
	for _, bad := range []*recoveryNode{nil, {}, {depth: 1}, {child: 1}, {parent: [4]byte{1}}} {
		got, err := prepareRootGrantsFromMaster(bad)
		if err == nil || got != nil {
			t.Fatal("non-master or invalid master admitted")
		}
	}
}

// rootGrantsAssertPublic independently constructs the public projection and
// P2PKH script from the range-checked fixture exponent. It tests no signature.
func rootGrantsAssertPublic(t *testing.T, got RootGrantsPublic, exponent []byte) {
	t.Helper()
	n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
	d := new(big.Int).SetBytes(exponent)
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		t.Fatal("invalid test exponent")
	}
	key, _ := btcec.PrivKeyFromBytes(exponent)
	defer key.Zero()
	compressed := key.PubKey().SerializeCompressed()
	compressed[0] = 2 // lift_x(K), independent of the original parity
	h := sha256.Sum256(compressed)
	r := ripemd160.New()
	_, _ = r.Write(h[:])
	if got.PublicKey != hex.EncodeToString(compressed[1:]) || got.SealPublicKey != hex.EncodeToString(compressed) ||
		got.SealScript != "76a914"+hex.EncodeToString(r.Sum(nil))+"88ac" {
		t.Fatal("x-only/even-Y seal correspondence mismatch")
	}
}

// Claim: published BIP340 scalar3/public K and its n-3 odd-Y counterpart retain
// identical K, normalize to scalar3, and bind the even compressed seal script.
// Range endpoints zero/n/overflow hard-refuse and invalidate prior state.
// Limits: normalization/pin projection only; no ECDSA/BIP340 signing or presence.
func TestRootGrantsParityAndRange(t *testing.T) {
	p := newRootGrantsPrepared()
	defer p.clear()
	n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
	for _, d := range []*big.Int{big.NewInt(3), new(big.Int).Sub(n, big.NewInt(3))} {
		var entropy [64]byte
		d.FillBytes(entropy[:32])
		for i := 32; i < 64; i++ {
			entropy[i] = 0xff // irrelevant trailing half
		}
		if err := p.state.setBIP85Entropy(&entropy); err != nil {
			t.Fatal(err)
		}
		view, err := p.publicView()
		if err != nil || view.Root.PublicKey != "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" {
			t.Fatal("published BIP340 public pin mismatch")
		}
		rootGrantsAssertPublic(t, view.Root, entropy[:32])
		clear(entropy[:])
		var three [32]byte
		three[31] = 3
		if *p.state.scalar != three {
			t.Fatal("even-Y scalar normalization mismatch")
		}
	}
	for _, d := range []*big.Int{big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1))} {
		var entropy [64]byte
		d.FillBytes(entropy[:32])
		if err := p.state.setBIP85Entropy(&entropy); err != nil {
			t.Fatal("valid range neighbor refused")
		}
		rootGrantsAssertPublic(t, p.state.public.Root, entropy[:32])
		clear(entropy[:])
	}
	for _, d := range []*big.Int{big.NewInt(0), n, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		var entropy [64]byte
		d.FillBytes(entropy[:32])
		err := p.state.setBIP85Entropy(&entropy)
		clear(entropy[:])
		rootGrantsWantRefusal(t, err, "invalid_derivation")
		if *p.state.scalar != [32]byte{} || p.state.ready {
			t.Fatal("invalid exponent retained private preparation")
		}
	}
	rootGrantsWantRefusal(t, p.state.setBIP85Entropy(nil), "invalid_derivation")
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 32), rootGrantsTestHex(t, rootGrantsCurveOrder), make([]byte, 33)} {
		entropy, err := rootGrantsBIP85Entropy(bad)
		rootGrantsWantRefusal(t, err, "invalid_derivation")
		if entropy != [64]byte{} {
			t.Fatal("invalid child yielded entropy")
		}
	}
}

func rootGrantsWantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != "recovery_"+code {
		t.Fatalf("expected fixed refusal %s", code)
	}
}

func rootGrantsTestPair(t *testing.T, schema string) ([]byte, RootGrantsPairBinding) {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecoveryRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if schema == "keyvault-recovery/2" {
		r.Schema = schema
		r.Nostr.Service = r.Service
		r.Namecoin.Service = "example-wallet"
		raw, err = json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
	}
	return raw, rootGrantsPairBinding(raw, r)
}

// Claim: both legitimate retained schemas admit the published NIP06 24-word
// pair, preserve every input byte, and bind a deterministic index7 public view.
// Alias clear invalidates the handle, clears its owned scalar and leaves public
// snapshots usable. Limits: fixture expected bindings are not real enrollment;
// no wrapping/store/ciphertext access, native ACL or physical-erasure proof.
func TestRootGrantsAttachPublishedPair(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			raw, expected := rootGrantsTestPair(t, schema)
			before := bytes.Clone(raw)
			phrase := []byte(recoveryFixturePhrase)
			p, err := prepareRootGrantsAttach(context.Background(), phrase, raw, expected)
			if err != nil {
				t.Fatal(err)
			}
			defer p.clear()
			if !bytes.Equal(phrase, make([]byte, len(phrase))) || !bytes.Equal(raw, before) {
				t.Fatal("input lifetime/pair preservation failure")
			}
			view, err := p.publicView()
			if err != nil || view.Pair != expected || view.Pair.NostrPublicKey != "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573" {
				t.Fatal("public preparation binding mismatch")
			}
			fullDigest := sha256.Sum256(raw)
			if view.Pair.MetadataSHA256 != hex.EncodeToString(fullDigest[:]) {
				t.Fatal("binding digest is not the complete retained canonical record")
			}
			seed := pbkdf2.Key([]byte(recoveryFixturePhrase), []byte("mnemonic"), 2048, 64, sha512.New)
			root, err := masterRecoveryNode(seed)
			clear(seed)
			if err != nil {
				t.Fatal(err)
			}
			entropy := rootGrantsOracleEntropy(t, &root, []uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
			root.clear()
			rootGrantsAssertPublic(t, view.Root, entropy[:32])
			clear(entropy[:])
			alias := *p
			p.clear()
			if *alias.state.scalar != [32]byte{} {
				t.Fatal("aliased private buffer not cleared")
			}
			_, err = alias.publicView()
			rootGrantsWantRefusal(t, err, "private_protocol_error")
		})
	}
}

// Claim: EACH externally pinned record field is mandatory. Canonical metadata,
// checksum-valid wrong words and separate social/account/origin swaps all refuse
// with no prepared handle. Inputs are cleared on every refusal. Since this seam
// has no effect interface, refusal cannot call a wrap/store/ACL/install callback.
// Limits: actual orchestration order and no-write preservation need docking
// tests; no test here qualifies the old store, owner pin source or tty grammar.
func TestRootGrantsAttachRefusals(t *testing.T) {
	raw, expected := rootGrantsTestPair(t, "keyvault-recovery/2")
	for _, mutate := range []func(*RootGrantsPairBinding){
		func(p *RootGrantsPairBinding) { p.Schema = "keyvault-recovery/1" },
		func(p *RootGrantsPairBinding) { p.Service = "other" },
		func(p *RootGrantsPairBinding) { p.Version++ },
		func(p *RootGrantsPairBinding) { p.GroupID = strings.Repeat("1", 32) },
		func(p *RootGrantsPairBinding) { p.MetadataSHA256 = strings.Repeat("0", 64) },
		func(p *RootGrantsPairBinding) { p.NostrIdentity = "other" },
		func(p *RootGrantsPairBinding) { p.NostrVersion++ },
		func(p *RootGrantsPairBinding) { p.NostrPublicKey = "" },
		func(p *RootGrantsPairBinding) { p.NostrNPub = "" },
		func(p *RootGrantsPairBinding) { p.NamecoinIdentity = "other" },
		func(p *RootGrantsPairBinding) { p.NamecoinVersion++ },
		func(p *RootGrantsPairBinding) { p.NamecoinXPub = "" },
		func(p *RootGrantsPairBinding) { p.NamecoinOrigin = "" },
	} {
		pins := expected
		mutate(&pins)
		rootGrantsAssertAttachRefused(t, context.Background(), recoveryFixturePhrase, raw, pins, "retained_record_mismatch")
	}
	for _, bad := range [][]byte{
		nil, append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), []byte(" {}")...),
		[]byte(strings.Replace(string(raw), `"group_id":`, `"unknown":0,"group_id":`, 1)),
		[]byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(raw), "m/84'/7'/0'", "m/84'/7'/1'", 1)),
		[]byte(strings.Replace(string(raw), "m/44'/1237'/0'/0/0", "m/44'/1237'/1'/0/0", 1)),
		make([]byte, recoveryMaxMetadata+1),
	} {
		rootGrantsAssertAttachRefused(t, context.Background(), recoveryFixturePhrase, bad, expected, "retained_record_mismatch")
	}
	// These valid changes leave every projected pin/address identical; only a
	// hash of the COMPLETE exact metadata catches them against retained pins.
	for _, mutate := range []func(*RecoveryRecord){
		func(r *RecoveryRecord) { r.Created = "2026-01-03T03:04:05Z" },
		func(r *RecoveryRecord) {
			r.Nostr.WrappingPoint, r.Namecoin.WrappingPoint = r.Namecoin.WrappingPoint, r.Nostr.WrappingPoint
			r.Nostr.WrappingFingerprint, r.Namecoin.WrappingFingerprint = r.Namecoin.WrappingFingerprint, r.Nostr.WrappingFingerprint
		},
	} {
		r, _ := parseRecoveryRecord(raw)
		mutate(&r)
		changed, err := json.Marshal(r)
		if err != nil || validateRecoveryRecord(r) != nil {
			t.Fatal("complete-metadata hash control is not a valid record")
		}
		rootGrantsAssertAttachRefused(t, context.Background(), recoveryFixturePhrase, changed, expected, "retained_record_mismatch")
	}
	for _, v := range []struct{ phrase, code string }{
		{"", "invalid_word_count"},
		{"leader monkey parrot ring guide accident before fence cannon height naive bean", "invalid_word_count"},
		{recoveryFixturePhrase + " abandon", "invalid_word_count"},
		{strings.Replace(recoveryFixturePhrase, "what bleak", "bleak what", 1), "checksum_or_pin_mismatch"},
		{strings.Replace(recoveryFixturePhrase, "what", "bleak", 1), "checksum_or_pin_mismatch"},
		{strings.Repeat("abandon ", 23) + "abandon", "invalid_checksum"},
		{strings.Repeat("abandon ", 23) + "art", "public_pin_mismatch"},
		{strings.Replace(recoveryFixturePhrase, "what", "WHAT", 1), "invalid_mnemonic"},
	} {
		rootGrantsAssertAttachRefused(t, context.Background(), v.phrase, raw, expected, v.code)
	}
	// Swap each public purpose pin independently but keep a canonical record and
	// matching external record binding. This reaches DERIVED-public comparison,
	// rather than passing merely because the record hash caught every mutation.
	var rows []struct {
		Public string `json:"public_key"`
		NPub   string `json:"npub"`
		XPub   string `json:"namecoin_xpub"`
		Origin string `json:"origin"`
	}
	fixtures, err := os.ReadFile("testdata/recovery/reference-public.json")
	if err != nil || json.Unmarshal(fixtures, &rows) != nil || len(rows) != 5 {
		t.Fatal("reference fixture unavailable")
	}
	for _, mutate := range []func(*RecoveryRecord){
		func(r *RecoveryRecord) { r.Nostr.PublicKey, r.Nostr.NPub = rows[2].Public, rows[2].NPub },
		func(r *RecoveryRecord) { r.Namecoin.XPub = rows[2].XPub },
		func(r *RecoveryRecord) { r.Namecoin.Origin = rows[2].Origin },
	} {
		r, _ := parseRecoveryRecord(raw)
		mutate(&r)
		changed, err := json.Marshal(r)
		if err != nil || validateRecoveryRecord(r) != nil {
			t.Fatal("negative public-pin fixture is not a valid retained record")
		}
		pins := rootGrantsPairBinding(changed, r)
		rootGrantsAssertAttachRefused(t, context.Background(), recoveryFixturePhrase, changed, pins, "public_pin_mismatch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rootGrantsAssertAttachRefused(t, ctx, recoveryFixturePhrase, raw, expected, "canceled")
	// Deterministically cancel at the post-pair and post-root checks without a
	// timing race or production callback that could expose private material.
	for _, phase := range []int{2, 3} {
		ctx := &rootGrantsPhaseCancellation{Context: context.Background(), at: phase}
		rootGrantsAssertAttachRefused(t, ctx, recoveryFixturePhrase, raw, expected, "canceled")
		if ctx.calls != phase {
			t.Fatal("cancellation did not reach the expected private preparation phase")
		}
	}
	rootGrantsAssertAttachRefused(t, nil, recoveryFixturePhrase, raw, expected, "invalid_arguments")
}

// A test-only context controls phase observation. It carries no private data.
type rootGrantsPhaseCancellation struct {
	context.Context
	at, calls int
}

func (c *rootGrantsPhaseCancellation) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return nil
}

func rootGrantsAssertAttachRefused(t *testing.T, ctx context.Context, words string, raw []byte, pins RootGrantsPairBinding, code string) {
	t.Helper()
	phrase := []byte(words)
	before := bytes.Clone(raw)
	p, err := prepareRootGrantsAttach(ctx, phrase, raw, pins)
	if p != nil {
		p.clear()
		t.Fatal("refusal returned a prepared handle")
	}
	if code == "checksum_or_pin_mismatch" {
		// Word order can fail BIP39 checksum OR (if checksum-valid) both pins.
		var r *Refusal
		if !errors.As(err, &r) || (r.Code != "recovery_invalid_checksum" && r.Code != "recovery_public_pin_mismatch") {
			t.Fatal("reordered words did not fail checksum/pins")
		}
	} else {
		rootGrantsWantRefusal(t, err, code)
	}
	if !bytes.Equal(phrase, make([]byte, len(phrase))) || !bytes.Equal(raw, before) {
		t.Fatal("refusal did not clear input/preserve retained metadata")
	}
}

// Claim: the published BIP39 256-bit-zero vector has exactly 24 English words
// and the expected entropy/checksum mapping; invalid counts/checksums refuse.
// Limits: this anchors parsing, not a passphrase option (product is EMPTY only)
// or PBKDF2 in isolation; published NIP06 pins above anchor empty-passphrase use.
func TestRootGrantsPublishedBIP39(t *testing.T) {
	phrase := []byte(strings.Repeat("abandon ", 23) + "art")
	defer clear(phrase)
	indices, err := parseMnemonic(phrase)
	defer clear(indices)
	if err != nil || len(indices) != 24 || indices[23] != 102 {
		t.Fatal("published BIP39 256-bit-zero vector mismatch")
	}
	for _, index := range indices[:23] {
		if index != 0 {
			t.Fatal("published BIP39 zero entropy mapping mismatch")
		}
	}
}

// Claim: ordinary formatting and JSON serialization cannot export the private
// handle/state; public snapshots have only public fields. Concurrent clear/view
// operations are serialized, and clear is idempotent. Limits: no unsafe or
// reflection defense, heap-erasure guarantee, binary/ABI audit or native lane.
func TestRootGrantsOpaqueLifetime(t *testing.T) {
	p := newRootGrantsPrepared()
	var entropy [64]byte
	entropy[31] = 3
	if err := p.state.setBIP85Entropy(&entropy); err != nil {
		t.Fatal(err)
	}
	clear(entropy[:])
	defer p.clear()
	for _, value := range []any{p, *p, p.state, *p.state} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
			if fmt.Sprintf(format, value) != "<private-root-grants>" {
				t.Fatal("private preparation formatting is not fixed")
			}
		}
		if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
			t.Fatal("private preparation serialization admitted")
		}
	}
	public, err := p.publicView()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(public)
	if err != nil || bytes.Contains(encoded, []byte("scalar")) || bytes.Contains(encoded, []byte("chain")) {
		t.Fatal("public view serialization failed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.publicView(); p.clear() }()
	}
	wg.Wait()
	if *p.state.scalar != [32]byte{} || p.state.ready {
		t.Fatal("private state survived clear")
	}
	var missing *rootGrantsPrepared
	missing.clear()
	_, err = missing.publicView()
	rootGrantsWantRefusal(t, err, "private_protocol_error")
}
