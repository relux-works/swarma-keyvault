package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Published NIP-06 rows independently pin both scalar and public outputs. The
// 12-word row is a low-level fixture; owner CLI restore will require 24 words.
func TestRecoveryNIP06Vectors(t *testing.T) {
	for _, v := range []struct{ phrase, private, public, npub string }{
		{"leader monkey parrot ring guide accident before fence cannon height naive bean", "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a", "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917", "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"},
		{"what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade", "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add", "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573", "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h"},
	} {
		m, err := deriveRecovery([]byte(v.phrase))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(m.nostr[:]) != v.private || m.publicKey != v.public || m.npub != v.npub {
			t.Fatal("published vector mismatch")
		}
		if !strings.HasPrefix(m.xpub, "xpub") || !strings.HasSuffix(m.origin, "/84h/7h/0h]") {
			t.Fatal("account public metadata missing")
		}
		m.clear()
		if m.nostr != [32]byte{} || m.namecoin.key != [32]byte{} || m.namecoin.chain != [32]byte{} {
			t.Fatal("owned material not cleared")
		}
	}
}

// All 17 published BIP-32 xpubs in vectors 1-4 pin serialization and derivation,
// including hardened/normal mixed paths and the two leading-zero regressions.
func TestRecoveryBIP32PublishedPaths(t *testing.T) {
	var vectors []struct {
		Vector int    `json:"vector"`
		Seed   string `json:"seed"`
		Nodes  []struct {
			Path string `json:"path"`
			XPub string `json:"xpub"`
		} `json:"nodes"`
	}
	raw, err := os.ReadFile("testdata/recovery/bip32-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors) != 4 {
		t.Fatal("invalid fixture")
	}
	count := 0
	for _, v := range vectors {
		seed, err := hex.DecodeString(v.Seed)
		if err != nil {
			t.Fatal(err)
		}
		root, err := masterRecoveryNode(seed)
		clear(seed)
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range v.Nodes {
			path := []uint32{}
			for _, part := range strings.Split(node.Path, "/")[1:] {
				hardened := strings.HasSuffix(part, "'")
				part = strings.TrimSuffix(part, "'")
				n, err := strconv.ParseUint(part, 10, 31)
				if err != nil {
					t.Fatal("invalid fixture index")
				}
				index := uint32(n)
				if hardened {
					index |= 0x80000000
				}
				path = append(path, index)
			}
			derived, err := root.path(path)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := derived.xpub()
			derived.clear()
			if err != nil || actual != node.XPub {
				t.Fatalf("BIP32 vector %d path %s mismatch", v.Vector, node.Path)
			}
			count++
		}
		root.clear()
	}
	if count != 17 {
		t.Fatal("published path coverage changed")
	}
}

// The English list pin and five outputs from an isolated unmodified public
// reference constrain word ordering, origin fingerprint and both account paths.
// Public-account receive0/0 and change1/0 outputs independently pin the retained
// private account's ability to derive the same watch-only children.
func TestRecoveryUnmodifiedReferenceFixtures(t *testing.T) {
	h := sha256.Sum256([]byte(recoveryEnglish))
	if hex.EncodeToString(h[:]) != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatal("English list changed")
	}
	var rows []struct {
		Phrase        string `json:"phrase"`
		Public        string `json:"public_key"`
		NPub          string `json:"npub"`
		XPub          string `json:"namecoin_xpub"`
		Origin        string `json:"origin"`
		ReceivePublic string `json:"receive_0_public"`
		ChangePublic  string `json:"change_0_public"`
	}
	raw, err := os.ReadFile("testdata/recovery/reference-public.json")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 5 {
		t.Fatal("reference fixtures missing")
	}
	for _, row := range rows {
		m, err := deriveRecovery([]byte(row.Phrase))
		if err != nil {
			t.Fatal(err)
		}
		if m.publicKey != row.Public || m.npub != row.NPub || m.xpub != row.XPub || m.origin != row.Origin {
			m.clear()
			t.Fatal("unmodified reference disagreement")
		}
		for branch, want := range []string{row.ReceivePublic, row.ChangePublic} {
			child, err := m.namecoin.path([]uint32{uint32(branch), 0})
			if err != nil {
				m.clear()
				t.Fatal("account child derivation refused")
			}
			public, err := child.public()
			child.clear()
			if err != nil || hex.EncodeToString(public) != want {
				m.clear()
				t.Fatal("watch-only account child disagreement")
			}
		}
		m.clear()
	}
}

// Rare BIP-32 invalid-child branches are injected at the scalar boundary, with
// valid neighbors. IL=0 is valid; IL>=n or a zero child must refuse, not skip.
func TestRecoveryBIP32InvalidChildBoundaries(t *testing.T) {
	var one, two, zero [32]byte
	one[31] = 1
	two[31] = 2
	n, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	nMinusOne := append([]byte{}, n...)
	nMinusOne[31]--
	for _, v := range []struct {
		parent, tweak []byte
		want          [32]byte
		valid         bool
	}{
		{one[:], one[:], two, true}, {one[:], zero[:], one, true},
		{one[:], n, zero, false}, {one[:], nMinusOne, zero, false}, {zero[:], one[:], zero, false}, {one[:31], one[:], zero, false},
	} {
		actual, err := recoveryChildKey(v.parent, v.tweak)
		if v.valid {
			if err != nil || actual != v.want {
				t.Fatal("valid child boundary refused")
			}
		} else {
			recoveryCode(t, err, "invalid_derivation")
			if actual != zero {
				t.Fatal("failed derivation returned private output")
			}
		}
	}
	for _, n := range []int{0, 15, 65} {
		if _, err := masterRecoveryNode(make([]byte, n)); err == nil {
			t.Fatal("invalid seed size accepted")
		}
	}
}

// All admitted entropy sizes round-trip checksum/word encoding; changed last
// checksum word, spacing, non-English and malformed counts refuse specifically.
func TestRecoveryMnemonicRoundTripAndRefusals(t *testing.T) {
	for _, n := range []int{16, 20, 24, 28, 32} {
		entropy := make([]byte, n)
		indices, err := mnemonicIndices(entropy)
		if err != nil {
			t.Fatal(err)
		}
		phrase, err := mnemonicPhrase(indices)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseMnemonic(phrase)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed) != len(indices) {
			t.Fatal("wrong word count")
		}
		for i := range parsed {
			if parsed[i] != indices[i] {
				t.Fatal("indices changed")
			}
		}
		if !bytes.Equal(entropy, make([]byte, n)) {
			t.Fatal("input changed")
		}
		indices[len(indices)-1] ^= 1
		bad, _ := mnemonicPhrase(indices)
		if _, err := parseMnemonic(bad); err == nil {
			t.Fatal("checksum corruption accepted")
		}
	}
	for _, s := range []string{"", "abandon", strings.Repeat("abandon ", 24), strings.Repeat("abandon ", 23) + "unknown", strings.Repeat("abandon ", 23) + "é", strings.Repeat("abandon ", 23) + "abandon"} {
		if _, err := parseMnemonic([]byte(s)); err == nil {
			t.Fatal("malformed mnemonic accepted")
		}
	}
	for _, n := range []int{0, 15, 17, 33, 36} {
		if _, err := mnemonicIndices(make([]byte, n)); err == nil {
			t.Fatal("invalid entropy size accepted")
		}
	}
}

// BIP-32 vector 1 pins the serialized master xpub, not an implementation's own
// round-trip. Leading-zero vectors and account interop are checked separately.
func TestRecoveryBIP32MasterVector(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	n, err := masterRecoveryNode(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer n.clear()
	xpub, err := n.xpub()
	if err != nil {
		t.Fatal(err)
	}
	if xpub != "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" {
		t.Fatal("BIP-32 master xpub mismatch")
	}
	if hex.EncodeToString(n.key[:]) != "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35" || hex.EncodeToString(n.chain[:]) != "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508" {
		t.Fatal("BIP-32 master vector mismatch")
	}
	if !strings.HasPrefix(xpub, "xpub661MyMwAqRbc") {
		t.Fatal("wrong master serialization prefix")
	}
}
