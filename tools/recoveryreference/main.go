// recoveryreference produces public expected outputs from unmodified upstream
// modules and known public fixtures only. It has no private user-input route.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/tyler-smith/go-bip39"
)

type fixture struct {
	Phrase        string `json:"phrase"`
	Public        string `json:"public_key"`
	NPub          string `json:"npub"`
	XPub          string `json:"namecoin_xpub"`
	Origin        string `json:"origin"`
	ReceivePublic string `json:"receive_0_public"`
	ChangePublic  string `json:"change_0_public"`
}

func derive(phrase string) (fixture, error) {
	var out fixture
	seed, err := bip39.NewSeedWithErrorChecking(phrase, "")
	if err != nil {
		return out, err
	}
	defer clear(seed)
	root, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return out, err
	}
	defer root.Zero()
	public, err := root.ECPubKey()
	if err != nil {
		return out, err
	}
	fp := btcutil.Hash160(public.SerializeCompressed())
	derivePath := func(path []uint32) (*hdkeychain.ExtendedKey, error) {
		current := root
		for _, index := range path {
			next, err := current.Derive(index)
			if current != root {
				current.Zero()
			}
			if err != nil {
				return nil, err
			}
			current = next
		}
		return current, nil
	}
	nostr, err := derivePath([]uint32{0x8000002c, 0x800004d5, 0x80000000, 0, 0})
	if err != nil {
		return out, err
	}
	defer nostr.Zero()
	private, err := nostr.ECPrivKey()
	if err != nil {
		return out, err
	}
	defer private.Zero()
	pub := schnorr.SerializePubKey(private.PubKey())
	words, err := bech32.ConvertBits(pub, 8, 5, true)
	if err != nil {
		return out, err
	}
	npub, err := bech32.Encode("npub", words)
	if err != nil {
		return out, err
	}
	account, err := derivePath([]uint32{0x80000054, 0x80000007, 0x80000000})
	if err != nil {
		return out, err
	}
	defer account.Zero()
	xpub, err := account.Neuter()
	if err != nil {
		return out, err
	}
	// Derive the receive/change controls from the PUBLIC account, independently
	// of the vault's private-node derivation. No private extended key is output.
	childPublic := func(branch uint32) (string, error) {
		b, err := xpub.Derive(branch)
		if err != nil {
			return "", err
		}
		defer b.Zero()
		child, err := b.Derive(0)
		if err != nil {
			return "", err
		}
		defer child.Zero()
		p, err := child.ECPubKey()
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(p.SerializeCompressed()), nil
	}
	receive, err := childPublic(0)
	if err != nil {
		return out, err
	}
	change, err := childPublic(1)
	if err != nil {
		return out, err
	}
	return fixture{Phrase: phrase, Public: hex.EncodeToString(pub), NPub: npub, XPub: xpub.String(), Origin: fmt.Sprintf("[%s/84h/7h/0h]", hex.EncodeToString(fp[:4])), ReceivePublic: receive, ChangePublic: change}, nil
}

func fixtures() ([]fixture, error) {
	phrases := []string{"leader monkey parrot ring guide accident before fence cannon height naive bean", "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"}
	for _, entropyHex := range []string{"0000000000000000000000000000000000000000000000000000000000000000", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"} {
		entropy, _ := hex.DecodeString(entropyHex)
		phrase, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
		phrases = append(phrases, phrase)
	}
	rows := make([]fixture, 0, len(phrases))
	for _, phrase := range phrases {
		row, err := derive(phrase)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "this fixture generator takes no input")
		os.Exit(2)
	}
	rows, err := fixtures()
	if err != nil {
		fmt.Fprintln(os.Stderr, "public fixture generation failed")
		os.Exit(1)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if e.Encode(rows) != nil {
		os.Exit(1)
	}
}
