// rootgrants is the independent expected-value oracle for the fixed index-7
// root grants key (BIP85 application 2, path m/83696968h/2h/7h). It uses the
// unmodified upstream BIP-39, BIP-32 and secp256k1 modules and shares no code,
// constant or expected value with the product's derivation. It accepts no
// arguments and no user seed input: every phrase is a published fixture phrase
// or explicitly synthetic public entropy. Output holds public values only (the
// fixture phrase, x-only K, 02||K and the seal script), never a private scalar.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	bip39 "github.com/tyler-smith/go-bip39"
)

// nip06Phrase is the published NIP-06 24-word test phrase.
const nip06Phrase = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"

type row struct {
	Phrase                  string `json:"phrase"`
	PublicKey               string `json:"public_key"`
	SealPublicKey           string `json:"seal_public_key"`
	SealScript              string `json:"seal_script"`
	OddYBeforeNormalization bool   `json:"odd_y_before_normalization"`
}

type document struct {
	Schema     string `json:"schema"`
	Profile    string `json:"profile"`
	Derivation string `json:"derivation"`
	Path       string `json:"path"`
	Rows       []row  `json:"rows"`
}

// fixturePhrases lists the published 24-word NIP-06 phrase and three 256-bit
// synthetic public entropies (zero, all-FF, sequential), the same synthetic
// inputs as the existing public recovery reference. The 12-word rows of that
// reference are omitted: the product entry point refuses 12 words.
func fixturePhrases() ([]string, error) {
	phrases := []string{nip06Phrase}
	for _, entropyHex := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	} {
		entropy, err := hex.DecodeString(entropyHex)
		if err != nil {
			return nil, err
		}
		phrase, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
		phrases = append(phrases, phrase)
	}
	return phrases, nil
}

func generate() (document, error) {
	doc := document{Schema: fixtureSchema, Profile: profile, Derivation: derivation, Path: pathText}
	phrases, err := fixturePhrases()
	if err != nil {
		return document{}, err
	}
	for _, phrase := range phrases {
		root, err := masterFromPhrase(phrase)
		if err != nil {
			return document{}, err
		}
		out, err := rootGrants(root)
		root.Zero()
		if err != nil {
			return document{}, err
		}
		doc.Rows = append(doc.Rows, row{
			Phrase: phrase, PublicKey: out.PublicKey, SealPublicKey: out.SealPublicKey,
			SealScript: out.SealScript, OddYBeforeNormalization: out.OddY,
		})
	}
	return doc, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "this fixture generator takes no input")
		return 2
	}
	doc, err := generate()
	if err != nil {
		fmt.Fprintln(stderr, "root grants reference generation failed")
		return 1
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if encoder.Encode(doc) != nil {
		fmt.Fprintln(stderr, "root grants reference generation failed")
		return 1
	}
	if _, err := stdout.Write(buffer.Bytes()); err != nil {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
