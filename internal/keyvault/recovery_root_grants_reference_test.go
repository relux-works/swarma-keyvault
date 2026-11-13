package keyvault

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// The expected index-7 values in testdata/recovery/reference-root-grants.json
// were produced by the isolated tools/recoveryreference/rootgrants module
// (unmodified upstream BIP-39/BIP-32/secp256k1, grounded in the published BIP85
// index-0 vectors, BIP340 and NIP-06 rows) and are regenerated and diffed byte
// for byte in hosted CI. They were NEVER produced by, or copied from, this
// package's derivation. All phrases are published or synthetic public inputs.
const rootGrantsReferencePath = "testdata/recovery/reference-root-grants.json"

type rootGrantsReferenceRow struct {
	Phrase                  string `json:"phrase"`
	PublicKey               string `json:"public_key"`
	SealPublicKey           string `json:"seal_public_key"`
	SealScript              string `json:"seal_script"`
	OddYBeforeNormalization bool   `json:"odd_y_before_normalization"`
}

type rootGrantsReferenceDocument struct {
	Schema     string                   `json:"schema"`
	Profile    string                   `json:"profile"`
	Derivation string                   `json:"derivation"`
	Path       string                   `json:"path"`
	Rows       []rootGrantsReferenceRow `json:"rows"`
}

var (
	rootGrantsReferenceHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootGrantsReferenceScript = regexp.MustCompile(`^76a914[0-9a-f]{40}88ac$`)
)

var errRootGrantsReference = errors.New("root grants reference fixture refused")

// parseRootGrantsReference is a closed loader: the schema, the profile
// identifiers and every field shape are fixed, unknown fields and trailing data
// are refused, and the rows must cover both Y parities so that the even-Y
// normalization is actually exercised by the fixture.
func parseRootGrantsReference(raw []byte) (rootGrantsReferenceDocument, error) {
	var doc rootGrantsReferenceDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return rootGrantsReferenceDocument{}, errRootGrantsReference
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return rootGrantsReferenceDocument{}, errRootGrantsReference
	}
	// The header restates the contract independently of the product constants;
	// the equality with the product constants is asserted separately below.
	if doc.Schema != "keyvault-root-grants-reference/1" || doc.Profile != "namecoin-landlord-root/1" ||
		doc.Derivation != "bip85-hdseed-wif/1" || doc.Path != "m/83696968h/2h/7h" || len(doc.Rows) < 4 {
		return rootGrantsReferenceDocument{}, errRootGrantsReference
	}
	seen := map[string]bool{}
	var odd, even int
	for _, r := range doc.Rows {
		if seen[r.Phrase] || len(strings.Split(r.Phrase, " ")) != 24 ||
			!rootGrantsReferenceHex64.MatchString(r.PublicKey) || r.SealPublicKey != "02"+r.PublicKey ||
			!rootGrantsReferenceScript.MatchString(r.SealScript) {
			return rootGrantsReferenceDocument{}, errRootGrantsReference
		}
		seen[r.Phrase] = true
		if r.OddYBeforeNormalization {
			odd++
		} else {
			even++
		}
	}
	if odd == 0 || even == 0 || !seen[recoveryFixturePhrase] {
		return rootGrantsReferenceDocument{}, errRootGrantsReference
	}
	return doc, nil
}

func loadRootGrantsReference(t *testing.T) (rootGrantsReferenceDocument, []byte) {
	t.Helper()
	raw, err := os.ReadFile(rootGrantsReferencePath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseRootGrantsReference(raw)
	if err != nil {
		t.Fatal("committed reference fixture refused by its own loader")
	}
	return doc, raw
}

// rootGrantsReferenceMismatch compares the product's public view with one
// independently generated row. It returns nil only when profile, derivation,
// path, x-only K, seal public key and seal script all agree.
func rootGrantsReferenceMismatch(doc rootGrantsReferenceDocument, row rootGrantsReferenceRow, got RootGrantsPublic) error {
	if got.Profile != doc.Profile || got.Derivation != doc.Derivation || got.Path != doc.Path ||
		got.PublicKey != row.PublicKey || got.SealPublicKey != row.SealPublicKey || got.SealScript != row.SealScript {
		return errRootGrantsReference
	}
	return nil
}

func rootGrantsReferenceRowFor(t *testing.T, doc rootGrantsReferenceDocument, phrase string) rootGrantsReferenceRow {
	t.Helper()
	for _, r := range doc.Rows {
		if r.Phrase == phrase {
			return r
		}
	}
	t.Fatal("fixture phrase missing from the reference")
	return rootGrantsReferenceRow{}
}

func rootGrantsReferenceMaster(t *testing.T, phrase string) recoveryNode {
	t.Helper()
	seed := pbkdf2.Key([]byte(phrase), []byte("mnemonic"), 2048, 64, sha512.New)
	defer clear(seed)
	root, err := masterRecoveryNode(seed)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// Claim: the closed fixture loader accepts the committed independently
// generated document, and the product's fixed profile identifiers equal the
// identifiers the oracle restated on its own. Limit: header equality only.
func TestRootGrantsReferenceFixtureAndProfile(t *testing.T) {
	doc, _ := loadRootGrantsReference(t)
	if doc.Profile != rootGrantsProfile || doc.Derivation != rootGrantsDerivation || doc.Path != rootGrantsPath {
		t.Fatal("product profile identifiers differ from the independent reference")
	}
}

// Claim: for EVERY independently generated phrase (the published NIP-06
// 24-word phrase and three synthetic 256-bit public entropies, covering both
// Y parities) the product's fixed index-7 derivation, from the BIP-39 phrase
// through the BIP32 master, the BIP85 transform and even-Y normalization,
// yields exactly the reference x-only K, 02||K and seal script. The product
// also accepts each phrase as valid BIP-39 input. Limit: these are four public
// inputs, not a proof for arbitrary seeds; the primitives are anchored by the
// official BIP85/BIP32/BIP340/NIP-06 vectors in their own tests.
func TestRootGrantsIndex7MatchesIndependentReference(t *testing.T) {
	doc, _ := loadRootGrantsReference(t)
	for _, row := range doc.Rows {
		t.Run(row.PublicKey[:8], func(t *testing.T) {
			material, err := deriveRecovery([]byte(row.Phrase))
			material.clear()
			if err != nil {
				t.Fatal("product refused a valid 24-word fixture phrase")
			}
			root := rootGrantsReferenceMaster(t, row.Phrase)
			defer root.clear()
			p, err := prepareRootGrantsFromMaster(&root)
			if err != nil {
				t.Fatal(err)
			}
			defer p.clear()
			view, err := p.publicView()
			if err != nil {
				t.Fatal(err)
			}
			if rootGrantsReferenceMismatch(doc, row, view.Root) != nil {
				t.Fatal("product index-7 output disagrees with the independent reference")
			}
		})
	}
}

// Claim: the real attach entry point (retained-record pins first, then the
// third leaf) produces the reference value for the published NIP-06 phrase on
// both retained pair schemas. Limit: only the NIP-06 phrase has a retained pair
// record, so only it can pass the pin gate; no native custody is exercised.
func TestRootGrantsAttachMatchesIndependentReference(t *testing.T) {
	doc, _ := loadRootGrantsReference(t)
	row := rootGrantsReferenceRowFor(t, doc, recoveryFixturePhrase)
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		raw, expected := rootGrantsTestPair(t, schema)
		p, err := prepareRootGrantsAttach(context.Background(), []byte(recoveryFixturePhrase), raw, expected)
		if err != nil {
			t.Fatal(err)
		}
		view, err := p.publicView()
		p.clear()
		if err != nil || rootGrantsReferenceMismatch(doc, row, view.Root) != nil {
			t.Fatalf("attach output for %s disagrees with the independent reference", schema)
		}
	}
}

func rootGrantsReferenceFlip(s string) string {
	b := []byte(s)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	return string(b)
}

// Claim: the comparison has teeth in both directions. The unmutated pair
// agrees (so rejecting everything fails), and each single-field mutation of
// the reference, a swapped row, and every plausible wrong product derivation of
// the SAME phrase (index 0, 6 and 8, another application, the raw BIP32 child,
// the last 32 entropy bytes) disagrees with the reference K, while the same
// plant harness at index 7 reproduces the reference K. Limit: a bounded set of
// plants, not exhaustive mutation testing.
func TestRootGrantsReferenceComparisonDetectsWrongDerivations(t *testing.T) {
	doc, _ := loadRootGrantsReference(t)
	row := rootGrantsReferenceRowFor(t, doc, recoveryFixturePhrase)
	root := rootGrantsReferenceMaster(t, recoveryFixturePhrase)
	defer root.clear()
	p, err := prepareRootGrantsFromMaster(&root)
	if err != nil {
		t.Fatal(err)
	}
	defer p.clear()
	view, err := p.publicView()
	if err != nil {
		t.Fatal(err)
	}
	if rootGrantsReferenceMismatch(doc, row, view.Root) != nil {
		t.Fatal("positive control: product and reference must agree")
	}
	mutants := map[string]func(*rootGrantsReferenceRow){
		"public key":      func(r *rootGrantsReferenceRow) { r.PublicKey = rootGrantsReferenceFlip(r.PublicKey) },
		"odd seal prefix": func(r *rootGrantsReferenceRow) { r.SealPublicKey = "03" + r.PublicKey },
		"seal key":        func(r *rootGrantsReferenceRow) { r.SealPublicKey = rootGrantsReferenceFlip(r.SealPublicKey) },
		"script":          func(r *rootGrantsReferenceRow) { r.SealScript = rootGrantsReferenceFlip(r.SealScript) },
		"swapped row": func(r *rootGrantsReferenceRow) {
			for _, other := range doc.Rows {
				if other.Phrase != r.Phrase {
					*r = other
					return
				}
			}
		},
	}
	for name, mutate := range mutants {
		changed := row
		mutate(&changed)
		if changed == row {
			t.Fatalf("mutant %q was not applied", name)
		}
		if rootGrantsReferenceMismatch(doc, changed, view.Root) == nil {
			t.Fatalf("mutant %q accepted", name)
		}
	}
	for name, header := range map[string]func(*RootGrantsPublic){
		"profile":    func(r *RootGrantsPublic) { r.Profile = "other" },
		"derivation": func(r *RootGrantsPublic) { r.Derivation = "other" },
		"path":       func(r *RootGrantsPublic) { r.Path = "m/83696968h/2h/0h" },
	} {
		changed := view.Root
		header(&changed)
		if rootGrantsReferenceMismatch(doc, row, changed) == nil {
			t.Fatalf("product header mutant %q accepted", name)
		}
	}
	xonly := func(scalar []byte) string {
		key, err := nostrPrivate(scalar)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Zero()
		return hex.EncodeToString(key.PubKey().SerializeCompressed()[1:])
	}
	plant := func(path []uint32, mode string) string {
		child, err := root.path(path)
		if err != nil {
			t.Fatal(err)
		}
		defer child.clear()
		entropy, err := rootGrantsBIP85Entropy(child.key[:])
		if err != nil {
			t.Fatal(err)
		}
		defer clear(entropy[:])
		switch mode {
		case "raw":
			return xonly(child.key[:])
		case "last32":
			return xonly(entropy[32:])
		default:
			return xonly(entropy[:32])
		}
	}
	const purpose = 0x80000000 | 83696968
	if got := plant([]uint32{purpose, 0x80000002, 0x80000007}, "first32"); got != row.PublicKey {
		t.Fatal("positive control: plant harness at index 7 must reproduce the reference K")
	}
	for name, got := range map[string]string{
		"index 0":       plant([]uint32{purpose, 0x80000002, 0x80000000}, "first32"),
		"index 6":       plant([]uint32{purpose, 0x80000002, 0x80000006}, "first32"),
		"index 8":       plant([]uint32{purpose, 0x80000002, 0x80000008}, "first32"),
		"application 1": plant([]uint32{purpose, 0x80000001, 0x80000007}, "first32"),
		"raw child":     plant([]uint32{purpose, 0x80000002, 0x80000007}, "raw"),
		"last 32 bytes": plant([]uint32{purpose, 0x80000002, 0x80000007}, "last32"),
	} {
		if got == row.PublicKey {
			t.Fatalf("wrong derivation %q equals the reference K", name)
		}
	}
}

func rootGrantsReferenceReplace(t *testing.T, raw []byte, old, replacement string, count int) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(old)) < 1 {
		t.Fatalf("plant %q not found in the committed fixture", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), count)
}

// Claim: the closed loader refuses every malformed variant of the committed
// fixture with the fixed refusal: unknown field, trailing data, wrong schema or
// path, uppercase or short K, seal key without the 02 prefix, malformed script,
// duplicate phrase, a 12-word phrase, and loss of either Y-parity coverage.
// Each plant is verified to have changed the bytes; the unmodified file passes.
// Limit: shape and coverage only; values are checked against the product by the
// comparison tests, not by this loader.
func TestRootGrantsReferenceLoaderRefusesMalformedFixtures(t *testing.T) {
	doc, raw := loadRootGrantsReference(t)
	first := doc.Rows[0]
	if _, err := parseRootGrantsReference(raw); err != nil {
		t.Fatal("positive control: committed fixture refused")
	}
	for name, mutate := range map[string]func() []byte{
		"unknown field": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"path": `, `"extra": 1, "path": `, 1)
		},
		"trailing data": func() []byte { return append(bytes.Clone(raw), []byte("{}")...) },
		"wrong schema": func() []byte {
			return rootGrantsReferenceReplace(t, raw, "keyvault-root-grants-reference/1", "keyvault-root-grants-reference/2", 1)
		},
		"wrong path": func() []byte {
			return rootGrantsReferenceReplace(t, raw, "m/83696968h/2h/7h", "m/83696968h/2h/0h", 1)
		},
		"wrong profile": func() []byte {
			return rootGrantsReferenceReplace(t, raw, "namecoin-landlord-root/1", "namecoin-landlord-root/2", 1)
		},
		"uppercase K": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"public_key": "`+first.PublicKey+`"`, `"public_key": "`+strings.ToUpper(first.PublicKey)+`"`, 1)
		},
		"short K": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"public_key": "`+first.PublicKey+`"`, `"public_key": "`+first.PublicKey[:62]+`"`, 1)
		},
		"odd seal prefix": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"seal_public_key": "02`+first.PublicKey, `"seal_public_key": "03`+first.PublicKey, 1)
		},
		"truncated script": func() []byte {
			return rootGrantsReferenceReplace(t, raw, first.SealScript, first.SealScript[:len(first.SealScript)-2], 1)
		},
		"duplicate phrase": func() []byte {
			return rootGrantsReferenceReplace(t, raw, doc.Rows[1].Phrase, first.Phrase, 1)
		},
		"12-word phrase": func() []byte {
			return rootGrantsReferenceReplace(t, raw, doc.Rows[1].Phrase, strings.Join(strings.Split(doc.Rows[1].Phrase, " ")[:12], " "), 1)
		},
		"no odd-Y coverage": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"odd_y_before_normalization": true`, `"odd_y_before_normalization": false`, -1)
		},
		"no even-Y coverage": func() []byte {
			return rootGrantsReferenceReplace(t, raw, `"odd_y_before_normalization": false`, `"odd_y_before_normalization": true`, -1)
		},
	} {
		mutated := mutate()
		if bytes.Equal(mutated, raw) {
			t.Fatalf("plant %q was not applied", name)
		}
		if _, err := parseRootGrantsReference(mutated); !errors.Is(err, errRootGrantsReference) {
			t.Fatalf("malformed fixture %q admitted", name)
		}
	}
}
