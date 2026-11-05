package muinterop

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Claim: test keys derive only from their published seeds: the same name
// gives the same key id on every run, the seed is SHA-256 of the published
// label, and different names give different keys.
func TestPublishedSeeds(t *testing.T) {
	a, err := P256("grant-root")
	if err != nil {
		t.Fatal(err)
	}
	b, err := P256("grant-root")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("swarma-keyvault mu-interop seed/1 grant-root"))
	if a.ID != b.ID || hex.EncodeToString(a.Seed) != hex.EncodeToString(want[:]) {
		t.Fatal("seed derivation not reproducible")
	}
	seen := map[string]string{}
	for _, n := range KeyNames {
		k, err := P256(n)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[k.ID]; dup {
			t.Fatal("two names share a key", n, other)
		}
		seen[k.ID] = n
	}
}

// Claim: the Mac family has unique ids in the case format, every negative
// names a positive control present in the family, and every case has at
// least one step with an expected verdict.
func TestMacFamilyShape(t *testing.T) {
	cases, err := MacFamily()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range cases {
		if c.Format != Format || ids[c.ID] || len(c.Steps) == 0 {
			t.Fatal("bad case", c.ID)
		}
		ids[c.ID] = true
		for _, s := range c.Steps {
			if s.Expected == "" || s.Event == "" || s.Snapshot == "" {
				t.Fatal("incomplete step", c.ID)
			}
		}
	}
	for _, c := range cases {
		if c.PositiveControl != "" && !ids[c.PositiveControl] {
			t.Fatal("missing positive control", c.ID, c.PositiveControl)
		}
	}
	if len(cases) < 14 {
		t.Fatal("family shrank", len(cases))
	}
}
