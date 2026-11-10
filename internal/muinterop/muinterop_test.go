package muinterop

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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
	cases, err := MacFamily("owner:fixture-owner")
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

// Claim: the Linux family has unique ids distinct from the Mac family, Linux
// pins and registry evidence on every case, an agent snapshot on every step,
// and every negative names a positive control present in the family.
func TestLinuxFamilyShape(t *testing.T) {
	mac, err := MacFamily("owner:fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	linux, err := LinuxFamily("owner:fixture-owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range mac {
		ids[c.ID] = true
	}
	own := map[string]bool{}
	for _, c := range linux {
		if ids[c.ID] || own[c.ID] || c.Pins.Linux == nil || c.Registry == nil || len(c.Steps) == 0 {
			t.Fatal("bad linux case", c.ID)
		}
		own[c.ID] = true
		for _, s := range c.Steps {
			if s.AgentSnapshot == "" || s.Expected == "" {
				t.Fatal("incomplete linux step", c.ID)
			}
		}
	}
	for _, c := range linux {
		if c.PositiveControl != "" && !own[c.PositiveControl] {
			t.Fatal("missing positive control", c.ID)
		}
	}
	if len(linux) < 10 {
		t.Fatal("linux family shrank", len(linux))
	}
}

// Claim: the Ed25519 publisher family has ids distinct from the Mac and Linux
// families, an Ed25519 publisher key pin on its positive control, and every
// negative names a positive control present in the family.
func TestPublisherEd25519FamilyShape(t *testing.T) {
	ids := map[string]bool{}
	for _, f := range []func() ([]Case, error){MacFamily, LinuxFamily} {
		cs, err := f()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			ids[c.ID] = true
		}
	}
	p2, err := PublisherEd25519Family("owner:fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	own := map[string]Case{}
	for _, c := range p2 {
		if _, dup := own[c.ID]; ids[c.ID] || dup || len(c.Steps) == 0 {
			t.Fatal("bad publisher-ed25519 case", c.ID)
		}
		own[c.ID] = c
	}
	accept, ok := own["P2-P-accept"]
	if !ok || !strings.HasPrefix(accept.Pins.PublisherKey, "ed25519:") {
		t.Fatal("positive control missing or not an Ed25519 publisher")
	}
	for _, c := range p2 {
		if c.PositiveControl != "" {
			if _, ok := own[c.PositiveControl]; !ok {
				t.Fatal("missing positive control", c.ID)
			}
		}
	}
}
