package main

import (
	"strings"
	"testing"
)

// The packager embeds the pinned manifest, selected source and exact three
// code identities; untrusted linker syntax and a reused vault identity refuse.
func TestSeedBundleLinkPins(t *testing.T) {
	hash := func(s string) string { return strings.Repeat(s, 64) }
	code := func(s string) string { return strings.Repeat(s, 40) }
	asset := func(s string) artifact { return artifact{SHA256: hash(s), CDHash: code(s)} }
	base := seedManifest{manifest: manifest{Head: code("1"), Tree: code("2"), Vault: asset("3"), Helper: asset("4")}, Version: "v0.2.0", PlannerSource: code("1"), Foreign: asset("5")}
	pins, err := seedLinkerFlags(base, hash("6"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"main.releaseVersion=v0.2.0", "main.releaseSource=" + code("1"),
		"main.releasePlannerSource=" + code("1"), "main.releaseManifestSHA=" + hash("6"), "main.releaseVaultCDHash=" + code("3"),
		"main.releaseHelperSHA=" + hash("4"), "main.releaseForeignCDHash=" + code("5")} {
		if !strings.Contains(pins, "-X "+expected) {
			t.Fatal("pin omitted", expected)
		}
	}
	for _, change := range []func(*seedManifest){
		func(m *seedManifest) { m.Version = "v0.2.0 -X main.other=value" },
		func(m *seedManifest) { m.Head = "branch" },
		func(m *seedManifest) { m.PlannerSource = code("7") },
		func(m *seedManifest) { m.PlannerSource = "" },
		func(m *seedManifest) { m.Foreign.CDHash = m.Vault.CDHash },
		func(m *seedManifest) { m.Foreign.SHA256 = m.Vault.SHA256 },
	} {
		m := base
		change(&m)
		if got, err := seedLinkerFlags(m, hash("6")); err == nil || got != "" {
			t.Fatal("unsafe linker pins admitted")
		}
	}
	if got, err := seedLinkerFlags(base, "unverified manifest"); err == nil || got != "" {
		t.Fatal("unverified manifest admitted")
	}
}
