// Command keyvault-seed runs the attended macOS recovery setup for two
// explicitly chosen identities. Its only exported results are public.
package main

import (
	"os"

	"github.com/relux-works/swarma-keyvault/internal/seedsetup"
)

// Populated by the release packager after the matched pair is built and signed.
// A source build with no release pins cannot start an attended setup.
var releaseVersion, releaseSource, releasePlannerSource, releaseManifestSHA string
var releaseVaultSHA, releaseVaultCDHash string
var releaseHelperSHA, releaseHelperCDHash string
var releaseForeignSHA, releaseForeignCDHash string

func main() {
	os.Exit(seedsetup.Run(os.Args[1:], seedsetup.Release{
		Version: releaseVersion, Source: releaseSource, PlannerSource: releasePlannerSource, ManifestSHA: releaseManifestSHA,
		Vault:   seedsetup.ArtifactPin{SHA256: releaseVaultSHA, CDHash: releaseVaultCDHash},
		Helper:  seedsetup.ArtifactPin{SHA256: releaseHelperSHA, CDHash: releaseHelperCDHash},
		Foreign: seedsetup.ArtifactPin{SHA256: releaseForeignSHA, CDHash: releaseForeignCDHash},
	}, os.Stdout, os.Stderr))
}
