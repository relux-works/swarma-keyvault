package seedsetup

import (
	"os"
	"path/filepath"
)

const (
	vaultName    = "mac-keyvault"
	helperName   = "mac-keyvault-enclave"
	manifestName = "manifest.json"
	foreignDir   = "qualification"
)

// ArtifactPin authenticates both exact bytes and the signed macOS designated
// requirement. Hashes originate in the release build, not in caller input.
type ArtifactPin struct{ SHA256, CDHash string }

type Release struct {
	Version, Source, PlannerSource, ManifestSHA string
	Vault, Helper, Foreign                      ArtifactPin
}

func (r Release) validate() error {
	if !hexValue(r.Source, 20) || r.PlannerSource != r.Source {
		return refused("release_planner_source_mismatch")
	}
	if !hexValue(r.ManifestSHA, 32) {
		return refused("release_manifest_pin_missing")
	}
	for _, pin := range []ArtifactPin{r.Vault, r.Helper, r.Foreign} {
		if !hexValue(pin.SHA256, 32) || !hexValue(pin.CDHash, 20) {
			return refused("release_artifact_pin_missing")
		}
	}
	if r.Vault.CDHash == r.Foreign.CDHash || r.Vault.SHA256 == r.Foreign.SHA256 ||
		r.Helper.SHA256 == r.Vault.SHA256 || r.Helper.SHA256 == r.Foreign.SHA256 {
		return refused("release_artifact_pins_collide")
	}
	return nil
}

type installFile struct {
	relative string
	sha      string
	code     string
	mode     os.FileMode
}

type installation struct {
	paths     Paths
	release   Release
	uid       uint32
	fileOwner func(string, os.FileInfo) (uint32, bool)
}

func (p installation) files() []installFile {
	return []installFile{
		{vaultName, p.release.Vault.SHA256, p.release.Vault.CDHash, 0700},
		{helperName, p.release.Helper.SHA256, p.release.Helper.CDHash, 0700},
		{manifestName, p.release.ManifestSHA, "", 0600},
		{filepath.Join(foreignDir, vaultName), p.release.Foreign.SHA256, p.release.Foreign.CDHash, 0700},
		{filepath.Join(foreignDir, helperName), p.release.Helper.SHA256, p.release.Helper.CDHash, 0700},
	}
}

func (p installation) installParents() []string {
	return []string{p.paths.Root, p.paths.BinaryParent}
}

func (p installation) writePaths() []string {
	paths := append(p.installParents(), p.paths.InstallDirectory, filepath.Join(p.paths.InstallDirectory, foreignDir))
	for _, f := range p.files() {
		paths = append(paths, filepath.Join(p.paths.InstallDirectory, f.relative))
	}
	paths = append(paths, p.paths.LockParents...)
	return append(paths, p.paths.Lock)
}

func (p installation) sourceVault() string {
	return filepath.Join(p.paths.ArtifactDirectory, vaultName)
}

func (p installation) installedVault() string {
	return filepath.Join(p.paths.InstallDirectory, vaultName)
}

func (p installation) installedForeign() string {
	return filepath.Join(p.paths.InstallDirectory, foreignDir, vaultName)
}
