package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const publicQualifier = "qualification/mac-keyvault"

var seedVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var sha1Pattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type seedManifest struct {
	manifest
	Version string   `json:"release_version"`
	Foreign artifact `json:"public_qualification"`
}

// Each value is validated before joining the linker's own argument syntax.
// No path, spaces, caller string or environment becomes a linker expression.
func seedLinkerFlags(m seedManifest, manifestSHA string) (string, error) {
	if !seedVersionPattern.MatchString(m.Version) || !sha1Pattern.MatchString(m.Head) ||
		!sha1Pattern.MatchString(m.Tree) || !sha256Pattern.MatchString(manifestSHA) {
		return "", errors.New("invalid seed release pins")
	}
	for _, a := range []artifact{m.Vault, m.Helper, m.Foreign} {
		if !sha1Pattern.MatchString(a.CDHash) || !sha256Pattern.MatchString(a.SHA256) {
			return "", errors.New("invalid seed artifact pins")
		}
	}
	if m.Vault.CDHash == m.Foreign.CDHash || m.Vault.SHA256 == m.Foreign.SHA256 ||
		m.Helper.SHA256 == m.Vault.SHA256 || m.Helper.SHA256 == m.Foreign.SHA256 {
		return "", errors.New("seed artifact pins collide")
	}
	pins := [][2]string{
		{"releaseVersion", m.Version},
		{"releaseSource", m.Head},
		{"releaseManifestSHA", manifestSHA},
		{"releaseVaultSHA", m.Vault.SHA256},
		{"releaseVaultCDHash", m.Vault.CDHash},
		{"releaseHelperSHA", m.Helper.SHA256},
		{"releaseHelperCDHash", m.Helper.CDHash},
		{"releaseForeignSHA", m.Foreign.SHA256},
		{"releaseForeignCDHash", m.Foreign.CDHash},
	}
	var flags []string
	for _, pin := range pins {
		flags = append(flags, "-X", "main."+pin[0]+"="+pin[1])
	}
	return strings.Join(flags, " "), nil
}

func buildSeedBundle(ctx context.Context, log io.Writer, goTool, out, version, head, tree, swift, link string, vault, helper artifact) error {
	if err := os.Mkdir(filepath.Join(out, "qualification"), 0700); err != nil {
		return err
	}
	foreignPath := filepath.Join(out, filepath.FromSlash(publicQualifier))
	if _, err := command(ctx, log, goTool, "build", "-trimpath", "-ldflags", link+" -X main.recoveryQualificationOnly=1", "-o", foreignPath, "./cmd/mac-keyvault"); err != nil {
		return err
	}
	if _, err := command(ctx, log, "/usr/bin/codesign", "-s", "-", "--force", "--options", "runtime", "--timestamp=none", "--identifier", "works.relux.mac-keyvault.qualification-foreign", foreignPath); err != nil {
		return err
	}
	foreign, err := inspect(ctx, log, foreignPath)
	if err != nil {
		return err
	}
	helperCopy := filepath.Join(out, "qualification", "mac-keyvault-enclave")
	helperBytes, err := os.ReadFile(helper.Path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(helperCopy, helperBytes, 0700); err != nil {
		return err
	}
	vault.Path, helper.Path, foreign.Path = "mac-keyvault", "mac-keyvault-enclave", publicQualifier
	m := seedManifest{manifest: manifest{
		Schema: "keyvault-seed-build/1", Head: head, Tree: tree, Go: runtime.Version(), Swift: swift, Vault: vault, Helper: helper,
	}, Version: version, Foreign: foreign}
	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	sum := sha256.Sum256(encoded)
	manifestSHA := hex.EncodeToString(sum[:])
	flags, err := seedLinkerFlags(m, manifestSHA)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), encoded, 0600); err != nil {
		return err
	}
	seed := filepath.Join(out, "keyvault-seed")
	if _, err := command(ctx, log, goTool, "build", "-trimpath", "-ldflags", flags, "-o", seed, "./cmd/keyvault-seed"); err != nil {
		return err
	}
	if _, err := command(ctx, log, "/usr/bin/codesign", "-s", "-", "--force", "--options", "runtime", "--timestamp=none", seed); err != nil {
		return err
	}
	s, err := inspect(ctx, log, seed)
	if err != nil {
		return err
	}
	var sums strings.Builder
	for _, a := range []struct{ name, sha string }{
		{"keyvault-seed", s.SHA256}, {vault.Path, vault.SHA256}, {helper.Path, helper.SHA256},
		{"manifest.json", manifestSHA}, {foreign.Path, foreign.SHA256}, {"qualification/mac-keyvault-enclave", helper.SHA256},
	} {
		fmt.Fprintf(&sums, "%s  %s\n", a.sha, a.name)
	}
	if err := os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(sums.String()), 0600); err != nil {
		return err
	}
	fmt.Println(filepath.Join(out, "SHA256SUMS"))
	return nil
}
