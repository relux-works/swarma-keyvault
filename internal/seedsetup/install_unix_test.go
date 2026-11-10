//go:build darwin || linux

package seedsetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func installFixture(t *testing.T) (installation, runner) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, source := filepath.Join(root, "fixture-home"), filepath.Join(root, "assets")
	for _, p := range []string{filepath.Join(home, "Library", "Application Support"), filepath.Join(source, foreignDir)} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(raw string) string {
		d := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(d[:])
	}
	release := Release{Version: "v0.2.0", Source: strings.Repeat("b", 40), ManifestSHA: hash("public manifest"),
		Vault: ArtifactPin{hash("vault bytes"), strings.Repeat("1", 40)}, Helper: ArtifactPin{hash("helper bytes"), strings.Repeat("2", 40)},
		Foreign: ArtifactPin{hash("foreign bytes"), strings.Repeat("3", 40)}}
	paths, err := UserPaths(home, filepath.Join(source, "keyvault-seed"), "", release.Version, release.Source)
	if err != nil || release.validate() != nil {
		t.Fatal(err)
	}
	payloads := []string{"vault bytes", "helper bytes", "public manifest", "foreign bytes", "helper bytes"}
	p := installation{paths: paths, release: release, uid: uint32(os.Getuid())}
	for i, f := range p.files() {
		if err := os.WriteFile(filepath.Join(source, f.relative), []byte(payloads[i]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// This is an injected inspection receipt. It never calls codesign.
	return p, func(binary string, args ...string) ([]byte, int) {
		if binary != "/usr/bin/codesign" || len(args) != 3 {
			t.Fatalf("unexpected non-fixture inspection: %s", binary)
		}
		switch args[0] {
		case "--verify":
			return nil, 0
		case "-d":
			raw, err := os.ReadFile(args[2])
			if err != nil {
				t.Fatal(err)
			}
			pins := map[string]ArtifactPin{"vault bytes": release.Vault, "helper bytes": release.Helper, "foreign bytes": release.Foreign}
			return []byte("# designated => cdhash H\"" + pins[string(raw)].CDHash + "\"\n"), 0
		}
		t.Fatal("unexpected inspection")
		return nil, -1
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected persistent effect: %s (%v)", filepath.Base(path), err)
	}
}

// An empty user install preflights without writes; installation creates the
// exact owner-private file set and refuses a repeat, preserving its bytes.
func TestFirstUserInstallAndRepeatRefusal(t *testing.T) {
	p, run := installFixture(t)
	if err := p.preflight(run); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, p.paths.Root)
	mustNotExist(t, p.paths.Lock)
	if err := p.install(run); err != nil {
		t.Fatal(err)
	}
	for _, f := range p.files() {
		path := filepath.Join(p.paths.InstallDirectory, f.relative)
		if ok, err := optionalOwned(path, p.uid, false, f.mode); !ok || err != nil {
			t.Fatal("wrong installed mode/ownership", err)
		}
		if err := p.verifyFile(path, f, run); err != nil {
			t.Fatal(err)
		}
	}
	mustNotExist(t, p.paths.Lock)
	if err := p.install(run); err == nil || err.Error() != "install_destination_already_exists" {
		t.Fatal("existing release was not protected", err)
	}
	for _, f := range p.files() {
		if err := p.verifyFile(filepath.Join(p.paths.InstallDirectory, f.relative), f, run); err != nil {
			t.Fatal("repeat altered installed release", err)
		}
	}
}

// Foreign-owned, wrong-hash, wrong-code, symlink and unsafe-mode controls
// are all refusals before creation of any install or lock destination.
func TestPreflightUnsafeInputsNoWrites(t *testing.T) {
	for _, mode := range []string{"wrong-uid", "bad-hash", "wrong-code", "source-link", "lock-link", "unsafe-install-parent"} {
		t.Run(mode, func(t *testing.T) {
			p, run := installFixture(t)
			want := ""
			switch mode {
			case "wrong-uid":
				p.uid++
				want = "directory_chain_unsafe"
				if os.Getuid() == 0 {
					want = "home_ownership"
				}
			case "bad-hash":
				p.release.Helper.SHA256 = strings.Repeat("d", 64)
				want = "release_artifact_hash"
			case "wrong-code":
				p.release.Vault.CDHash = strings.Repeat("c", 40)
				want = "release_artifact_code_identity"
			case "source-link":
				source := filepath.Join(p.paths.ArtifactDirectory, helperName)
				if err := os.Rename(source, source+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source+".target", source); err != nil {
					t.Fatal(err)
				}
				want = "release_artifact_unavailable"
			case "lock-link":
				if err := os.MkdirAll(filepath.Dir(p.paths.Lock), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.sourceVault(), p.paths.Lock); err != nil {
					t.Fatal(err)
				}
				want = "private_path_unsafe"
			case "unsafe-install-parent":
				if err := os.Mkdir(p.paths.Root, 0755); err != nil {
					t.Fatal(err)
				}
				want = "private_path_unsafe"
			}
			if err := p.preflight(run); err == nil || err.Error() != want {
				t.Fatal("wrong refusal", err, want)
			}
			mustNotExist(t, p.paths.InstallDirectory)
			if mode != "lock-link" {
				mustNotExist(t, p.paths.Lock)
			}
		})
	}
}

// A full preflight and the first correct retype do not enable writes. The
// second name must match before install starts; no qualification runs early.
func TestSetupStopsBeforeAnyWriteOnSecondIdentityRefusal(t *testing.T) {
	for _, mode := range []string{"second-wrong", "second-eof", "second-right"} {
		t.Run(mode, func(t *testing.T) {
			p, code := installFixture(t)
			actual := publicTarget{"north", "south", 3, 5, 7}
			qual := publicTarget{"fixture-north", "fixture-south", 1, 1, 1}
			ids := Identities{actual.NostrIdentity, actual.NamecoinIdentity, qual.NostrIdentity, qual.NamecoinIdentity}
			plans, prompts, restores := 0, 0, 0
			plan := func(target publicTarget) []byte {
				return successReply(t, "recovery", publicPlan{"keyvault-recovery-plan/1", true,
					target.NostrIdentity, target.NamecoinIdentity, target.Version, target.NostrVersion, target.NamecoinVersion,
					target.group(), target.nostr(), target.namecoin()})
			}
			var out bytes.Buffer
			w := workflow{out: &out, run: func(binary string, args ...string) ([]byte, int) {
				if binary == "/usr/bin/codesign" {
					return code(binary, args...)
				}
				if binary != p.sourceVault() || len(args) < 3 || !reflect.DeepEqual(args[:3], []string{"--json", "recovery", "plan"}) {
					t.Fatal("non-plan command ran before qualification")
				}
				plans++
				if plans == 1 {
					if !reflect.DeepEqual(args[3:], []string{"--nostr-identity", actual.NostrIdentity, "--namecoin-identity", actual.NamecoinIdentity}) {
						t.Fatal("actual advisory plan changed")
					}
					return plan(actual), 0
				}
				if plans != 2 || !reflect.DeepEqual(args[3:], qual.mutationArguments()) {
					t.Fatal("qualification advisory plan changed")
				}
				return plan(qual), 0
			}, prompt: func(_ string, _ int) (string, error) {
				prompts++
				mustNotExist(t, p.paths.Root)
				mustNotExist(t, p.paths.Lock)
				if prompts == 1 {
					return actual.NostrIdentity, nil
				}
				switch mode {
				case "second-wrong":
					return actual.NostrIdentity, nil
				case "second-eof":
					return "", io.EOF
				}
				return actual.NamecoinIdentity, nil
			}, restore: func(binary string, got publicTarget) ([]byte, int) {
				restores++
				if got != qual || binary != p.installedVault() {
					t.Fatal("restore changed confirmed address/install")
				}
				if _, err := os.Stat(p.installedVault()); err != nil {
					t.Fatal("restore started before install", err)
				}
				return nil, -1
			}}
			err := execute(context.Background(), p, w, Config{NostrIdentity: actual.NostrIdentity, NamecoinIdentity: actual.NamecoinIdentity}, ids)
			if plans != 2 || prompts != 2 || out.Len() != 0 {
				t.Fatal("unexpected preflight effects", plans, prompts, out.Len())
			}
			if mode == "second-right" {
				if restores != 1 || err == nil || err.Error() != unknownMutation {
					t.Fatal("valid positive stopped at wrong boundary", restores, err)
				}
			} else {
				if restores != 0 || err == nil || err.Error() != "identity_confirmation_refused" {
					t.Fatal("invalid confirmation started custody", fmt.Sprint(err), restores)
				}
				mustNotExist(t, p.paths.Root)
			}
			mustNotExist(t, p.paths.Lock)
		})
	}
}
