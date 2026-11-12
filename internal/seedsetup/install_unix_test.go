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
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
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
	release := Release{Version: "v0.2.0", Source: strings.Repeat("b", 40), PlannerSource: strings.Repeat("b", 40), ManifestSHA: hash("public manifest"),
		Vault: ArtifactPin{hash("vault bytes"), strings.Repeat("1", 40)}, Helper: ArtifactPin{hash("helper bytes"), strings.Repeat("2", 40)},
		Foreign: ArtifactPin{hash("foreign bytes"), strings.Repeat("3", 40)}}
	paths, err := UserPaths(home, filepath.Join(source, "keyvault-seed"), "", release.Version, release.Source)
	if err != nil || release.validate() != nil {
		t.Fatal(err)
	}
	payloads := []string{"vault bytes", "helper bytes", "public manifest", "foreign bytes", "helper bytes"}
	p := installation{paths: paths, release: release, uid: uint32(os.Getuid()), certificateFile: func(string, codesignpolicy.Role) error { return nil }}
	for i, f := range p.files() {
		if err := os.WriteFile(filepath.Join(source, f.relative), []byte(payloads[i]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// These injected command and certificate receipts prove orchestration and
	// software admission only. No actual codesign, chain, DER or OS check runs.
	return p, func(binary string, args ...string) invocation {
		if binary != "/usr/bin/codesign" || len(args) < 3 {
			t.Fatalf("unexpected non-fixture inspection: %s", binary)
		}
		if args[0] == "--verify" {
			return invocation{exit: 0, started: true}
		}
		if args[0] != "-d" {
			t.Fatal("unexpected inspection")
		}
		raw, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			t.Fatal(err)
		}
		pins := map[string]ArtifactPin{"vault bytes": release.Vault, "helper bytes": release.Helper, "foreign bytes": release.Foreign}
		roles := map[string]codesignpolicy.Role{"vault bytes": codesignpolicy.Vault, "helper bytes": codesignpolicy.Helper, "foreign bytes": codesignpolicy.Qualification}
		pin, ok := pins[string(raw)]
		if !ok {
			t.Fatal("unknown fixture asset")
		}
		role := roles[string(raw)]
		id, _ := codesignpolicy.Identifier(role)
		switch args[1] {
		case "-r-":
			dr, _ := codesignpolicy.Requirement(role)
			return invocation{raw: []byte(dr + "\n"), exit: 0, started: true}
		case "--verbose=4":
			return invocation{raw: []byte("Identifier=" + id + "\nTeamIdentifier=262RZ595FP\nCodeDirectory v=20500 size=700 flags=0x10000(runtime) hashes=1\nCDHash=" + pin.CDHash + "\n"), exit: 0, started: true}
		case "--entitlements":
			return invocation{exit: 0, started: true}
		default:
			t.Fatal("unexpected inspection")
		}
		return invocation{exit: -1, started: true}
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
		if ok, err := p.optionalOwned(path, false, f.mode); !ok || err != nil {
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
				// Plant the forbidden permission explicitly: a restrictive
				// inherited umask must not turn this negative into mode0700.
				if err := os.Chmod(p.paths.Root, 0755); err != nil {
					t.Fatal(err)
				}
				if st, err := os.Stat(p.paths.Root); err != nil || st.Mode().Perm() != 0755 {
					t.Fatal("unsafe-mode plant not applied")
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

			var out bytes.Buffer
			w := workflow{out: &out, run: func(binary string, args ...string) invocation {
				if binary != "/usr/bin/codesign" {
					t.Fatal("source vault launched before consent")
				}
				return code(binary, args...)
			}, planner: plannerFunc(func(q keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
				plans++
				if plans == 1 {
					if q != (keyvault.RecoveryRequest{NostrIdentity: actual.NostrIdentity, NamecoinIdentity: actual.NamecoinIdentity}) {
						t.Fatal("actual advisory plan changed")
					}
					return fixturePlan(actual), nil
				}
				if plans != 2 || q != (keyvault.RecoveryRequest{NostrIdentity: qual.NostrIdentity, NamecoinIdentity: qual.NamecoinIdentity, Version: 1, NostrVersion: 1, NamecoinVersion: 1}) {
					t.Fatal("qualification advisory plan changed")
				}
				return fixturePlan(qual), nil
			}), prompt: func(_ string, _ int) (string, error) {
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
			}, restore: func(binary string, got publicTarget) invocation {
				restores++
				if got != qual || binary != p.installedVault() {
					t.Fatal("restore changed confirmed address/install")
				}
				if _, err := os.Stat(p.installedVault()); err != nil {
					t.Fatal("restore started before install", err)
				}
				return invocation{raw: nil, exit: -1, started: true}
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

// Two synthetic OS UID/home projections each complete the real file install
// path, including checked bytes/modes. Cross-account source and home selections
// refuse before installation. Ownership is injected; real multi-account native
// adoption and ACL behavior remain outside this test.
func TestTwoUserInstallOwnershipIsolation(t *testing.T) {
	a, runA := installFixture(t)
	b, runB := installFixture(t)
	a.uid, b.uid = 20001, 20002
	owner := func(path string, info os.FileInfo) (uint32, bool) {
		for _, user := range []installation{a, b} {
			for _, root := range []string{user.paths.Home, user.paths.ArtifactDirectory} {
				if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
					return user.uid, true
				}
			}
		}
		_, ok := ownerOf(info)
		return 0, ok // existing synthetic shared ancestors
	}
	a.fileOwner, b.fileOwner = owner, owner
	crossA, crossB := a, b
	crossA.paths, crossB.paths = b.paths, a.paths
	for _, cross := range []installation{crossA, crossB} {
		if err := cross.preflight(func(string, ...string) invocation {
			t.Fatal("foreign owner reached code inspection")
			return invocation{}
		}); err == nil || err.Error() != "directory_chain_unsafe" {
			t.Fatal("cross-account home accepted", err)
		}
	}
	for _, pair := range []struct {
		install installation
		run     runner
	}{{a, runA}, {b, runB}} {
		if err := pair.install.preflight(pair.run); err != nil {
			t.Fatal("valid synthetic account preflight refused", err)
		}
		if err := pair.install.install(pair.run); err != nil {
			t.Fatal("valid synthetic account install refused", err)
		}
		for _, spec := range pair.install.files() {
			path := filepath.Join(pair.install.paths.InstallDirectory, spec.relative)
			if ok, err := pair.install.optionalOwned(path, false, spec.mode); !ok || err != nil {
				t.Fatal("incorrect synthetic account output", err)
			}
		}
		mustNotExist(t, pair.install.paths.Lock)
	}
	if a.paths.InstallDirectory == b.paths.InstallDirectory || a.paths.Lock == b.paths.Lock {
		t.Fatal("account paths overlapped")
	}
}

// Replacing a source artifact after preflight cannot launch it for planning.
// A valid identity confirmation reaches a hash refusal during install, before
// fixture restore or actual generation. The preserved partial install is kept.
func TestPreConsentSourceReplacementNeverExecutes(t *testing.T) {
	for _, replace := range []string{"rename", "in-place"} {
		t.Run(replace, func(t *testing.T) {
			p, code := installFixture(t)
			actual := publicTarget{"north", "south", 1, 1, 1}
			qual := publicTarget{"fixture-north", "fixture-south", 1, 1, 1}
			plans, prompts := 0, 0
			w := workflow{run: func(binary string, args ...string) invocation {
				if binary != "/usr/bin/codesign" {
					t.Fatal("pre-consent source path executed")
				}
				return code(binary, args...)
			}, planner: plannerFunc(func(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
				plans++
				if plans == 1 {
					return fixturePlan(actual), nil
				}
				return fixturePlan(qual), nil
			}), restore: func(string, publicTarget) invocation { t.Fatal("replacement reached restore"); return invocation{} }, out: &bytes.Buffer{}}
			w.prompt = func(string, int) (string, error) {
				prompts++
				if prompts == 1 {
					if replace == "rename" {
						if err := os.Rename(p.sourceVault(), p.sourceVault()+".prior"); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(p.sourceVault(), []byte("untrusted replacement"), 0600); err != nil {
						t.Fatal(err)
					}
					return actual.NostrIdentity, nil
				}
				return actual.NamecoinIdentity, nil
			}
			err := execute(context.Background(), p, w, Config{NostrIdentity: actual.NostrIdentity, NamecoinIdentity: actual.NamecoinIdentity}, Identities{actual.NostrIdentity, actual.NamecoinIdentity, qual.NostrIdentity, qual.NamecoinIdentity})
			if err == nil || err.Error() != "release_artifact_hash" || plans != 2 || prompts != 2 {
				t.Fatal("replacement was not stopped before execution", err, plans, prompts)
			}
			mustNotExist(t, p.installedVault())
			mustNotExist(t, p.paths.Lock)
		})
	}
}

// The running utility accepts only a public planner source pin equal to the
// matched vault source revision. Missing or different source pins refuse
// before any public prompt or installation.
func TestReleasePlannerSourcePin(t *testing.T) {
	p, _ := installFixture(t)
	if err := p.release.validate(); err != nil {
		t.Fatal("matched planner source refused", err)
	}
	for _, pin := range []string{"", strings.Repeat("c", 40)} {
		r := p.release
		r.PlannerSource = pin
		if err := r.validate(); err == nil || err.Error() != "release_planner_source_mismatch" {
			t.Fatal("unmatched planner source admitted", err)
		}
	}
	mustNotExist(t, p.paths.Root)
	mustNotExist(t, p.paths.Lock)
}
