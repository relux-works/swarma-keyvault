//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func initializationFilesFixture(t *testing.T, mode, slot string) (InitializationFiles, string) {
	t.Helper()
	f, _, dir := signingFilesFixture(t, mode, slot)
	// The signing fixture supplies public files, but initialization neither
	// accepts nor opens its request/reveal paths.
	return InitializationFiles{Group: f.Group, Account: f.Account, ProfilePath: f.ProfilePath,
		ProfileSHA256: f.ProfileSHA256, AccountPinPath: f.AccountPinPath}, dir
}

// The four accepted independent profiles prepare owned PUBLIC snapshots with no
// filesystem effects. This proves input preparation, not consent or native use.
func TestInitializationFilesValidOwnedSnapshots(t *testing.T) {
	for _, mode := range []string{"two-stage", "all-four-before-release"} {
		for _, slot := range []string{"A", "C"} {
			t.Run(mode+slot, func(t *testing.T) {
				f, dir := initializationFilesFixture(t, mode, slot)
				before := inputTree(t, dir)
				got, err := PrepareInitializationFiles(f)
				if err != nil {
					t.Fatal(err)
				}
				profile, pin := got.ProfileBytes(), got.PinBytes()
				if len(profile) == 0 || len(pin) == 0 {
					t.Fatal("empty public snapshots")
				}
				config := got.NativeSelection()
				if _, err := initializationAccount(config, pin); err != nil {
					t.Fatal(err)
				}
				profile[0] ^= 1
				pin[0] ^= 1
				if bytes.Equal(profile, got.ProfileBytes()) || bytes.Equal(pin, got.PinBytes()) {
					t.Fatal("caller mutated snapshot")
				}
				if len(config.Selection.RevealValuesPin) > 0 {
					config.Selection.RevealValuesPin[0] ^= 1
					if bytes.Equal(config.Selection.RevealValuesPin, got.NativeSelection().Selection.RevealValuesPin) {
						t.Fatal("shared selection buffer")
					}
				}
				if !reflect.DeepEqual(before, inputTree(t, dir)) {
					t.Fatal("input preparation changed files")
				}
				// Once-read data must survive later file replacement without
				// silently selecting new bytes for review or private dispatch.
				retained := got.ProfileBytes()
				if err := os.WriteFile(f.ProfilePath, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(retained, got.ProfileBytes()) {
					t.Fatal("profile reread")
				}
			})
		}
	}
}

// Invalid independent selectors/files reject with the intended public class and
// no preparation effects; the neighboring valid control prevents reject-all.
func TestInitializationFilesRefusalsHaveNoWrites(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *InitializationFiles, string)
		code   namecoinwire.Code
	}{
		{"wrong-group", func(t *testing.T, f *InitializationFiles, _ string) { f.Group = "other/recovery@1" }, namecoinwire.AccountMismatch},
		{"wrong-account", func(t *testing.T, f *InitializationFiles, _ string) { f.Account = "other/namecoin@1" }, namecoinwire.AccountMismatch},
		{"profile-hash", func(t *testing.T, f *InitializationFiles, _ string) { f.ProfileSHA256 = strings.Repeat("0", 64) }, namecoinwire.PolicyRefused},
		{"missing-profile", func(t *testing.T, f *InitializationFiles, d string) { f.ProfilePath = filepath.Join(d, "absent") }, namecoinwire.PolicyRefused},
		{"malformed-profile", func(t *testing.T, f *InitializationFiles, _ string) {
			if err := os.WriteFile(f.ProfilePath, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}, namecoinwire.PolicyRefused},
		{"missing-pin", func(t *testing.T, f *InitializationFiles, d string) { f.AccountPinPath = filepath.Join(d, "absent") }, namecoinwire.AccountMismatch},
		{"wrong-pin", func(t *testing.T, f *InitializationFiles, _ string) {
			if err := os.WriteFile(f.AccountPinPath, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}, namecoinwire.AccountMismatch},
		{"unsafe-profile", func(t *testing.T, f *InitializationFiles, _ string) {
			if err := os.Chmod(f.ProfilePath, 0644); err != nil {
				t.Fatal(err)
			}
		}, namecoinwire.PolicyRefused},
		{"symlink-pin", func(t *testing.T, f *InitializationFiles, d string) {
			p := filepath.Join(d, "pin-link")
			if err := os.Symlink(f.AccountPinPath, p); err != nil {
				t.Fatal(err)
			}
			f.AccountPinPath = p
		}, namecoinwire.AccountMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, dir := initializationFilesFixture(t, "two-stage", "A")
			if _, err := PrepareInitializationFiles(f); err != nil {
				t.Fatal("positive control:", err)
			}
			tc.change(t, &f, dir)
			before := inputTree(t, dir)
			got, err := PrepareInitializationFiles(f)
			requireCode(t, err, tc.code)
			if len(got.ProfileBytes()) != 0 || len(got.PinBytes()) != 0 {
				t.Fatal("partial preparation returned")
			}
			if !reflect.DeepEqual(before, inputTree(t, dir)) {
				t.Fatal("refusal changed files")
			}
		})
	}
}
