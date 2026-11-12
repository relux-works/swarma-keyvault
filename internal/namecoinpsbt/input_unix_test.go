//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func signingFilesFixture(t *testing.T, mode, slot string) (SigningFiles, time.Time, string) {
	t.Helper()
	// Use the OS account home: writable ancestors such as /tmp are deliberately
	// refused by the production reader. Only this new directory is mutated.
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	owned, err := os.MkdirTemp(account.HomeDir, ".namecoin-psbt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(owned); err != nil {
			t.Error(err)
		}
	})
	dir, err := filepath.EvalSymlinks(owned)
	if err != nil {
		t.Fatal(err)
	}
	phase := "reservation"
	if slot == "C" || slot == "D" {
		phase = "reveal"
	}
	profile := fixture(t, "native-selection", mode+"-"+phase+".json")
	config, err := DecodeNativeSelection(profile)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	request, err := json.Marshal(requestFixture(t, mode, slot))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(profile)
	f := SigningFiles{Group: config.Selection.Group, Account: config.Selection.Account,
		ProfilePath: write("profile.json", profile), ProfileSHA256: hex.EncodeToString(hash[:]),
		AccountPinPath: write("account.json", fixture(t, mode, "account-pin.json")), RequestPath: write("request.json", request)}
	if phase == "reveal" {
		f.RevealPinPath = write("reveal.json", config.Selection.RevealValuesPin)
	}
	return f, time.Unix(int64(config.Selection.Policy.CreatedAt)+1, 0), dir
}

func inputTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			h := sha256.Sum256(raw)
			value += hex.EncodeToString(h[:])
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += target
		}
		m[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// All eight public fixture requests pass the composed real-file reader,
// independently hashed profile, explicit selectors and candidate admission at
// their fixture clock. Returned snapshots own their bytes after file edits and
// accessor edits. Synthetic sidecars establish no retained custody or consent.
func TestSigningFilesPublicAdmissionAndOwnership(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				f, now, dir := signingFilesFixture(t, mode, slot)
				before := inputTree(t, dir)
				p, err := PrepareSigningFiles(f, now)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, inputTree(t, dir)) {
					t.Fatal("preparation changed files")
				}
				if p.Attempt().Candidate().snapshot.Request().Slot != slot {
					t.Fatal("wrong candidate")
				}
				original := p.ProfileBytes()
				returned := p.ProfileBytes()
				returned[0] ^= 1
				if err := os.WriteFile(f.ProfilePath, []byte("later file change"), 0600); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(p.ProfileBytes(), original) {
					t.Fatal("profile snapshot alias")
				}
				pin := p.PinBytes()
				pin[0] ^= 1
				request := p.RequestBytes()
				request[0] ^= 1
				if bytes.Equal(p.PinBytes(), pin) || bytes.Equal(p.RequestBytes(), request) {
					t.Fatal("public byte alias")
				}
				config := p.NativeSelection()
				if len(config.Selection.RevealValuesPin) > 0 {
					config.Selection.RevealValuesPin[0] ^= 1
					if bytes.Equal(config.Selection.RevealValuesPin, p.NativeSelection().Selection.RevealValuesPin) {
						t.Fatal("reveal pin alias")
					}
				}
			})
		}
	}
}

// Composed presign refusals preserve all selected files and return no prepared
// candidate. Wrong hashes/selectors/pins, unsafe files, expired requests and
// missing/wrong separate reveal selections reject with their intended code.
// There is structurally no output/helper capability in this public-only stage;
// complete outer CLI/native no-effect integration remains a separate check.
func TestSigningFilesRefusalComposition(t *testing.T) {
	for _, kind := range []string{"hash", "hash-case", "profile-missing", "profile-link", "profile-mode", "group", "account", "pin", "pin-missing", "request", "expired", "reveal-missing", "reveal-changed", "reservation-extra"} {
		t.Run(kind, func(t *testing.T) {
			slot := "C"
			if kind == "reservation-extra" {
				slot = "A"
			}
			f, now, dir := signingFilesFixture(t, "two-stage", slot)
			code := namecoinwire.PolicyRefused
			switch kind {
			case "hash":
				f.ProfileSHA256 = strings.Repeat("0", 64)
			case "hash-case":
				f.ProfileSHA256 = strings.ToUpper(f.ProfileSHA256)
			case "profile-missing":
				f.ProfilePath = filepath.Join(dir, "missing")
			case "profile-link":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(f.ProfilePath, alias); err != nil {
					t.Fatal(err)
				}
				f.ProfilePath = alias
			case "profile-mode":
				if err := os.Chmod(f.ProfilePath, 0644); err != nil {
					t.Fatal(err)
				}
			case "group":
				f.Group = "other/recovery@1"
				code = namecoinwire.AccountMismatch
			case "account":
				f.Account = "other/namecoin@1"
				code = namecoinwire.AccountMismatch
			case "pin":
				if err := os.WriteFile(f.AccountPinPath, []byte("changed pin"), 0600); err != nil {
					t.Fatal(err)
				}
				code = namecoinwire.AccountMismatch
			case "pin-missing":
				f.AccountPinPath = filepath.Join(dir, "missing")
				code = namecoinwire.AccountMismatch
			case "request":
				if err := os.WriteFile(f.RequestPath, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				code = namecoinwire.InvalidRequest
			case "expired":
				now = now.Add(24 * time.Hour)
				code = namecoinwire.RequestExpired
			case "reveal-missing":
				f.RevealPinPath = ""
				code = namecoinwire.IntentMismatch
			case "reveal-changed":
				if err := os.WriteFile(f.RevealPinPath, []byte("changed value pin"), 0600); err != nil {
					t.Fatal(err)
				}
				code = namecoinwire.IntentMismatch
			case "reservation-extra":
				f.RevealPinPath = f.AccountPinPath
				code = namecoinwire.IntentMismatch
			}
			before := inputTree(t, dir)
			p, err := PrepareSigningFiles(f, now)
			requireCode(t, err, code)
			if len(p.Attempt().Descriptor()) != 0 || len(p.ProfileBytes()) != 0 {
				t.Fatal("refusal returned prepared authority")
			}
			if !reflect.DeepEqual(before, inputTree(t, dir)) {
				t.Fatal("refusal changed files")
			}
		})
	}
}
