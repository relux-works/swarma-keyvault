package keyvault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesigntest"
)

var recoveryPipeBuild codesigntest.BuildOnce

func recoveryBuildPipeFixture(t *testing.T, run string) string {
	t.Helper()
	fixture, err := recoveryPipeBuild.Get(func() (string, error) {
		dir, err := os.MkdirTemp(run, "recovery-base-")
		if err != nil {
			return "", err
		}
		path := filepath.Join(dir, "pass")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p", "1", "-o", path, "./testdata/recovery/helper")
		if raw, err := codesigntest.NativeOutput(t, "build recovery helper", cmd); err != nil {
			return "", fmt.Errorf("public fixture build failed: %w, %s", err, raw)
		}
		return path, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

// The exact emitted wrap object is admitted for both policies. Omitted false,
// duplicate/unknown fields and alternative base64 encodings are rejected by
// canonical comparison, before they can be used as a persisted wrapping key.
func TestRecoveryPrivateWrapResponseSchema(t *testing.T) {
	for _, purpose := range []string{"nostr", "namecoin"} {
		helper := &recoveryFakeHelper{}
		w, err := helper.CreateWrap(purpose)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"blob": w.Blob, "point": w.Point, "fingerprint": w.Fingerprint, "policy": w.Policy, "silent_refused": w.SilentRefused}
		valid, _ := json.Marshal(body)
		if _, err := parseRecoveryWrap(valid, purpose); err != nil {
			t.Fatal("valid helper response refused")
		}
		bad := bytes.Replace(valid, []byte(`"blob":"`), []byte(`"blob":"\n`), 1)
		for _, raw := range [][]byte{
			bad,
			bytes.Replace(valid, []byte(`"blob":`), []byte(`"extra":0,"blob":`), 1),
			bytes.Replace(valid, []byte(`"blob":`), []byte(`"blob":"AQ==","blob":`), 1),
			append(bytes.Clone(valid), '\n'),
		} {
			_, err := parseRecoveryWrap(raw, purpose)
			recoveryCode(t, err, "wrapping_policy_refused")
		}
		delete(body, "silent_refused")
		missing, _ := json.Marshal(body)
		_, err = parseRecoveryWrap(missing, purpose)
		recoveryCode(t, err, "wrapping_policy_refused")
	}
}

// Actual subprocess pipes accept the valid fixed response. Truncation, extra
// bytes, wrong exit, declared excess, refusal and timeout are distinct rejects.
// A failed child admission occurs before the fixture receives any request.
func TestRecoveryPrivateHelperFramingAndAdmission(t *testing.T) {
	run := codesigntest.Require(t, codesigntest.RecoverySelection)
	fixture := recoveryBuildPipeFixture(t, run)
	root := codesigntest.FixtureDir(t, run, "framing")
	verify := func(int, []byte) error { return nil }
	for _, mode := range []string{"pass", "truncated", "extra", "bad-exit", "oversized", "refusal", "hang", "denied"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(root, mode)
			data, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0700); err != nil {
				t.Fatal(err)
			}
			h := &execRecoveryHelper{path: path, pin: strings.Repeat("1", 40), verify: verify, timeout: 10 * time.Second}
			if mode == "hang" {
				h.timeout = 500 * time.Millisecond
			}
			if mode == "denied" {
				h.verify = func(pid int, _ []byte) error {
					if pid != 0 {
						return recoveryRefuse("code_not_admitted")
					}
					return nil
				}
			}
			var result []byte
			err = codesigntest.NativeAttempt(t, "execute recovery pipe fixture", func() error {
				result, err = h.call(struct {
					Op string `json:"op"`
				}{"fixture"}, 68)
				return err
			})
			if mode == "pass" {
				if err != nil || len(result) != 68 || !bytes.Equal(result, make([]byte, 68)) {
					t.Fatal("valid frame rejected")
				}
			} else {
				want := "helper_protocol"
				if mode == "refusal" {
					want = "helper_refused"
				}
				if mode == "hang" {
					h.timeout = 500 * time.Millisecond
				}
				if mode == "denied" {
					want = "helper_not_admitted"
				}
				recoveryCode(t, err, want)
				if result != nil {
					t.Fatal("refusal returned a payload")
				}
			}
			_, received := os.Stat(path + ".received")
			if mode == "denied" && !os.IsNotExist(received) {
				t.Fatal("unadmitted helper received a request")
			}
		})
	}
}

// Missing/invalid compile-time pins and absent runtime policy refuse before
// process creation; they cannot silently use the legacy helper protocol.
func TestRecoveryPrivateHelperMissingPinAndParentPolicy(t *testing.T) {
	for _, pin := range []string{"", "00", strings.Repeat("A", 40)} {
		h := &execRecoveryHelper{path: "/nonexistent/helper", pin: pin, timeout: time.Second, verify: func(int, []byte) error { t.Fatal("bad pin reached code verifier"); return nil }}
		_, err := h.call(struct{}{}, 68)
		recoveryCode(t, err, "helper_not_admitted")
	}
	h := &execRecoveryHelper{path: "/nonexistent/helper", pin: strings.Repeat("1", 40), timeout: time.Second, verify: func(int, []byte) error { return recoveryRefuse("code_not_admitted") }}
	_, err := h.call(struct{}{}, 68)
	recoveryCode(t, err, "vault_not_hardened")
}
