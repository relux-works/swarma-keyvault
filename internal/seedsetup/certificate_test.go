//go:build darwin || linux

package seedsetup

import (
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"path/filepath"
	"strings"
	"testing"
)

// Software fixtures prove each independent role/DR/hash/hardening refusal and
// no install writes. The injected native result does not qualify actual leaf
// DER, Security.framework, code execution or an installed certificate release.
func TestSeedCertificateRefusals(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-role", "wrong-team", "wrong-flags", "wrong-code", "wrong-dr", "or-dr", "implicit-dr", "entitled", "native-leaf", "unknown-asset"} {
		t.Run(mode, func(t *testing.T) {
			p, base := installFixture(t)
			spec := p.files()[0]
			path := filepath.Join(p.paths.ArtifactDirectory, spec.relative)
			if mode == "unknown-asset" {
				spec.relative = "unexpected"
			}
			if mode == "native-leaf" {
				p.certificateFile = func(string, codesignpolicy.Role) error { return errors.New("fixture native refusal") }
			}
			run := func(binary string, args ...string) invocation {
				r := base(binary, args...)
				if len(args) > 1 && args[0] == "-d" {
					switch args[1] {
					case "--verbose=4":
						switch mode {
						case "wrong-role":
							r.raw = []byte(strings.Replace(string(r.raw), "Identifier=works.relux.keyvault\n", "Identifier=works.relux.keyvault.enclave\n", 1))
						case "wrong-team":
							r.raw = []byte(strings.Replace(string(r.raw), "262RZ595FP", "OTHER", 1))
						case "wrong-flags":
							r.raw = []byte(strings.Replace(string(r.raw), "0x10000(runtime)", "0x10002(adhoc,runtime)", 1) + "Signature=adhoc\n")
						case "wrong-code":
							r.raw = []byte(strings.Replace(string(r.raw), strings.Repeat("1", 40), strings.Repeat("4", 40), 1))
						}
					case "-r-":
						switch mode {
						case "wrong-dr":
							r.raw = []byte(strings.Replace(string(r.raw), "works.relux.keyvault", "works.relux.keyvault.seed", 1))
						case "or-dr":
							r.raw = append(r.raw, []byte(` or cdhash H"1111111111111111111111111111111111111111"`)...)
						case "implicit-dr":
							r.raw = append([]byte("# "), r.raw...)
						}
					case "--entitlements":
						if mode == "entitled" {
							r.raw = []byte(`<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`)
						}
					}
				}
				return r
			}
			err := p.verifyFile(path, spec, run)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				want := "release_artifact_code_identity"
				if mode == "native-leaf" {
					want = "release_artifact_certificate"
				}
				if err == nil || err.Error() != want {
					t.Fatalf("wanted%s got%v", want, err)
				}
			}
			mustNotExist(t, p.paths.InstallDirectory)
			mustNotExist(t, p.paths.Lock)
		})
	}
}

// XML and the actual codesign executable label stay separate. Unknown stderr,
// duplicate labels and truncation cannot become an empty-entitlement success.
func TestSeedEntitlementOutput(t *testing.T) {
	for _, label := range []string{"", "Executable=/fixture/tool\n"} {
		out, diag := &capped{limit: 1024}, &capped{limit: 1024}
		out.Write([]byte(`<plist version="1.0"><dict/></plist>`))
		diag.Write([]byte(label))
		got := checkEntitlementOutput(out, diag, 0, "/fixture/tool")
		if got.exit != 0 || codesignpolicy.EmptyEntitlements(got.raw) != nil {
			t.Fatal("valid separated receipt refused")
		}
	}
	for _, label := range []string{"Executable=/different/tool\n", "Executable=/fixture/tool\nExecutable=/fixture/tool\n", "unexpected warning"} {
		out, diag := &capped{limit: 1024}, &capped{limit: 1024}
		diag.Write([]byte(label))
		if got := checkEntitlementOutput(out, diag, 0, "/fixture/tool"); got.exit != -1 || !got.started {
			t.Fatal("unknown stderr admitted")
		}
	}
	out, diag := &capped{limit: 1}, &capped{limit: 1}
	out.Write([]byte("xx"))
	if got := checkEntitlementOutput(out, diag, 0, "/fixture/tool"); got.exit != -1 {
		t.Fatal("truncated output admitted")
	}
}
