package codesignpolicy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Fixed literal readback fixtures exercise metadata/DR admission, not actual
// certificate trust, codesign execution, installed artifacts or native ACLs.
func TestCertificateReleaseReadback(t *testing.T) {
	for _, item := range []struct {
		role Role
		id   string
	}{{Vault, "works.relux.keyvault"}, {Helper, "works.relux.keyvault.enclave"}, {Seed, "works.relux.keyvault.seed"}, {Qualification, "works.relux.keyvault.qualification-foreign"}} {
		t.Run(item.id, func(t *testing.T) {
			info := "Executable=/fixture/new-tool\nIdentifier=" + item.id + "\nCodeDirectory v=20500 size=700 flags=0x10000(runtime) hashes=2\nCDHash=" + strings.Repeat("1", 40) + "\nAuthority=Apple Development: Public Fixture\nTeamIdentifier=262RZ595FP\n"
			dr := `designated => identifier "` + item.id + `" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */`
			for _, ent := range []string{"", `<?xml version="1.0"?><plist version="1.0"><dict/></plist>`} {
				got, err := CodeInfo(item.role, []byte(info), []byte(ent))
				if err != nil || got != strings.Repeat("1", 40) {
					t.Fatal("valid certificate metadata refused")
				}
			}
			for _, valid := range []string{dr, "Executable=/fixture/new-tool\n" + dr + "\n", strings.ReplaceAll(strings.ReplaceAll(dr, "/* exists */", ""), " and ", "\tand\t")} {
				if err := RequirementReadback(item.role, []byte(valid)); err != nil {
					t.Fatal("valid explicit requirement refused")
				}
			}
			infoBad := []string{
				strings.Replace(info, "flags=0x10000(runtime)", "flags=0x10002(adhoc,runtime)", 1) + "Signature=adhoc\n",
				strings.Replace(info, "flags=0x10000", "flags=0x0", 1),
				strings.Replace(info, "flags=0x10000", "flags=0x10000000", 1),
				strings.Replace(info, "TeamIdentifier=262RZ595FP", "TeamIdentifier=OTHER", 1),
				strings.Replace(info, "Identifier="+item.id+"\n", "Identifier=works.relux.other\n", 1),
				info + "CDHash=" + strings.Repeat("2", 40) + "\n",
				info + "Identifier=" + item.id + "\n",
				info + "TeamIdentifier=262RZ595FP\n",
				info + "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1\n",
				strings.Replace(info, strings.Repeat("1", 40), strings.Repeat("g", 40), 1),
				strings.Replace(info, "CDHash="+strings.Repeat("1", 40)+"\n", "", 1),
			}
			for i, bad := range infoBad {
				if got, err := CodeInfo(item.role, []byte(bad), nil); got != "" || !errors.Is(err, ErrPolicy) {
					t.Fatalf("metadata case%d did not refuse without hash", i)
				}
			}
			for _, bad := range []string{
				`<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`,
				`<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><false/></dict></plist>`,
				`<plist version="1.0"><dict/><dict/></plist>`,
				`<plist version="1.0"><dict>`,
				`<plist version="1.0"><dict/></plist><plist version="1.0"><dict/></plist>`,
				`<plist version="1.0"><dict xmlns="urn:foreign"/></plist>`,
			} {
				if got, err := CodeInfo(item.role, []byte(info), []byte(bad)); got != "" || !errors.Is(err, ErrPolicy) {
					t.Fatal("forbidden entitlements did not refuse without hash")
				}
			}
			for _, bad := range []string{
				"# " + dr,
				dr + "\n" + dr,
				dr + ` or cdhash H"1111111111111111111111111111111111111111"`,
				strings.Replace(dr, "d71190abe54185f908169ee9ca538d4066942c0f", strings.Repeat("2", 40), 1),
				strings.Replace(dr, item.id, "works.relux.other", 1),
				strings.Replace(dr, "anchor apple generic", "anchor trusted", 1),
				strings.Replace(dr, `certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f"`, `certificate leaf[subject.CN] = "Public Fixture"`, 1),
				strings.Replace(dr, "/* exists */", "/* unknown */", 1),
				strings.Replace(dr, " and anchor apple generic", "", 1),
				strings.Replace(dr, "/* exists */", "/* exists */ /* exists */", 1),
				strings.Replace(dr, item.id, item.id+`\u0000`, 1),
			} {
				if !errors.Is(RequirementReadback(item.role, []byte(bad)), ErrPolicy) {
					t.Fatal("weaker or ambiguous designated requirement admitted")
				}
			}
		})
	}
}

// Structured argv keeps the full explicit requirement in one argument, selects
// the exact certificate and preserves paths with spaces without shell parsing.
func TestCertificateSigningArguments(t *testing.T) {
	dr, _ := Requirement(Vault)
	want := []string{"-s", "d71190abe54185f908169ee9ca538d4066942c0f", "--force", "--options", "runtime", "--timestamp=none", "--identifier", "works.relux.keyvault", "-r=" + dr, "/fixture with spaces/new-vault"}
	got, err := SigningArgs(Vault, want[len(want)-1])
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("fixed signing arguments differ")
	}
	for _, role := range []Role{0, 5, 255} {
		if got, err := SigningArgs(role, "/fixture/tool"); got != nil || !errors.Is(err, ErrPolicy) {
			t.Fatal("unknown role admitted")
		}
		if _, err := Requirement(role); !errors.Is(err, ErrPolicy) {
			t.Fatal("unknown role constructed a requirement")
		}
	}
	for _, path := range []string{"", "relative", "/fixture/./tool", "/fixture/tool\x00extra"} {
		if got, err := SigningArgs(Vault, path); got != nil || !errors.Is(err, ErrPolicy) {
			t.Fatal("invalid artifact path admitted")
		}
	}
}

// Wrong certificate bytes, including an otherwise parseable public object,
// cannot match the fixed owner leaf. The actual fixed-leaf positive and chain
// trust are separate attended native readback requirements, NOT_RUN here.
func TestCertificateLeafRefusesOtherBytes(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, []byte("public-certificate-fixture"), bytesRepeated(32769)} {
		if !errors.Is(Leaf(raw), ErrPolicy) {
			t.Fatal("wrong leaf bytes admitted")
		}
	}
}

func bytesRepeated(n int) []byte { return []byte(strings.Repeat("x", n)) }
