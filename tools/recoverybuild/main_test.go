package main

import (
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"strings"
	"testing"
)

// Builder metadata admission uses the same fixed certificate policy as the
// release verifier. Fixtures prove role/hash/entitlement refusals only; actual
// certificate trust and signing remain attended native checks.
func TestArtifactMetadataPolicy(t *testing.T) {
	info := "Identifier=works.relux.keyvault\nTeamIdentifier=262RZ595FP\nCodeDirectory v=20500 size=700 flags=0x10000(runtime) hashes=1\nCDHash=" + strings.Repeat("1", 40) + "\n"
	for _, ent := range []string{"", `<plist version="1.0"><dict/></plist>`} {
		pin, err := checkArtifactInfo(codesignpolicy.Vault, []byte(info), []byte(ent))
		if err != nil || pin != strings.Repeat("1", 40) {
			t.Fatal("valid role metadata refused")
		}
	}
	for _, bad := range []string{
		strings.Replace(info, "flags=0x10000(runtime)", "flags=0x10002(adhoc,runtime)", 1) + "Signature=adhoc\n",
		strings.Replace(info, "flags=0x10000", "flags=0x0", 1),
		strings.Replace(info, "Identifier=works.relux.keyvault\n", "Identifier=works.relux.keyvault.enclave\n", 1),
		info + "CDHash=" + strings.Repeat("2", 40) + "\n",
	} {
		if pin, err := checkArtifactInfo(codesignpolicy.Vault, []byte(bad), nil); pin != "" || !errors.Is(err, codesignpolicy.ErrPolicy) {
			t.Fatal("forbidden identity admitted")
		}
	}
	if pin, err := checkArtifactInfo(codesignpolicy.Vault, []byte(info), []byte(`<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`)); pin != "" || !errors.Is(err, codesignpolicy.ErrPolicy) {
		t.Fatal("entitled artifact admitted")
	}
}
