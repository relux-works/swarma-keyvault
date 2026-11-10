package main

import (
	"strings"
	"testing"
)

// Real codesign-shaped positive controls accept absent/empty entitlements.
// Missing runtime, debug/runtime exceptions, false-valued unknown entitlement,
// malformed/multiple identity fields and non-ad-hoc code all refuse.
func TestArtifactPolicyPositiveAndForbiddenControls(t *testing.T) {
	info := "CodeDirectory v=20500 size=20 flags=0x10002(adhoc,runtime) hashes=1\nSignature=adhoc\nCDHash=" + strings.Repeat("1", 40) + "\n"
	for _, xml := range []string{"", `<?xml version="1.0"?><plist version="1.0"><dict/></plist>`} {
		if _, err := checkArtifactInfo([]byte(info), []byte(xml)); err != nil {
			t.Fatal("valid artifact refused")
		}
	}
	for _, bad := range []struct{ info, xml, want string }{
		{strings.Replace(info, "0x10002", "0x2", 1), "", "ad-hoc hardened runtime required"},
		{strings.Replace(info, "0x10002", "0x10000002", 1), "", "ad-hoc hardened runtime required"},
		{strings.Replace(info, "Signature=adhoc", "Signature=other", 1), "", "unexpected code identity"},
		{info + "CDHash=" + strings.Repeat("2", 40) + "\n", "", "unexpected code identity"},
		{info, `<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`, "entitlements are not empty"},
		{info, `<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><false/></dict></plist>`, "entitlements are not empty"},
		{info, `<plist version="1.0"><dict/><dict/></plist>`, "entitlements are not empty"},
		{info, `<plist version="1.0"><dict>`, "invalid entitlement document"},
	} {
		if _, err := checkArtifactInfo([]byte(bad.info), []byte(bad.xml)); err == nil || err.Error() != bad.want {
			t.Fatalf("wanted %s; got %v", bad.want, err)
		}
	}
}
