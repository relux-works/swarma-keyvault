package main

import (
	"bytes"
	"strings"
	"testing"
)

// The release's distinct qualification binary accepts only its public digest
// signing route; mutating and private-input routes refuse before custody.
func TestQualificationOnlyMode(t *testing.T) {
	prior := recoveryQualificationOnly
	recoveryQualificationOnly = "1"
	t.Cleanup(func() { recoveryQualificationOnly = prior })
	if !qualificationInvocation([]string{"--json", "nostr", "sign", "fixture/nostr", "--version", "1", "--digest", strings.Repeat("0", 64)}) {
		t.Fatal("expected public fixture probe refused")
	}
	for _, args := range [][]string{
		{"--json", "recovery", "generate"},
		{"--json", "recovery", "restore"},
		{"--json", "recovery", "delete"},
		{"--json", "nostr", "sign", "fixture/nostr", "--version", "1", "--digest", strings.Repeat("a", 64)},
		{"--json", "nostr", "sign", "fixture/nostr", "--version", "2", "--digest", strings.Repeat("0", 64)},
	} {
		var out, diag bytes.Buffer
		if code := run(args, &out, &diag); code != 2 || !strings.Contains(out.String(), "public qualification executable admits only") || diag.Len() != 0 {
			t.Fatal("forbidden command did not refuse at the fixed gate", code)
		}
	}
}
