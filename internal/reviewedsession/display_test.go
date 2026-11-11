package reviewedsession

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

const ownerKeyDisplay = "fixture-owner/grants-owner-v1 v7"

var expectedOwnerKey = signerclient.Address{Kind: signerclient.KindKey, Service: "fixture-owner", Purpose: ownerkey.GrantPurpose, Version: 7}

func testDigest() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i)
	}
	return d
}

// The displayed digest cue, full document digest and configured owner-key reason bind the same prepared request.
func TestDigestCueAndFullReasonBinding(t *testing.T) {
	d := testDigest()
	if got := shortDigest(d); got != "0001 0203 0405 0607" {
		t.Fatal(got)
	}
	other := d
	other[31] ^= 1
	if shortDigest(other) != shortDigest(d) {
		t.Fatal("bad same-cue fixture")
	}
	for _, p := range []profile{repository, localRepository, a2aCertificate, muGrantMac} {
		f := titleFacts{profile: p}
		if p == muGrantMac {
			f.actions, f.targets, f.use = 2, 2, "once"
		}
		reason, err := renderReason(f, d, expectedOwnerKey, ownerKeyDisplay)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if err := checkFinalReason(f, d, d[:], expectedOwnerKey, ownerKeyDisplay, reason); err != nil {
			t.Fatal(err)
		}
		for name, altered := range map[string]string{
			"empty": "", "fallback": "mac-keyvault: sign sha256 00010203 with " + ownerKeyDisplay,
			"missing-key":    strings.TrimSuffix(reason, " with "+ownerKeyDisplay),
			"drop-delimiter": strings.Replace(reason, "]", "", 1),
			"wrong-cue":      strings.Replace(reason, "0001 0203", "0001 0204", 1),
			"newline":        reason + "\n", "oversized": reason + strings.Repeat("x", 201),
		} {
			t.Run(string(p)+"/"+name, func(t *testing.T) {
				if checkFinalReason(f, d, d[:], expectedOwnerKey, ownerKeyDisplay, altered) == nil {
					t.Fatal("accepted altered final request")
				}
			})
		}
		if checkFinalReason(f, d, other[:], expectedOwnerKey, ownerKeyDisplay, reason) == nil {
			t.Fatal("accepted same cue, different last digest byte")
		}
		if checkFinalReason(f, d, d[:31], expectedOwnerKey, ownerKeyDisplay, reason) == nil {
			t.Fatal("accepted short digest")
		}
		if checkFinalReason(f, d, d[:], expectedOwnerKey, "fixture-owner/grants-owner-v1 v8", reason) == nil {
			t.Fatal("accepted different resolved generation")
		}
	}
}

// The configured address consumes part of the 200-scalar reason budget. Fit
// optional text without shortening the exact address or the digest cue.
func TestWholeReasonBudget(t *testing.T) {
	d := testDigest()
	base := titleFacts{profile: repository}
	short, err := renderReason(base, d, expectedOwnerKey, ownerKeyDisplay)
	if err != nil {
		t.Fatal(err)
	}
	core, _ := base.core()
	if got := 200 - utf8.RuneCountInString(short) + utf8.RuneCountInString(core); got != 112 {
		t.Fatal("title budget", got)
	}
	for _, length := range []int{199, 200, 201, 400} {
		f := base
		f.optionalToken = strings.Repeat("x", length-utf8.RuneCountInString(short)-2)
		reason, err := renderReason(f, d, expectedOwnerKey, ownerKeyDisplay)
		if err != nil {
			t.Fatal(err)
		}
		want := min(length, 200)
		if utf8.RuneCountInString(reason) != want {
			t.Fatalf("length %d: %d", length, utf8.RuneCountInString(reason))
		}
		if !strings.HasSuffix(reason, " | [ХЕШ-ПОДПИСИ 0001 0203 0405 0607] with "+ownerKeyDisplay) {
			t.Fatal(reason)
		}
		if length > 200 && !strings.Contains(reason, "… | ") {
			t.Fatal("missing fitted ellipsis")
		}
	}
}

func TestDynamicDisplayRefusalsAndReversibleEscaping(t *testing.T) {
	bad := []string{"a\nb", "a\rb", "a\tb", "\x00", "\x1b", "\x7f", "\u0085", "\u202e", "\u2066", "\u200d", "\ufffe", "\ue000", "\u0378", "é", "e\u0301", "😀", "Иван", string([]byte{0xff}), "SIGNING_DIGEST_SHA256=bad", "short_signing_digest=x", "plan_snapshot_sha256=x", "session_nonce=x", "[ХЕШ-ПОДПИСИ x]"}
	for _, s := range bad {
		if _, err := safeString(s); err == nil {
			t.Fatalf("display accepted %q", s)
		}
	}
	for _, s := range []string{"", "@subject:example.org", `a \"<>&;[x]|`, "space = value", "sha256:00"} {
		quoted, err := safeString(s)
		if err != nil {
			t.Fatal(err)
		}
		var restored string
		if err := json.Unmarshal([]byte(quoted), &restored); err != nil || restored != s {
			t.Fatalf("not reversible: %q => %s", s, quoted)
		}
		if strings.ContainsAny(quoted, "\n\r\t<>|[] ") {
			t.Fatal("unsafe literal punctuation", quoted)
		}
	}
	for _, s := range []string{"a|b", "a[b]", "a b", "a\"b", `a\b`, "a;b"} {
		if titleToken(s) {
			t.Fatalf("unsafe title token %q", s)
		}
	}
}

func TestClosedProfilesAndPolicyTitles(t *testing.T) {
	d := testDigest()
	for _, p := range []profile{"", "mac-agent", "publisher", "publisher-ed25519", "linux", "grant", "repository-2"} {
		if p.included() {
			t.Fatal(p)
		}
		if _, err := renderReason(titleFacts{profile: p}, d, expectedOwnerKey, ownerKeyDisplay); err == nil {
			t.Fatal(p)
		}
	}
	f := titleFacts{profile: muGrantMac, actions: 2, targets: 2, use: "until_expiry"}
	if reason, err := renderReason(f, d, expectedOwnerKey, ownerKeyDisplay); err != nil || !strings.Contains(reason, "до истечения срока") {
		t.Fatal(reason, err)
	}
	for _, use := range []string{"", "unlimited", "Once", "1"} {
		f.use = use
		if _, err := renderReason(f, d, expectedOwnerKey, ownerKeyDisplay); err == nil {
			t.Fatal(use)
		}
	}
	if workflowAvailability() != errUnavailable {
		t.Fatal("source components must never enable a sitting")
	}
}

func TestStrictDigestAndByteRepresentations(t *testing.T) {
	d := testDigest()
	h := hex.EncodeToString(d[:])
	if got, err := digestHex(h); err != nil || got != d {
		t.Fatal(got, err)
	}
	for _, s := range []string{h[:63], h + "0", strings.ToUpper(h), " " + h, h + "\n", strings.Repeat("g", 64)} {
		if _, err := digestHex(s); err == nil {
			t.Fatal(s)
		}
	}
	if got, err := byteString("_w", 1); err != nil || !bytes.Equal(got, []byte{255}) {
		t.Fatal(got, err)
	}
	for _, s := range []string{"", "_w==", "/w", "_x", "_w\n", "AAAB"} {
		if _, err := byteString(s, 1); err == nil {
			t.Fatal(s)
		}
	}
}
