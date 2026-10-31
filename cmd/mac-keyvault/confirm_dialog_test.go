package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testDigest      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type dialogCall struct{ args []string }

// stubDialog replaces osascript with a canned answer and records each call.
func stubDialog(t *testing.T, stdin string, answer string, err error) *[]dialogCall {
	t.Helper()
	calls := &[]dialogCall{}
	oldRun, oldStdin, oldNow := runOSAScript, stdinReader, confirmNow
	runOSAScript = func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, dialogCall{args})
		return []byte(answer), err
	}
	stdinReader = strings.NewReader(stdin)
	confirmNow = func() time.Time { return time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { runOSAScript, stdinReader, confirmNow = oldRun, oldStdin, oldNow })
	return calls
}

func signRequest() string {
	return `{"purpose":"sign","address":"relux-source/signing","version":1,"fingerprint":"` + testFingerprint + `","sha256":"` + testDigest + `"}`
}

func unlockRequest() string {
	return `{"purpose":"unlock","address":"m1max-agents/release","version":1,"fingerprint":"` + testFingerprint + `","until":"2026-10-18T17:00:00Z"}`
}

// Claim: only the exact grant answer of a dialog built from validated
// fields grants (exit 0); the request data reaches osascript as argv next to
// a fixed script, never as script text.
func TestConfirmDialogGrantsOnlyExplicitButton(t *testing.T) {
	for _, tc := range []struct{ name, stdin, grant string }{
		{"sign", signRequest(), "Sign"},
		{"unlock", unlockRequest(), "Unlock"},
		{"unlock spelled with an escape", strings.Replace(unlockRequest(), `"unlock"`, `"\u0075nlock"`, 1), "Unlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubDialog(t, tc.stdin, tc.grant+"|false\n", nil)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"confirm-dialog"}, &stdout, &stderr); code != exitOK {
				t.Fatalf("grant: code %d, stderr %s", code, &stderr)
			}
			if len(*calls) != 1 {
				t.Fatalf("calls = %d", len(*calls))
			}
			args := (*calls)[0].args
			if len(args) != 5 || args[0] != "-e" || args[1] != dialogScript || args[3] != tc.grant || args[4] != "12" {
				t.Fatalf("osascript argv = %q", args)
			}
			if !strings.Contains(args[2], testFingerprint) || strings.Contains(dialogScript, "relux-source") {
				t.Fatalf("prompt %q", args[2])
			}
		})
	}
}

// Claim: every answer other than the exact grant line refuses: Deny (osascript
// fails with -128 because Deny is the cancel button), giving up, the grant
// button reported together with giving up, empty or extra output, and the
// other purpose's grant label.
func TestConfirmDialogRefusesEverythingElse(t *testing.T) {
	for name, tc := range map[string]struct {
		answer string
		err    error
	}{
		"deny (cancel)":          {"", errors.New("exit status 1")},
		"gave up":                {"|true\n", nil},
		"sign but gave up":       {"Sign|true\n", nil},
		"empty":                  {"", nil},
		"extra output":           {"Sign|false\nSign|false\n", nil},
		"unlock label for sign":  {"Unlock|false\n", nil},
		"grant with runner fail": {"Sign|false\n", errors.New("killed")},
	} {
		t.Run(name, func(t *testing.T) {
			stubDialog(t, signRequest(), tc.answer, tc.err)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"confirm-dialog"}, &stdout, &stderr); code != exitRefused {
				t.Fatalf("code %d", code)
			}
		})
	}
}

// Claim: malformed, ambiguous or incomplete requests are refused before any
// dialog is shown: trailing data including closing delimiters, duplicate or
// escape-equivalent members, case-variant names, wrong types, and missing or
// purpose-inconsistent fields. The valid requests above are the positive
// control.
func TestConfirmDialogRefusesMalformedRequests(t *testing.T) {
	sign, unlock := signRequest(), unlockRequest()
	for name, stdin := range map[string]string{
		"not json":             "sign please",
		"unknown field":        strings.Replace(sign, `"purpose"`, `"command":"x","purpose"`, 1),
		"trailing object":      sign + sign,
		"closing bracket":      sign + "]",
		"closing brace":        sign + "}",
		"duplicate address":    strings.Replace(sign, `"version"`, `"address":"other/key","version"`, 1),
		"escaped duplicate":    strings.Replace(sign, `"version"`, `"addr\u0065ss":"other/key","version"`, 1),
		"case alias":           strings.Replace(sign, `"address"`, `"Address"`, 1),
		"version as string":    strings.Replace(sign, `"version":1`, `"version":"1"`, 1),
		"version null":         strings.Replace(sign, `"version":1`, `"version":null`, 1),
		"address as number":    strings.Replace(sign, `"relux-source/signing"`, `7`, 1),
		"sign with null until": strings.Replace(sign, `"sha256"`, `"until":null,"sha256"`, 1),
		"unlock null digest":   strings.Replace(unlock, `"until"`, `"sha256":null,"until"`, 1),
		"sign no sha256":       strings.Replace(sign, `,"sha256":"`+testDigest+`"`, "", 1),
		"oversized":            sign + strings.Repeat(" ", maxConfirmInput),
		"unknown purpose":      strings.Replace(sign, `"sign"`, `"export"`, 1),
		"version zero":         strings.Replace(sign, `"version":1`, `"version":0`, 1),
		"raw label address":    strings.Replace(sign, `relux-source/signing`, `works.relux.mac-keyvault.key.x.y.v1`, 1),
		"bad fingerprint":      strings.Replace(sign, testFingerprint, "SHA256:short", 1),
		"bad digest":           strings.Replace(sign, testDigest, strings.ToUpper(testDigest), 1),
		"sign with until":      strings.Replace(sign, `"sha256"`, `"until":"2026-10-18T17:00:00Z","sha256"`, 1),
		"unlock with digest":   strings.Replace(unlock, `"until"`, `"sha256":"`+testDigest+`","until"`, 1),
		"unlock in the past":   strings.Replace(unlock, "2026-10-18T17:00:00Z", "2026-10-18T08:00:00Z", 1),
		"unlock no until":      strings.Replace(unlock, `,"until":"2026-10-18T17:00:00Z"`, "", 1),
		"empty":                "",
	} {
		t.Run(name, func(t *testing.T) {
			calls := stubDialog(t, stdin, "Sign|false\n", nil)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"confirm-dialog"}, &stdout, &stderr); code != exitRefused || len(*calls) != 0 {
				t.Fatalf("code %d, dialogs %d", code, len(*calls))
			}
		})
	}
}

// Claim: --wait outside [1s, 55s] and positional arguments are usage errors
// and show no dialog; --wait inside the range reaches osascript in seconds.
func TestConfirmDialogWaitBounds(t *testing.T) {
	for _, args := range [][]string{{"--wait", "0s"}, {"--wait", "56s"}, {"extra"}} {
		calls := stubDialog(t, signRequest(), "Sign|false\n", nil)
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"confirm-dialog"}, args...), &stdout, &stderr); code != exitUsage || len(*calls) != 0 {
			t.Fatalf("%v: code %d, dialogs %d", args, code, len(*calls))
		}
	}
	calls := stubDialog(t, signRequest(), "Sign|false\n", nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"confirm-dialog", "--wait", "30s"}, &stdout, &stderr); code != exitOK || (*calls)[0].args[4] != "30" {
		t.Fatalf("control: code %d, calls %v", code, *calls)
	}
}
