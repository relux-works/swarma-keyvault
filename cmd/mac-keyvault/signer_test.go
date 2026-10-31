package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// runSignerServe drives run(signer serve ...) with the given stdin and
// returns the exit code, the parsed stdout lines (hello first) and stderr.
func runSignerServe(t *testing.T, stdin string, args ...string) (int, []signerclient.Response, string) {
	t.Helper()
	previous := stdinReader
	stdinReader = strings.NewReader(stdin)
	t.Cleanup(func() { stdinReader = previous })
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"signer", "serve"}, args...), &stdout, &stderr)
	var lines []signerclient.Response
	for i, line := range strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n") {
		var resp signerclient.Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("stdout line %d is not a response (%v): %q", i, err, line)
		}
		if resp.Error != nil && (resp.Error.Code == "" || resp.Error.Message == "" || resp.Error.Hint == "") {
			t.Fatalf("line %d violates the error contract: %s", i, line)
		}
		lines = append(lines, resp)
	}
	return code, lines, stderr.String()
}

func request(t *testing.T, req signerclient.Request) string {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

// run(signer serve --address) through the production entry point: the
// hello announces contract 1 with the resolved label; describe, pub,
// sign (DER and raw) and verify round-trip over the stream against a
// recording store, the DER signature verifies with crypto/ecdsa under the
// pub result's SPKI, a refused request in the middle does not end the
// stream, EOF exits 0 with an empty stderr and one Sign call per sign.
func TestRunSignerServeRoundTrip(t *testing.T) {
	label := tl("serve", 1)
	store := newMemStore(label)
	useStore(t, store)
	pub := signerFor(store.keys[label].SPKI).PublicKey
	digest := digestHex("signer serve round trip")
	stdin := request(t, signerclient.Request{ID: json.RawMessage("1"), Op: "describe"}) +
		request(t, signerclient.Request{ID: json.RawMessage("2"), Op: "pub"}) +
		request(t, signerclient.Request{ID: json.RawMessage("3"), Op: "sign", Digest: digest}) +
		`{"id":4,"op":"sign","digest":"` + digest + `","format":"pkcs1"}` + "\n" +
		request(t, signerclient.Request{ID: json.RawMessage("5"), Op: "sign", Digest: digest, Format: signerclient.FormatRaw})
	code, lines, stderr := runSignerServe(t, stdin, "--address", "test/serve")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if len(lines) != 6 {
		t.Fatalf("%d lines: %+v", len(lines), lines)
	}
	var hello signerclient.Hello
	if lines[0].Contract != signerclient.Contract || !lines[0].OK || json.Unmarshal(lines[0].Result, &hello) != nil || hello.Label != label || hello.Tool != "mac-keyvault" {
		t.Fatalf("hello: %+v", lines[0])
	}
	var view map[string]any
	if !lines[1].OK || json.Unmarshal(lines[1].Result, &view) != nil || view["label"] != label || view["schema"] != 2.0 {
		t.Fatalf("describe: %+v", lines[1])
	}
	var pubResult signerclient.PublicKey
	if !lines[2].OK || json.Unmarshal(lines[2].Result, &pubResult) != nil {
		t.Fatalf("pub: %+v", lines[2])
	}
	der, err := base64.StdEncoding.DecodeString(pubResult.DERBase64)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil || !parsed.(*ecdsa.PublicKey).Equal(&pub) {
		t.Fatalf("pub SPKI: %v", err)
	}
	var sig signerclient.Signature
	if !lines[3].OK || json.Unmarshal(lines[3].Result, &sig) != nil || sig.Format != signerclient.FormatDERLowS || sig.Digest != digest || !sig.LowS {
		t.Fatalf("sign: %+v", lines[3])
	}
	if !ecdsa.VerifyASN1(&pub, hexBytes(t, digest), hexBytes(t, sig.Signature)) {
		t.Fatal("crypto/ecdsa rejects the streamed DER signature")
	}
	if lines[4].OK || lines[4].Error.Code != signerclient.CodeBadRequest || string(lines[4].ID) != "4" {
		t.Fatalf("bad format: %+v", lines[4])
	}
	var raw signerclient.Signature
	if !lines[5].OK || json.Unmarshal(lines[5].Result, &raw) != nil || raw.Format != signerclient.FormatRaw {
		t.Fatalf("sign raw: %+v", lines[5])
	}
	rawSig := hexBytes(t, raw.Signature)
	if len(rawSig) != 64 || !ecdsa.Verify(&pub, hexBytes(t, digest), new(big.Int).SetBytes(rawSig[:32]), new(big.Int).SetBytes(rawSig[32:])) {
		t.Fatal("crypto/ecdsa rejects the streamed raw signature")
	}
	if len(store.signs) != 2 {
		t.Fatalf("store saw %d signs, want 2", len(store.signs))
	}
}

// The address gate runs before the store exists: a raw label (inside or
// outside the prefix), a bad kind, a missing --address, a positional, a
// negative version, an unknown signer subcommand and a bare `signer` are
// refused with exactly one startup hello line on stdout (contract 1,
// ok=false, error code), the documented exit code, an empty stderr — text
// mode and the multi-line CLI envelope are never used by the stream
// command — and zero store calls; the store then serves a valid address,
// so it was reachable.
func TestRunSignerServeRefusesBeforeStore(t *testing.T) {
	store := newMemStore(tl("guard", 1))
	useStore(t, store)
	cases := []struct {
		args []string
		exit int
		code string
	}{
		{[]string{"--address", keyvault.LabelPrefix + "key.kvctl.pki-root.v1"}, exitRefused, keyvault.CodeForeignLabel},
		{[]string{"--address", "com.apple.security.something"}, exitRefused, keyvault.CodeForeignLabel},
		{[]string{"--address", "test/guard", "--kind", "bogus"}, exitRefused, keyvault.CodeInvalidKind},
		{[]string{"--address", "test/guard", "--version", "-1"}, exitRefused, keyvault.CodeInvalidPurpose},
		{[]string{"--address", "Test/guard"}, exitRefused, keyvault.CodeInvalidService},
		{[]string{}, exitUsage, "usage"},
		{[]string{"--address", "test/guard", "extra"}, exitUsage, "usage"},
		{[]string{"--address", "test/guard", "--bogus"}, exitUsage, "usage"},
	}
	for _, c := range cases {
		previous := stdinReader
		stdinReader = strings.NewReader(`{"id":1,"op":"sign","digest":"` + digestHex("x") + `"}` + "\n")
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"signer", "serve"}, c.args...), &stdout, &stderr)
		stdinReader = previous
		var resp signerclient.Response
		if err := keyvault.DecodeSingleJSON(stdout.Bytes(), &resp); err != nil || strings.Count(stdout.String(), "\n") != 1 {
			t.Fatalf("%v: stdout is not exactly one hello line: %v: %s", c.args, err, stdout.String())
		}
		if code != c.exit || resp.OK || resp.Contract != signerclient.Contract || resp.Error == nil || resp.Error.Code != c.code || stderr.Len() != 0 {
			t.Errorf("%v: exit %d %+v stderr %q, want %d %s", c.args, code, resp.Error, stderr.String(), c.exit, c.code)
		}
	}
	for _, args := range [][]string{{"signer"}, {"signer", "attest"}, {"--json", "signer"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		var resp signerclient.Response
		if err := keyvault.DecodeSingleJSON(stdout.Bytes(), &resp); err != nil || code != exitUsage || stderr.Len() != 0 || resp.Contract != signerclient.Contract || resp.Error == nil || resp.Error.Code != "usage" {
			t.Errorf("%v: exit %d stdout %q stderr %q (%v)", args, code, stdout.String(), stderr.String(), err)
		}
	}
	if store.touched() {
		t.Fatalf("a refused signer serve reached the store: creates=%d lists=%d signs=%d", len(store.creates), store.lists, len(store.signs))
	}
	if code, lines, _ := runSignerServe(t, "", "--address", "test/guard"); code != exitOK || len(lines) != 1 || !lines[0].OK {
		t.Fatalf("positive control: exit %d %+v", code, lines)
	}
	if store.lists != 1 {
		t.Fatalf("positive control listed %d times", store.lists)
	}
}

// A key that does not exist is a startup failure: exactly one line, the
// hello with ok=false and not_found, exit 1, and the pending request is
// never answered; a Security failure on sign is one error response in the
// stream (code security, os_status attached), exit 0 at EOF.
func TestRunSignerServeStartupAndSecurityFailures(t *testing.T) {
	store := newMemStore(tl("sec", 1))
	useStore(t, store)
	code, lines, stderr := runSignerServe(t, `{"id":1,"op":"describe"}`+"\n", "--address", "test/absent")
	if code != exitFailure || stderr != "" || len(lines) != 1 || lines[0].OK || lines[0].Contract != signerclient.Contract || lines[0].Error.Code != "not_found" {
		t.Fatalf("absent: exit %d %+v stderr %q", code, lines, stderr)
	}
	store.signE = &keyvault.StatusError{Op: "SecKeyCreateSignature", Status: -25293}
	code, lines, _ = runSignerServe(t, request(t, signerclient.Request{ID: json.RawMessage(`"a"`), Op: "sign", Digest: digestHex("sec")})+request(t, signerclient.Request{ID: json.RawMessage(`"b"`), Op: "pub"}), "--address", "test/sec")
	if code != exitOK || len(lines) != 3 {
		t.Fatalf("security: exit %d %+v", code, lines)
	}
	if lines[1].OK || lines[1].Error.Code != keyvault.CodeSecurity || lines[1].Error.OSStatus != -25293 || string(lines[1].ID) != `"a"` {
		t.Fatalf("security response: %+v", lines[1])
	}
	if !lines[2].OK || string(lines[2].ID) != `"b"` {
		t.Fatalf("stream ended after the security failure: %+v", lines[2])
	}
}

// End-to-end through the production SecurityStore on this Mac: a key
// created by run(init) under service test serves describe, pub, sign and
// verify over run(signer serve); the DER signature verifies with
// crypto/ecdsa under the streamed SPKI and under run(pub)'s file; a
// tampered signature is signature_invalid without ending the stream; EOF
// exits 0. Every label the store saw is a test label and is deleted in
// cleanup.
func TestRunSignerServeAgainstLoginKeychain(t *testing.T) {
	guard := &guardedBackend{t: t, inner: newTestSecurityStore(t)}
	useStore(t, guard)
	t.Cleanup(func() {
		for _, label := range guard.touched {
			if err := guard.inner.Delete(label); err != nil && !errors.Is(err, keyvault.ErrNotFound) {
				t.Errorf("cleanup %s: %v", label, err)
			}
		}
	})
	purpose := fmt.Sprintf("serve-e2e-%d", os.Getpid())
	if code, _, raw := runJSON(t, initArgs(purpose, "--usages", "sign,verify")...); code != exitOK {
		t.Fatalf("init: %s", raw)
	}
	digest := digestHex("serve e2e " + purpose)
	stdin := request(t, signerclient.Request{ID: json.RawMessage("1"), Op: "pub"}) +
		request(t, signerclient.Request{ID: json.RawMessage("2"), Op: "sign", Digest: digest})
	code, lines, stderr := runSignerServe(t, stdin, "--address", "test/"+purpose)
	if code != exitOK || stderr != "" || len(lines) != 3 || !lines[1].OK || !lines[2].OK {
		t.Fatalf("serve: exit %d %+v stderr %q", code, lines, stderr)
	}
	var hello signerclient.Hello
	if err := json.Unmarshal(lines[0].Result, &hello); err != nil || hello.Label != tl(purpose, 1) {
		t.Fatalf("hello: %v %+v", err, hello)
	}
	var pubResult signerclient.PublicKey
	var sig signerclient.Signature
	if json.Unmarshal(lines[1].Result, &pubResult) != nil || json.Unmarshal(lines[2].Result, &sig) != nil {
		t.Fatal("results do not decode")
	}
	der, _ := base64.StdEncoding.DecodeString(pubResult.DERBase64)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(parsed.(*ecdsa.PublicKey), hexBytes(t, digest), hexBytes(t, sig.Signature)) {
		t.Fatal("crypto/ecdsa rejects the keychain signature streamed by signer serve")
	}
	tampered := hexBytes(t, sig.Signature)
	tampered[len(tampered)-1] ^= 0x01
	stdin = request(t, signerclient.Request{ID: json.RawMessage("1"), Op: "verify", Digest: digest, Signature: hex.EncodeToString(tampered)}) +
		request(t, signerclient.Request{ID: json.RawMessage("2"), Op: "verify", Digest: digest, Signature: sig.Signature})
	code, lines, _ = runSignerServe(t, stdin, "--address", "test/"+purpose)
	if code != exitOK || len(lines) != 3 || lines[1].OK || lines[1].Error.Code != keyvault.CodeSignatureInvalid || !lines[2].OK {
		t.Fatalf("verify: exit %d %+v", code, lines)
	}
	for _, touched := range guard.touched {
		if !keyvault.IsTestLabel(touched) {
			t.Fatalf("non-test label touched: %s", touched)
		}
	}
}
