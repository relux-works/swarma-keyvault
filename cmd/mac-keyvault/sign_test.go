package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func digestHex(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// highSTwin returns (r, n-s) of a low-S signature as strict DER.
func highSTwin(t *testing.T, der []byte) []byte {
	t.Helper()
	sig, err := keyvault.ParseSignature(der, keyvault.FormatSignatureDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.IsLowS() {
		t.Fatal("premise: sign output must be low-S")
	}
	twin := keyvault.Signature{R: sig.R, S: new(big.Int).Sub(elliptic.P256().Params().N, sig.S)}
	out, _ := twin.Encode(keyvault.FormatSignatureDERLowS)
	return out
}

// run(sign) over a 32-byte digest emits strict DER (re-encodes to itself,
// asn1 parses it) with low-S that verifies with crypto/ecdsa under the
// key's SPKI (interop, this -> Go); --raw emits 64 bytes r||s carrying the
// same integers; --out writes the bytes 0600; text mode prints hex;
// --data-file and --stdin hash with SHA-256 and report digest_source and
// the exact digest; a record whose format.signature is ecdsa-raw defaults
// to raw and --format ecdsa-der-low-s overrides it; a backend that hands
// back a high-S value is normalised (low_s true, normalized true, same
// r) and the emitted signature still verifies.
func TestRunSignFormatsAndInterop(t *testing.T) {
	store := newMemStore(tl("sig", 1))
	useStore(t, store)
	label := tl("sig", 1)
	pub := signerFor(store.keys[label].SPKI).PublicKey
	digest := digestHex("sign formats")

	code, resp, raw := runJSON(t, "sign", "test/sig", "--digest", digest)
	if code != exitOK {
		t.Fatalf("sign: %s", raw)
	}
	result := resultMap(t, resp)
	if result["format"] != keyvault.FormatSignatureDERLowS || result["hash"] != "sha256" || result["digest"] != digest || result["digest_source"] != "digest" || result["low_s"] != true || result["normalized"] != false || result["label"] != label || len(store.signs) != 1 {
		t.Fatalf("result: %s", raw)
	}
	der := hexBytes(t, result["signature"].(string))
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("not DER: %v", err)
	}
	if again, _ := asn1.Marshal(parsed); !bytes.Equal(again, der) {
		t.Fatal("DER is not strict")
	}
	if parsed.S.Cmp(new(big.Int).Rsh(elliptic.P256().Params().N, 1)) > 0 {
		t.Fatal("s is in the high half")
	}
	if !ecdsa.VerifyASN1(&pub, hexBytes(t, digest), der) {
		t.Fatal("crypto/ecdsa rejects the DER signature")
	}

	code, resp, raw = runJSON(t, "sign", "test/sig", "--digest", digest, "--raw")
	if code != exitOK {
		t.Fatalf("raw: %s", raw)
	}
	rawSig := hexBytes(t, resultMap(t, resp)["signature"].(string))
	if len(rawSig) != 64 || resultMap(t, resp)["format"] != keyvault.FormatSignatureRaw {
		t.Fatalf("raw: %s", raw)
	}
	if !ecdsa.Verify(&pub, hexBytes(t, digest), new(big.Int).SetBytes(rawSig[:32]), new(big.Int).SetBytes(rawSig[32:])) {
		t.Fatal("crypto/ecdsa rejects the raw signature")
	}

	outPath := filepath.Join(t.TempDir(), "sig.der")
	code, resp, raw = runJSON(t, "sign", "test/sig", "--digest", digest, "--out", outPath)
	if code != exitOK || resultMap(t, resp)["out"] != outPath {
		t.Fatalf("out: %s", raw)
	}
	written, err := os.ReadFile(outPath)
	if err != nil || !ecdsa.VerifyASN1(&pub, hexBytes(t, digest), written) {
		t.Fatalf("written signature: %v", err)
	}
	if info, _ := os.Stat(outPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "test/sig", "--digest", digest}, &stdout, &stderr); code != exitOK || stderr.Len() != 0 {
		t.Fatalf("text: %d %s", code, stderr.String())
	}
	if !ecdsa.VerifyASN1(&pub, hexBytes(t, digest), hexBytes(t, strings.TrimSpace(stdout.String()))) {
		t.Fatalf("text output is not a hex signature: %q", stdout.String())
	}

	data := []byte("the quick brown fox")
	dataPath := writeTemp(t, "data.bin", data)
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(data); return s[:] }())
	code, resp, raw = runJSON(t, "sign", "test/sig", "--data-file", dataPath)
	if code != exitOK || resultMap(t, resp)["digest"] != want || resultMap(t, resp)["digest_source"] != "file" {
		t.Fatalf("data-file: %s", raw)
	}
	if !ecdsa.VerifyASN1(&pub, hexBytes(t, want), hexBytes(t, resultMap(t, resp)["signature"].(string))) {
		t.Fatal("data-file signature does not verify over sha256(data)")
	}
	stdinReader = bytes.NewReader(data)
	t.Cleanup(func() { stdinReader = os.Stdin })
	code, resp, raw = runJSON(t, "sign", "test/sig", "--stdin")
	if code != exitOK || resultMap(t, resp)["digest"] != want || resultMap(t, resp)["digest_source"] != "stdin" {
		t.Fatalf("stdin: %s", raw)
	}

	// Record default ecdsa-raw, and the explicit override.
	rawLabel := tl("rawdefault", 1)
	item := memItem(rawLabel, 9)
	rec, _ := keyvault.DecodeRecord(item.Tag)
	rec.Format.Signature = keyvault.FormatSignatureRaw
	item.Tag, _ = keyvault.EncodeRecord(rec)
	store.keys[rawLabel] = item
	if _, resp, raw = runJSON(t, "sign", "test/rawdefault", "--digest", digest); resultMap(t, resp)["format"] != keyvault.FormatSignatureRaw || len(hexBytes(t, resultMap(t, resp)["signature"].(string))) != 64 {
		t.Fatalf("record default raw: %s", raw)
	}
	if _, resp, raw = runJSON(t, "sign", "test/rawdefault", "--digest", digest, "--format", keyvault.FormatSignatureDERLowS); resultMap(t, resp)["format"] != keyvault.FormatSignatureDERLowS {
		t.Fatalf("override: %s", raw)
	}

	store.signHighS = true
	code, resp, raw = runJSON(t, "sign", "test/sig", "--digest", digest)
	if code != exitOK || resultMap(t, resp)["low_s"] != true || resultMap(t, resp)["normalized"] != true {
		t.Fatalf("high-S backend: %s", raw)
	}
	normalised := hexBytes(t, resultMap(t, resp)["signature"].(string))
	sig, err := keyvault.ParseSignature(normalised, keyvault.FormatSignatureDERLowS)
	if err != nil || !sig.IsLowS() || !ecdsa.VerifyASN1(&pub, hexBytes(t, digest), normalised) {
		t.Fatalf("normalised signature: %v", err)
	}
	store.signHighS = false
}

// run(verify) judges a signature over a digest: by label (exit 0, ok true,
// verified true, by label, the key view) and by --spki DER or PEM (no store
// call at all); a Go crypto/ecdsa signature over the same digest verifies
// through --spki (interop, Go -> this); a raw signature verifies with
// --raw. Verdict false is exit 1 signature_invalid with verified false in
// the result: a tampered r byte, another digest, another key's SPKI. A
// high-S signature (DER or raw) is exit 3 high_s_refused without
// --allow-high-s (verdict not computed), and verifies with exit 0, low_s
// false, when the flag is given. Text mode prints "verified: true|false".
func TestRunVerifyVerdicts(t *testing.T) {
	store := newMemStore(tl("ver", 1))
	useStore(t, store)
	label := tl("ver", 1)
	spki := store.keys[label].SPKI
	priv := signerFor(spki)
	digest := digestHex("verify verdicts")

	_, resp, raw := runJSON(t, "sign", "test/ver", "--digest", digest)
	sigHex := resultMap(t, resp)["signature"].(string)
	der := hexBytes(t, sigHex)
	_, resp, _ = runJSON(t, "sign", "test/ver", "--digest", digest, "--raw")
	rawHex := resultMap(t, resp)["signature"].(string)

	code, resp, raw := runJSON(t, "verify", "test/ver", "--digest", digest, "--sig", sigHex)
	if code != exitOK || !resp.OK || resultMap(t, resp)["verified"] != true || resultMap(t, resp)["by"] != "label" || resultMap(t, resp)["label"] != label || resultMap(t, resp)["low_s"] != true {
		t.Fatalf("by label: %s", raw)
	}
	if len(store.signs) != 2 {
		t.Fatalf("verify signed: %v", store.signs)
	}
	if code, resp, raw = runJSON(t, "verify", "test/ver", "--digest", digest, "--sig", rawHex, "--raw"); code != exitOK || resultMap(t, resp)["verified"] != true || resultMap(t, resp)["format"] != keyvault.FormatSignatureRaw {
		t.Fatalf("raw by label: %s", raw)
	}

	derPath := writeTemp(t, "pub.der", spki)
	pemPath := writeTemp(t, "pub.pem", keyvault.EncodePEM(spki))
	sigPath := writeTemp(t, "sig.der", der)
	for _, spkiPath := range []string{derPath, pemPath} {
		fresh := newMemStore()
		useStore(t, fresh)
		code, resp, raw = runJSON(t, "verify", "--spki", spkiPath, "--digest", "@"+writeTemp(t, "digest.bin", hexBytes(t, digest)), "--sig", "@"+sigPath)
		if code != exitOK || resultMap(t, resp)["verified"] != true || resultMap(t, resp)["by"] != "spki" || resultMap(t, resp)["fingerprint"] != (keyvault.Key{SPKI: spki}).Fingerprint() {
			t.Fatalf("by spki %s: %s", spkiPath, raw)
		}
		if fresh.touched() {
			t.Fatal("verify --spki touched the store")
		}
	}
	useStore(t, store)

	// Go -> this: a crypto/ecdsa signature verifies here.
	goSig, err := ecdsa.SignASN1(rand.Reader, priv, hexBytes(t, digest))
	if err != nil {
		t.Fatal(err)
	}
	goLow, _ := keyvault.ParseSignature(goSig, keyvault.FormatSignatureDERLowS)
	goLowDER, _ := goLow.LowS().Encode(keyvault.FormatSignatureDERLowS)
	if code, resp, raw = runJSON(t, "verify", "--spki", pemPath, "--digest", digest, "--sig", hex.EncodeToString(goLowDER)); code != exitOK || resultMap(t, resp)["verified"] != true {
		t.Fatalf("go signature: %s", raw)
	}
	if code, resp, raw = runJSON(t, "verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(goLowDER)); code != exitOK || resultMap(t, resp)["verified"] != true {
		t.Fatalf("go signature by label: %s", raw)
	}

	// Verdict false.
	tampered := append([]byte(nil), der...)
	tampered[5] ^= 0x01 // inside r
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	falseCases := map[string][]string{
		"tampered r":   {"verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(tampered)},
		"other digest": {"verify", "test/ver", "--digest", digestHex("other"), "--sig", sigHex},
		"other key":    {"verify", "--spki", writeTemp(t, "other.der", otherSPKI), "--digest", digest, "--sig", sigHex},
		"raw tampered": {"verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(func() []byte { b := hexBytes(t, rawHex); b[40] ^= 0x80; return b }()), "--raw"},
	}
	for name, args := range falseCases {
		t.Run(name, func(t *testing.T) {
			code, resp, raw := runJSON(t, args...)
			if code != exitFailure || resp.OK || resp.Error.Code != keyvault.CodeSignatureInvalid || resultMap(t, resp)["verified"] != false {
				t.Fatalf("%s", raw)
			}
		})
	}

	// High-S.
	high := highSTwin(t, der)
	if !ecdsa.VerifyASN1(&priv.PublicKey, hexBytes(t, digest), high) {
		t.Fatal("premise: the high-S twin is a valid ECDSA signature")
	}
	highRaw, _ := func() ([]byte, error) {
		s, _ := keyvault.ParseSignature(high, keyvault.FormatSignatureDERLowS)
		return s.Encode(keyvault.FormatSignatureRaw)
	}()
	for name, args := range map[string][]string{
		"der by label": {"verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(high)},
		"der by spki":  {"verify", "--spki", pemPath, "--digest", digest, "--sig", hex.EncodeToString(high)},
		"raw by label": {"verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(highRaw), "--raw"},
	} {
		t.Run("high-s "+name, func(t *testing.T) {
			fresh := newMemStore(tl("ver", 1))
			fresh.keys[label] = store.keys[label]
			useStore(t, fresh)
			code, resp, raw := runJSON(t, args...)
			if code != exitRefused || resp.OK || resp.Error.Code != keyvault.CodeHighSRefused || resultMap(t, resp)["verified"] != false || resultMap(t, resp)["low_s"] != false {
				t.Fatalf("%s", raw)
			}
			if fresh.touched() {
				t.Fatalf("high-S refusal touched the store: lists=%d signs=%v", fresh.lists, fresh.signs)
			}
			code, resp, raw = runJSON(t, append(args, "--allow-high-s")...)
			if code != exitOK || resultMap(t, resp)["verified"] != true || resultMap(t, resp)["low_s"] != false || resultMap(t, resp)["high_s_allowed"] != true {
				t.Fatalf("allowed: %s", raw)
			}
		})
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "test/ver", "--digest", digest, "--sig", sigHex}, &stdout, &stderr); code != exitOK || stdout.String() != "verified: true\n" || stderr.Len() != 0 {
		t.Fatalf("text true: %d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"verify", "test/ver", "--digest", digest, "--sig", hex.EncodeToString(tampered)}, &stdout, &stderr); code != exitFailure || stdout.String() != "verified: false\n" || !strings.Contains(stderr.String(), "error: signature_invalid:") {
		t.Fatalf("text false: %d %q %q", code, stdout.String(), stderr.String())
	}
}

// Regression for review rev1 F2 (high-S refusal ordered after the backend
// read): a high-S signature without --allow-high-s is refused on the
// signature bytes alone, before the vault is listed and before the --spki
// file is read. The signatures are prepared independently with
// crypto/ecdsa (never through run(sign)); the backend is a fresh recording
// store that holds the addressed key with a signer behind it, so a leaked
// List would succeed rather than fail for another reason, and the test
// asserts zero backend calls. Ordering witnesses: an address with no item
// and a --spki path that does not exist are still high_s_refused, not
// not_found / usage — the key is never resolved. Positive control: the
// low-S form of the same signature does reach the store and verifies.
func TestRunVerifyHighSRefusedBeforeStore(t *testing.T) {
	label := tl("hs", 1)
	digest := digestHex("high-s before store")
	seed := newMemStore(label)
	priv := signerFor(seed.keys[label].SPKI)
	goDER, err := ecdsa.SignASN1(rand.Reader, priv, hexBytes(t, digest))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := keyvault.ParseSignature(goDER, keyvault.FormatSignatureDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	lowDER, _ := parsed.LowS().Encode(keyvault.FormatSignatureDERLowS)
	highDER := highSTwin(t, lowDER)
	highRaw, _ := keyvault.Signature{R: parsed.R, S: new(big.Int).Sub(elliptic.P256().Params().N, parsed.LowS().S)}.Encode(keyvault.FormatSignatureRaw)
	if !ecdsa.VerifyASN1(&priv.PublicKey, hexBytes(t, digest), highDER) {
		t.Fatal("premise: the high-S twin is a valid ECDSA signature")
	}
	missingSPKI := filepath.Join(t.TempDir(), "absent.pem")
	cases := map[string][]string{
		"der by label":         {"verify", "test/hs", "--digest", digest, "--sig", hex.EncodeToString(highDER)},
		"raw by label":         {"verify", "test/hs", "--digest", digest, "--sig", hex.EncodeToString(highRaw), "--raw"},
		"der by label @file":   {"verify", "test/hs", "--digest", "@" + writeTemp(t, "digest.bin", hexBytes(t, digest)), "--sig", "@" + writeTemp(t, "sig.der", highDER)},
		"der by absent label":  {"verify", "test/nothere", "--digest", digest, "--sig", hex.EncodeToString(highDER)},
		"der by absent --spki": {"verify", "--spki", missingSPKI, "--digest", digest, "--sig", hex.EncodeToString(highDER)},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			fresh := newMemStore(label)
			fresh.keys[label] = seed.keys[label]
			useStore(t, fresh)
			code, resp, raw := runJSON(t, args...)
			if code != exitRefused || resp.OK || resp.Error.Code != keyvault.CodeHighSRefused {
				t.Fatalf("%s", raw)
			}
			res := resultMap(t, resp)
			if res["verified"] != false || res["low_s"] != false || res["high_s_allowed"] != false || res["digest"] != digest {
				t.Fatalf("result: %s", raw)
			}
			if _, leaked := res["label"]; leaked {
				t.Fatalf("key resolved before the refusal: %s", raw)
			}
			if fresh.touched() {
				t.Fatalf("high-S refusal touched the store: lists=%d signs=%v", fresh.lists, fresh.signs)
			}
		})
	}
	t.Run("control low-S reaches the store", func(t *testing.T) {
		fresh := newMemStore(label)
		fresh.keys[label] = seed.keys[label]
		useStore(t, fresh)
		code, resp, raw := runJSON(t, "verify", "test/hs", "--digest", digest, "--sig", hex.EncodeToString(lowDER))
		if code != exitOK || resultMap(t, resp)["verified"] != true || resultMap(t, resp)["label"] != label {
			t.Fatalf("%s", raw)
		}
		if fresh.lists != 1 || len(fresh.signs) != 0 {
			t.Fatalf("control: lists=%d signs=%v", fresh.lists, fresh.signs)
		}
	})
}

// Malformed input is refused before any store call (zero lists, zero
// signs): a digest of 31, 33 or 0 bytes as hex or @file (invalid_digest,
// exit 3), no or two digest sources / non-hex / unreadable files / --raw
// against --format DER / address plus --spki / missing --sig (usage, exit
// 2), a raw signature of 63 or 65 bytes, non-strict DER (padded integer,
// trailing byte), r = 0 (invalid_signature, exit 3), an SPKI that is not
// P-256 or not a key (invalid_public_key, exit 3), and a raw label in
// place of an address (foreign_label, exit 3) on both commands. A @file
// digest is taken as raw bytes even when its 32 bytes look like hex text
// (positive control: it signs and reports those bytes).
func TestRunSignVerifyRefuseBadInputBeforeStore(t *testing.T) {
	digest := digestHex("bad input")
	sig := func() string {
		store := newMemStore(tl("bad", 1))
		useStore(t, store)
		_, resp, _ := runJSON(t, "sign", "test/bad", "--digest", digest)
		return resultMap(t, resp)["signature"].(string)
	}()
	der := hexBytes(t, sig)
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	type rawInts struct{ R, S asn1.RawValue }
	padded, _ := asn1.Marshal(rawInts{R: asn1.RawValue{Tag: asn1.TagInteger, Bytes: append([]byte{0, 0}, parsed.R.Bytes()...)}, S: asn1.RawValue{Tag: asn1.TagInteger, Bytes: parsed.S.Bytes()}})
	zeroR, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(0), parsed.S})
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	spki384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	spkiPath := writeTemp(t, "p384.der", spki384)
	notKey := writeTemp(t, "not.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
	short := writeTemp(t, "short.bin", make([]byte, 31))
	long := writeTemp(t, "long.bin", make([]byte, 33))
	rawSig := func(n int) string { return strings.Repeat("11", n) }
	cases := map[string]struct {
		args    []string
		code    int
		errCode string
	}{
		"sign digest 31 hex":      {[]string{"sign", "test/bad", "--digest", digest[:62]}, exitRefused, keyvault.CodeInvalidDigest},
		"sign digest 33 hex":      {[]string{"sign", "test/bad", "--digest", digest + "aa"}, exitRefused, keyvault.CodeInvalidDigest},
		"sign digest empty file":  {[]string{"sign", "test/bad", "--digest", "@" + writeTemp(t, "empty", nil)}, exitRefused, keyvault.CodeInvalidDigest},
		"sign digest 31 file":     {[]string{"sign", "test/bad", "--digest", "@" + short}, exitRefused, keyvault.CodeInvalidDigest},
		"sign digest 33 file":     {[]string{"sign", "test/bad", "--digest", "@" + long}, exitRefused, keyvault.CodeInvalidDigest},
		"verify digest 31":        {[]string{"verify", "test/bad", "--digest", digest[:62], "--sig", sig}, exitRefused, keyvault.CodeInvalidDigest},
		"verify spki digest 33":   {[]string{"verify", "--spki", spkiPath, "--digest", digest + "00", "--sig", sig}, exitRefused, keyvault.CodeInvalidDigest},
		"sign no source":          {[]string{"sign", "test/bad"}, exitUsage, "usage"},
		"sign two sources":        {[]string{"sign", "test/bad", "--digest", digest, "--stdin"}, exitUsage, "usage"},
		"sign non-hex":            {[]string{"sign", "test/bad", "--digest", "zz" + digest[2:]}, exitUsage, "usage"},
		"sign missing file":       {[]string{"sign", "test/bad", "--digest", "@" + filepath.Join(t.TempDir(), "nope")}, exitUsage, "usage"},
		"sign data-file missing":  {[]string{"sign", "test/bad", "--data-file", filepath.Join(t.TempDir(), "nope")}, exitUsage, "usage"},
		"sign raw vs format":      {[]string{"sign", "test/bad", "--digest", digest, "--raw", "--format", keyvault.FormatSignatureDERLowS}, exitUsage, "usage"},
		"sign bad format":         {[]string{"sign", "test/bad", "--digest", digest, "--format", "p1363"}, exitUsage, "usage"},
		"sign no address":         {[]string{"sign", "--digest", digest}, exitUsage, "usage"},
		"sign raw label":          {[]string{"sign", tl("bad", 1), "--digest", digest}, exitRefused, keyvault.CodeForeignLabel},
		"sign bad kind":           {[]string{"sign", "test/bad", "--digest", digest, "--kind", "cert"}, exitRefused, keyvault.CodeInvalidKind},
		"verify no sig":           {[]string{"verify", "test/bad", "--digest", digest}, exitUsage, "usage"},
		"verify address and spki": {[]string{"verify", "test/bad", "--spki", spkiPath, "--digest", digest, "--sig", sig}, exitUsage, "usage"},
		"verify neither":          {[]string{"verify", "--digest", digest, "--sig", sig}, exitUsage, "usage"},
		"verify raw label":        {[]string{"verify", tl("bad", 1), "--digest", digest, "--sig", sig}, exitRefused, keyvault.CodeForeignLabel},
		"verify raw 63":           {[]string{"verify", "test/bad", "--digest", digest, "--sig", rawSig(63), "--raw"}, exitRefused, keyvault.CodeInvalidSignature},
		"verify raw 65":           {[]string{"verify", "test/bad", "--digest", digest, "--sig", rawSig(65), "--raw"}, exitRefused, keyvault.CodeInvalidSignature},
		"verify der as raw":       {[]string{"verify", "test/bad", "--digest", digest, "--sig", sig, "--raw"}, exitRefused, keyvault.CodeInvalidSignature},
		"verify padded der":       {[]string{"verify", "test/bad", "--digest", digest, "--sig", hex.EncodeToString(padded)}, exitRefused, keyvault.CodeInvalidSignature},
		"verify trailing byte":    {[]string{"verify", "test/bad", "--digest", digest, "--sig", sig + "00"}, exitRefused, keyvault.CodeInvalidSignature},
		"verify zero r":           {[]string{"verify", "test/bad", "--digest", digest, "--sig", hex.EncodeToString(zeroR)}, exitRefused, keyvault.CodeInvalidSignature},
		"verify sig non-hex":      {[]string{"verify", "test/bad", "--digest", digest, "--sig", "xyz"}, exitUsage, "usage"},
		"verify spki p384":        {[]string{"verify", "--spki", spkiPath, "--digest", digest, "--sig", sig}, exitRefused, keyvault.CodeInvalidPublicKey},
		"verify spki not key":     {[]string{"verify", "--spki", notKey, "--digest", digest, "--sig", sig}, exitRefused, keyvault.CodeInvalidPublicKey},
		"verify spki missing":     {[]string{"verify", "--spki", filepath.Join(t.TempDir(), "nope"), "--digest", digest, "--sig", sig}, exitUsage, "usage"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemStore(tl("bad", 1))
			useStore(t, store)
			code, resp, raw := runJSON(t, tc.args...)
			if code != tc.code || resp.OK || resp.Error == nil || resp.Error.Code != tc.errCode {
				t.Fatalf("code %d, want %d %s: %s", code, tc.code, tc.errCode, raw)
			}
			if store.touched() {
				t.Fatalf("store touched: lists=%d signs=%v", store.lists, store.signs)
			}
		})
	}
	t.Run("hex-looking file is raw bytes", func(t *testing.T) {
		store := newMemStore(tl("bad", 1))
		useStore(t, store)
		text := []byte("0123456789abcdef0123456789abcdef") // 32 ASCII bytes
		code, resp, raw := runJSON(t, "sign", "test/bad", "--digest", "@"+writeTemp(t, "hexlike.bin", text))
		if code != exitOK || resultMap(t, resp)["digest"] != hex.EncodeToString(text) {
			t.Fatalf("%s", raw)
		}
	})
}

// The sign policy gates run through run(sign) with the manager clock fixed
// at 2026-09-15T12:00Z: usages without sign is exit 3 usage_refused, a
// not_after one hour in the past is exit 3 expired, a not_after exactly
// now is expired, a rev1 tag is exit 3 metadata_unknown, a record with no
// registry row (store enclave) is exit 1 unsupported_primitive, a forged
// record (title too long) is exit 3 metadata_unknown, an unknown address
// is exit 1 not_found — each with zero backend signs. Controls: usages
// sign with a not_after one hour ahead signs; verify by label still works
// for the verify-only and the expired key (verification needs no usage
// and no validity), and describe shows sign/verify via their commands.
func TestRunSignPolicyGates(t *testing.T) {
	fixed := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = time.Now })
	digest := digestHex("policy")
	stored := func(purpose string, mutate func(*keyvault.Record)) *memStore {
		label := tl(purpose, 1)
		store := newMemStore(label)
		item := store.keys[label]
		rec, _ := keyvault.DecodeRecord(item.Tag)
		mutate(&rec)
		item.Tag, _ = keyvault.EncodeRecord(rec)
		store.keys[label] = item
		return store
	}
	past, exact, future := keyvault.NewTime(fixed.Add(-time.Hour)), keyvault.NewTime(fixed), keyvault.NewTime(fixed.Add(time.Hour))
	cases := map[string]struct {
		mutate  func(*keyvault.Record)
		code    int
		errCode string
	}{
		"verify only": {func(r *keyvault.Record) { r.Usages = []string{"verify"} }, exitRefused, keyvault.CodeUsageRefused},
		"wrap only":   {func(r *keyvault.Record) { r.Usages = []string{"wrap"} }, exitRefused, keyvault.CodeUsageRefused},
		"expired":     {func(r *keyvault.Record) { r.Validity.NotAfter = &past }, exitRefused, keyvault.CodeExpired},
		"expires now": {func(r *keyvault.Record) { r.Validity.NotAfter = &exact }, exitRefused, keyvault.CodeExpired},
		// The memory store serves the keychain only.
		"store not served": {func(r *keyvault.Record) { r.Store = keyvault.StoreEnclave }, exitFailure, keyvault.CodeUnsupportedPrimitive},
		"forged title":     {func(r *keyvault.Record) { r.Title = strings.Repeat("x", 81) }, exitRefused, keyvault.CodeMetadataUnknown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := stored("gate", tc.mutate)
			useStore(t, store)
			code, resp, raw := runJSON(t, "sign", "test/gate", "--digest", digest)
			if code != tc.code || resp.Error == nil || resp.Error.Code != tc.errCode {
				t.Fatalf("code %d want %d %s: %s", code, tc.code, tc.errCode, raw)
			}
			if len(store.signs) != 0 {
				t.Fatalf("backend signed: %v", store.signs)
			}
		})
	}
	t.Run("rev1 tag", func(t *testing.T) {
		label := tl("legacy", 1)
		store := newMemStore()
		store.keys[label] = keyvault.Item{Label: label, Tag: []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"), SPKI: generatorSPKI(5)}
		useStore(t, store)
		if code, resp, raw := runJSON(t, "sign", "test/legacy", "--digest", digest); code != exitRefused || resp.Error.Code != keyvault.CodeMetadataUnknown || len(store.signs) != 0 {
			t.Fatalf("%s", raw)
		}
	})
	t.Run("not found", func(t *testing.T) {
		store := newMemStore(tl("present", 1))
		useStore(t, store)
		if code, resp, raw := runJSON(t, "sign", "test/absent", "--digest", digest); code != exitFailure || resp.Error.Code != "not_found" || len(store.signs) != 0 {
			t.Fatalf("%s", raw)
		}
	})
	t.Run("control future not_after signs", func(t *testing.T) {
		store := stored("gate", func(r *keyvault.Record) { r.Validity.NotAfter = &future })
		useStore(t, store)
		if code, _, raw := runJSON(t, "sign", "test/gate", "--digest", digest); code != exitOK || len(store.signs) != 1 {
			t.Fatalf("%s", raw)
		}
	})
	for name, mutate := range map[string]func(*keyvault.Record){
		"verify only": func(r *keyvault.Record) { r.Usages = []string{"verify"} },
		"expired":     func(r *keyvault.Record) { r.Validity.NotAfter = &past },
	} {
		t.Run("verify by label "+name, func(t *testing.T) {
			store := stored("gate", mutate)
			useStore(t, store)
			priv := signerFor(store.keys[tl("gate", 1)].SPKI)
			goSig, _ := ecdsa.SignASN1(rand.Reader, priv, hexBytes(t, digest))
			low, _ := keyvault.ParseSignature(goSig, keyvault.FormatSignatureDERLowS)
			lowDER, _ := low.LowS().Encode(keyvault.FormatSignatureDERLowS)
			if code, resp, raw := runJSON(t, "verify", "test/gate", "--digest", digest, "--sig", hex.EncodeToString(lowDER)); code != exitOK || resultMap(t, resp)["verified"] != true {
				t.Fatalf("%s", raw)
			}
			if len(store.signs) != 0 {
				t.Fatal("verify signed")
			}
		})
	}
	t.Run("verify by label store not served", func(t *testing.T) {
		store := stored("gate", func(r *keyvault.Record) { r.Store = keyvault.StoreEnclave })
		useStore(t, store)
		if code, resp, raw := runJSON(t, "verify", "test/gate", "--digest", digest, "--sig", strings.Repeat("11", 64), "--raw"); code != exitFailure || resp.Error.Code != keyvault.CodeUnsupportedPrimitive {
			t.Fatalf("%s", raw)
		}
	})
	t.Run("describe via", func(t *testing.T) {
		store := newMemStore(tl("via", 1))
		useStore(t, store)
		_, resp, raw := runJSON(t, "describe", "test/via")
		via := map[string]string{}
		for _, op := range resultMap(t, resp)["operations"].([]any) {
			via[op.(map[string]any)["name"].(string)] = op.(map[string]any)["via"].(string)
		}
		if via["ecdsa-sha256-sign"] != "sign" || via["ecdsa-sha256-verify"] != "verify" {
			t.Fatalf("%s", raw)
		}
	})
}

// A Security.framework failure from the bridge on sign is exit 1 security
// with the OSStatus attached, after the gates passed.
func TestRunSignSecurityFailure(t *testing.T) {
	store := newMemStore(tl("os", 1))
	store.signE = &keyvault.StatusError{Op: "sign", Status: -25293}
	useStore(t, store)
	code, resp, raw := runJSON(t, "sign", "test/os", "--digest", digestHex("os"))
	if code != exitFailure || resp.Error.Code != keyvault.CodeSecurity || resp.Error.Status != -25293 || len(store.signs) != 1 {
		t.Fatalf("%s", raw)
	}
}

// End-to-end through the production SecurityStore on this Mac: a key
// created by run(init) signs through run(sign); the DER verifies with
// crypto/ecdsa under run(pub)'s SPKI and with `openssl dgst -sha256
// -verify` (skipped when openssl is absent); a signature `openssl dgst
// -sign` made with a Go-generated key verifies through run(verify --spki)
// (interop both ways); run(verify) by label returns exit 0, a tampered
// signature exit 1 and a high-S twin exit 3; a key created with --usages
// verify refuses sign with usage_refused and a key with --not-after in the
// past refuses with expired, both without a bridge signature. Every label
// is under service test and deleted in cleanup.
func TestRunSignVerifyAgainstLoginKeychain(t *testing.T) {
	guard := &guardedBackend{t: t, inner: newTestSecurityStore(t)}
	useStore(t, guard)
	t.Cleanup(func() {
		for _, label := range guard.touched {
			if err := guard.inner.Delete(label); err != nil && !errors.Is(err, keyvault.ErrNotFound) {
				t.Errorf("cleanup %s: %v", label, err)
			}
		}
	})
	purpose := fmt.Sprintf("sign-e2e-%d", os.Getpid())
	addr := "test/" + purpose
	if code, _, raw := runJSON(t, initArgs(purpose, "--usages", "sign,verify")...); code != exitOK {
		t.Fatalf("init: %s", raw)
	}
	data := []byte("interop payload " + purpose)
	dataPath := writeTemp(t, "data.bin", data)
	digest := sha256.Sum256(data)
	sigPath := filepath.Join(t.TempDir(), "sig.der")
	code, resp, raw := runJSON(t, "sign", addr, "--data-file", dataPath, "--out", sigPath)
	if code != exitOK || resultMap(t, resp)["digest"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("sign: %s", raw)
	}
	der, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(t.TempDir(), "pub.pem")
	if code, _, raw := runJSON(t, "pub", addr, "--out", pemPath); code != exitOK {
		t.Fatalf("pub: %s", raw)
	}
	pemBytes, _ := os.ReadFile(pemPath)
	spki, pubKey, err := keyvault.ParseSPKI(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pubKey, digest[:], der) {
		t.Fatal("crypto/ecdsa rejects the keychain signature")
	}
	if sig, _ := keyvault.ParseSignature(der, keyvault.FormatSignatureDERLowS); !sig.IsLowS() {
		t.Fatal("emitted signature is not low-S")
	}
	_ = spki

	if code, resp, raw := runJSON(t, "verify", addr, "--data-file", dataPath, "--sig", "@"+sigPath); code != exitOK || resultMap(t, resp)["verified"] != true {
		t.Fatalf("verify by label: %s", raw)
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0x01
	if code, resp, raw := runJSON(t, "verify", addr, "--digest", hex.EncodeToString(digest[:]), "--sig", hex.EncodeToString(tampered)); code != exitFailure || resp.Error.Code != keyvault.CodeSignatureInvalid {
		t.Fatalf("tampered: %s", raw)
	}
	if code, resp, raw := runJSON(t, "verify", "--spki", pemPath, "--digest", hex.EncodeToString(digest[:]), "--sig", hex.EncodeToString(highSTwin(t, der))); code != exitRefused || resp.Error.Code != keyvault.CodeHighSRefused {
		t.Fatalf("high-S: %s", raw)
	}

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Log("openssl not on PATH; openssl interop not run")
	} else {
		out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pemPath, "-signature", sigPath, dataPath).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Verified OK") {
			t.Fatalf("openssl verify: %v %s", err, out)
		}
		// openssl -> this: sign with a Go-generated key through openssl,
		// verify through run(verify --spki).
		goKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkcs8, _ := x509.MarshalPKCS8PrivateKey(goKey)
		goPriv := writeTemp(t, "go.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
		goSPKI, _ := x509.MarshalPKIXPublicKey(&goKey.PublicKey)
		goPub := writeTemp(t, "go.pem", keyvault.EncodePEM(goSPKI))
		osslSig := filepath.Join(t.TempDir(), "ossl.der")
		if out, err := exec.Command(openssl, "dgst", "-sha256", "-sign", goPriv, "-out", osslSig, dataPath).CombinedOutput(); err != nil {
			t.Fatalf("openssl sign: %v %s", err, out)
		}
		osslDER, _ := os.ReadFile(osslSig)
		sig, err := keyvault.ParseSignature(osslDER, keyvault.FormatSignatureDERLowS)
		if err != nil {
			t.Fatalf("openssl DER: %v", err)
		}
		args := []string{"verify", "--spki", goPub, "--data-file", dataPath, "--sig", "@" + osslSig}
		if !sig.IsLowS() {
			args = append(args, "--allow-high-s") // openssl does not normalise
		}
		if code, resp, raw := runJSON(t, args...); code != exitOK || resultMap(t, resp)["verified"] != true {
			t.Fatalf("openssl signature: %s", raw)
		}
	}

	verifyOnly := purpose + "-vo"
	if code, _, raw := runJSON(t, initArgs(verifyOnly, "--usages", "verify")...); code != exitOK {
		t.Fatalf("init verify-only: %s", raw)
	}
	if code, resp, raw := runJSON(t, "sign", "test/"+verifyOnly, "--digest", hex.EncodeToString(digest[:])); code != exitRefused || resp.Error.Code != keyvault.CodeUsageRefused {
		t.Fatalf("usage_refused: %s", raw)
	}
	expired := purpose + "-exp"
	if code, _, raw := runJSON(t, initArgs(expired, "--usages", "sign", "--not-after", "2026-01-01T00:00:00Z")...); code != exitOK {
		t.Fatalf("init expired: %s", raw)
	}
	if code, resp, raw := runJSON(t, "sign", "test/"+expired, "--digest", hex.EncodeToString(digest[:])); code != exitRefused || resp.Error.Code != keyvault.CodeExpired {
		t.Fatalf("expired: %s", raw)
	}
	for _, touched := range guard.touched {
		if !keyvault.IsTestLabel(touched) {
			t.Fatalf("non-test label touched: %s", touched)
		}
	}
}
