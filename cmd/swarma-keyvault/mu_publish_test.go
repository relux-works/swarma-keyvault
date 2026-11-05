package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// TestMain lets the test binary act as a fake mac-keyvault for "sign": it
// checks the exact argv the publisher job uses and signs the digest with a
// test-only scalar. It never touches a real key or Keychain.
func TestMain(m *testing.M) {
	if d := os.Getenv("MU_FAKE_KEYVAULT_D"); d != "" && len(os.Args) == 9 && os.Args[1] == "sign" {
		os.Exit(muFakeSign(d))
	}
	os.Exit(m.Run())
}

func muFakeSign(dHex string) int {
	a := os.Args
	if os.Getenv("MU_FAKE_KEYVAULT_FAIL") == "1" || a[2] != os.Getenv("MU_FAKE_SIGNER") || a[3] != "--digest" || a[5] != "--format" || a[6] != "ecdsa-der-low-s" || a[7] != "--out" {
		return 3
	}
	digest, err := hex.DecodeString(a[4])
	if err != nil || len(digest) != 32 {
		return 4
	}
	d, ok := new(big.Int).SetString(dHex, 16)
	if !ok {
		return 5
	}
	k := &ecdsa.PrivateKey{D: d}
	k.PublicKey.Curve = elliptic.P256()
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	der, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil || os.WriteFile(a[8], der, 0600) != nil {
		return 6
	}
	return 0
}

type muPublishRig struct {
	exe, exeSHA, publisher, entries, out string
}

func newPublishRig(t *testing.T, entries string) *muPublishRig {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // software stand-in
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	publisher, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(exe)
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	t.Setenv("MU_FAKE_KEYVAULT_D", hex.EncodeToString(k.D.Bytes()))
	t.Setenv("MU_FAKE_SIGNER", "grant-revocation/publisher")
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")
	if err := os.WriteFile(path, []byte(entries), 0600); err != nil {
		t.Fatal(err)
	}
	return &muPublishRig{exe: exe, exeSHA: hex.EncodeToString(h.Sum(nil)), publisher: publisher, entries: path, out: filepath.Join(dir, "snapshot.json")}
}

func (r *muPublishRig) run(extra ...string) (int, string, string) {
	args := []string{"grants", "mu-revocation-publish", "--publisher", r.publisher, "--signer", "grant-revocation/publisher", "--keyvault", r.exe, "--keyvault-sha256", r.exeSHA, "--entries", r.entries, "--out", r.out, "--interval", "30s", "--once"}
	return muCLIRun(append(args, extra...)...)
}

const muEntries = `[{"kind":"record","id":"sha256:aaaa","from":"2026-11-05T10:00:00Z"},{"kind":"key","id":"p256:revoked","from":"2026-11-05T10:00:00Z"}]`

// Claim: one cycle publishes a complete revocation/1 snapshot whose issuer is
// the publisher key, whose entries are the file's entries, and whose
// signature verifies with the platform library under the publisher key.
func TestMUPublishOnce(t *testing.T) {
	r := newPublishRig(t, muEntries)
	if code, _, errText := r.run(); code != 0 {
		t.Fatal(code, errText)
	}
	wire, err := os.ReadFile(r.out)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Body struct {
			Type, Issuer string
			Complete     bool
			Entries      []mugrant.SnapshotEntry
		}
		Signatures []struct{ Key, Role, Sig string }
	}
	if err := json.Unmarshal(wire, &e); err != nil || e.Body.Type != "revocation/1" || e.Body.Issuer != r.publisher || !e.Body.Complete || len(e.Body.Entries) != 2 || len(e.Signatures) != 1 {
		t.Fatal("snapshot shape", err, string(wire))
	}
	parsed, _ := record.Parse(wire, 65536, 16)
	body := parsed.(map[string]any)["body"].(map[string]any)
	pre, err := record.SigningPreimage("revocation/1", r.publisher, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := record.DecodeBase64(e.Signatures[0].Sig, 64)
	if err != nil || record.VerifySignature(r.publisher, sig, pre) != nil {
		t.Fatal("snapshot signature does not verify", err)
	}
	if st, _ := os.Stat(r.out); st.Mode().Perm() != 0600 {
		t.Fatal("snapshot mode", st.Mode())
	}
}

// Claim: a failed cycle writes nothing and leaves the previous snapshot
// byte-identical: keyvault digest drift, signer failure, a signature by
// another key, and malformed entries. Usage bounds refuse with exit 2.
func TestMUPublishFailuresKeepPrevious(t *testing.T) {
	r := newPublishRig(t, muEntries)
	if code, _, errText := r.run(); code != 0 {
		t.Fatal(code, errText)
	}
	before, _ := os.ReadFile(r.out)
	check := func(name string) {
		t.Helper()
		after, _ := os.ReadFile(r.out)
		if !bytes.Equal(before, after) {
			t.Fatal("failed cycle replaced the snapshot", name)
		}
	}
	good := *r
	r.exeSHA = strings.Repeat("0", 64)
	if code, _, _ := r.run(); code != 1 {
		t.Fatal("digest drift published")
	}
	check("digest-drift")
	*r = good
	t.Setenv("MU_FAKE_KEYVAULT_FAIL", "1")
	if code, _, _ := r.run(); code != 1 {
		t.Fatal("signer failure published")
	}
	check("signer-failure")
	t.Setenv("MU_FAKE_KEYVAULT_FAIL", "")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Setenv("MU_FAKE_KEYVAULT_D", hex.EncodeToString(other.D.Bytes()))
	if code, _, _ := r.run(); code != 1 {
		t.Fatal("foreign signature published")
	}
	check("wrong-key")
	if err := os.WriteFile(r.entries, []byte(`[{"kind":"record","id":"x","from":"2026-11-05T10:00:00Z","note":"y"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := r.run(); code != 1 {
		t.Fatal("malformed entries published")
	}
	check("bad-entries")
	for name, iv := range map[string]string{"zero": "0s", "over-60s": "61s", "garbage": "soon"} {
		args := []string{"grants", "mu-revocation-publish", "--publisher", r.publisher, "--signer", "s/p", "--keyvault", r.exe, "--keyvault-sha256", r.exeSHA, "--entries", r.entries, "--out", r.out, "--interval", iv, "--once"}
		if code, _, _ := muCLIRun(args...); code != 2 {
			t.Fatal("interval admitted", name)
		}
	}
}
