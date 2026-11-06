package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func documentCLIFixture(t *testing.T, text string) ([]string, string, string) {
	t.Helper()
	dir := t.TempDir()
	file, pin, signature := filepath.Join(dir, "document.txt"), filepath.Join(dir, "public.der"), filepath.Join(dir, "signature.der")
	x, y := elliptic.P256().ScalarBaseMult([]byte{7})
	public, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(text))
	n := elliptic.P256().Params().N
	rx, _ := elliptic.P256().ScalarBaseMult([]byte{11})
	r := new(big.Int).Mod(rx, n)
	s := new(big.Int).Mul(r, big.NewInt(7))
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(big.NewInt(11), n)).Mod(s, n)
	der, err := (keyvault.Signature{R: r, S: s}).LowS().Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{file: []byte(text), pin: public, signature: der} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"--document", file, "--owner-spki-der", pin}, file, signature
}

func documentRun(args []string, output io.Writer) (int, string) {
	var stderr bytes.Buffer
	code := run(append([]string{"owner-document"}, args...), nil, output, &stderr)
	return code, stderr.String()
}

func TestOwnerDocumentCLIReviewVerifyRefuseNative(t *testing.T) {
	text := "Exact English.\n\nТочный русский.\n"
	args, file, signature := documentCLIFixture(t, text)
	previous := newIssueManager
	t.Cleanup(func() { newIssueManager = previous })
	newIssueManager = func(func([]byte) string) *keyvault.Manager {
		t.Fatal("unavailable native route accessed a manager")
		return nil
	}
	var output bytes.Buffer
	if code, err := documentRun(append([]string{"review"}, args...), &output); code != 0 || !strings.Contains(output.String(), text) || !strings.Contains(output.String(), "UNSIGNED") {
		t.Fatal(code, err, output.String())
	}
	output.Reset()
	verify := append(append([]string{"verify"}, args...), "--signature", signature)
	if code, err := documentRun(verify, &output); code != 0 || !strings.Contains(output.String(), "verified exact document") {
		t.Fatal(code, err)
	}
	output.Reset()
	if code, err := documentRun(append([]string{"sign"}, args...), &output); code != 1 || output.Len() != 0 || !strings.Contains(err, "owner-document-native-unavailable") {
		t.Fatal("native gap hidden", code, err)
	}
	if err := os.WriteFile(file, []byte(strings.TrimSuffix(text, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := documentRun(verify, &output); code != 1 || output.Len() != 0 || !strings.Contains(err, "verification refused") {
		t.Fatal("newline mutation verified", code, err)
	}
}

type documentMutatingWriter struct {
	file    string
	buffer  bytes.Buffer
	changed bool
}

func (w *documentMutatingWriter) Write(raw []byte) (int, error) {
	if !w.changed {
		w.changed = true
		if err := os.WriteFile(w.file, []byte("Changed source"), 0600); err != nil {
			return 0, err
		}
	}
	return w.buffer.Write(raw)
}

func TestOwnerDocumentCLIChangedDuringRender(t *testing.T) {
	args, file, _ := documentCLIFixture(t, "Exact source")
	w := &documentMutatingWriter{file: file}
	code, err := documentRun(append([]string{"review"}, args...), w)
	if code != 1 || !strings.Contains(err, "owner-document-changed") {
		t.Fatal("source change during render ignored", code, err)
	}
}

func TestOwnerDocumentCLIInputAndOutputRefusals(t *testing.T) {
	args, file, _ := documentCLIFixture(t, "Exact")
	for _, extra := range [][]string{{"--document", file}, {"--signature", file}, {"--unknown"}, {"positional"}} {
		var out bytes.Buffer
		all := append(append([]string{"sign"}, args...), extra...)
		if code, _ := documentRun(all, &out); code != 2 || out.Len() != 0 {
			t.Fatal("bad CLI shape accepted", all, code)
		}
	}
	for _, bad := range [][]byte{{0xff}, []byte("\x1b[2Jtext"), []byte("x\u202ey")} {
		if err := os.WriteFile(file, bad, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if code, _ := documentRun(append([]string{"review"}, args...), &out); code != 1 || out.Len() != 0 {
			t.Fatal("bad document rendered", code)
		}
	}
	if err := os.WriteFile(file, []byte("Exact"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := documentRun(append([]string{"review"}, args...), failingOutput{short: true}); code != 1 || !strings.Contains(err, "full rendering failed") {
		t.Fatal("short render accepted", code, err)
	}
}
