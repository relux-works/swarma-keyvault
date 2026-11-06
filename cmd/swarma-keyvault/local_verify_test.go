package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func verifyCLIBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Only the existing process-local synthetic fixture keys are used for test setup.
func verifyCLISigned(t *testing.T, key *ecdsa.PrivateKey, domain, kind string, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(append([]byte(domain+"\n"), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		s.Sub(key.Params().N, s)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return verifyCLIBytes(t, map[string]string{"type": kind, "payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawURLEncoding.EncodeToString(signature)})
}

func verifyCLIFixture(t *testing.T) ([]string, []byte) {
	t.Helper()
	_, raw, owner := issueCLIFixture(t)
	_, _, requester := issueCLIFixture(t)
	var certificate map[string]any
	if err := json.Unmarshal(raw, &certificate); err != nil {
		t.Fatal(err)
	}
	delete(certificate["subject"].(map[string]any), "device_ed25519")
	certificate["type"] = "grants-local-certificate-1"
	hash := sha256.Sum256(requester.item.SPKI)
	certificate["requester_spki_sha256"] = hex.EncodeToString(hash[:])
	entry := certificate["entries"].([]any)[0].(map[string]any)
	use := entry["uses"].([]any)[0].(map[string]any)
	cycle := certificate["cycles"].([]any)[0].(map[string]any)
	request := map[string]any{"type": "grants-local-operation-1", "request_id": "local-request", "certificate_id": certificate["certificate_id"], "entry_id": entry["entry_id"], "cycle_id": use["cycle_id"], "operation_use_id": use["operation_use_id"], "subject": certificate["subject"], "audience": certificate["audience"], "action": "repository.create", "target": entry["target"], "expires_at": certificate["expires_at"]}
	root := t.TempDir()
	config := map[string]any{"type": "grants-local-enrollment-2", "owner_mxid": grants.LocalOwnerMXID,
		"owner_spki": base64.RawURLEncoding.EncodeToString(owner.item.SPKI), "requester_spki": base64.RawURLEncoding.EncodeToString(requester.item.SPKI),
		"subject": certificate["subject"], "audience": certificate["audience"], "cycle": cycle, "organization": grants.LocalOrganization, "name": grants.LocalRepository,
		"state_dir": filepath.Join(root, "ABSENT-STATE"), "gh_path": filepath.Join(root, "ABSENT-PROVIDER")}
	configPath, certPath := filepath.Join(root, "config.json"), filepath.Join(root, "certificate.json")
	for path, data := range map[string][]byte{configPath: verifyCLIBytes(t, config), certPath: verifyCLISigned(t, owner.key, "swarma-grants/local-certificate/1", "grants-signed-local-certificate-1", verifyCLIBytes(t, certificate))} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	previousIssue, previousRequest, previousExecute := newIssueManager, newRequestManager, executeLocal
	t.Cleanup(func() {
		newIssueManager, newRequestManager, executeLocal = previousIssue, previousRequest, previousExecute
	})
	newIssueManager = func(func([]byte) string) *keyvault.Manager { t.Fatal("verify constructed issuer"); return nil }
	newRequestManager = func() *keyvault.Manager { t.Fatal("verify constructed requester"); return nil }
	executeLocal = func(*grants.LocalEnrollment, []byte, []byte) (*grants.LocalOutcome, error) {
		t.Fatal("verify invoked mediator")
		return nil, nil
	}
	return []string{"grants", "verify", "--config", configPath, "--certificate", certPath, "--request", "-", "--at", certificate["not_before"].(string)}, verifyCLISigned(t, requester.key, "swarma-grants/local-request/2", "grants-local-request-2", verifyCLIBytes(t, request))
}

// Claim: Actual CLI dispatch accepts file/stdin, preserves explicit observation instants, and reports failed/short output writes.
func TestLocalVerifyCLIOutput(t *testing.T) {
	args, request := verifyCLIFixture(t)
	var out, stderr bytes.Buffer
	if code := run(args, bytes.NewReader(request), &out, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(out.String(), `"verdict":"accepted"`) || bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		t.Fatal("valid CLI", code, out.String(), stderr.String())
	}
	file := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(file, request, 0600); err != nil {
		t.Fatal(err)
	}
	args[7] = file
	for _, writer := range []io.Writer{failingOutput{}, failingOutput{short: true}} {
		stderr.Reset()
		if code := run(args, nil, writer, &stderr); code != 1 {
			t.Fatal("output failure reported acceptance", code)
		}
	}
	var fileOut bytes.Buffer
	if code := run(args, nil, &fileOut, &stderr); code != 0 || !bytes.Equal(fileOut.Bytes(), out.Bytes()) {
		t.Fatal("file/stdin verdict differs", code, stderr.String())
	}
	instant, err := time.Parse(time.RFC3339, args[9])
	if err != nil {
		t.Fatal(err)
	}
	args[9] = instant.In(time.FixedZone("fixture offset", 3600)).Format(time.RFC3339)
	fileOut.Reset()
	if code := run(args, nil, &fileOut, &stderr); code != 0 || !bytes.Equal(fileOut.Bytes(), out.Bytes()) {
		t.Fatal("equivalent RFC3339 offset changed verdict", code, stderr.String())
	}
}

// Claim: Missing, repeated, unknown, positional and malformed time arguments exit 2 without output or private/executor construction.
func TestLocalVerifyCLIUsage(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "config-stdin", "certificate-stdin", "duplicate", "unknown", "positional", "bad-time", "empty-time", "duplicate-time"} {
		t.Run(mode, func(t *testing.T) {
			args, q := verifyCLIFixture(t)
			switch mode {
			case "missing":
				args = args[:6]
			case "empty":
				args[7] = ""
			case "config-stdin":
				args[3] = "-"
			case "certificate-stdin":
				args[5] = "-"
			case "duplicate":
				args = append(args, "--request=-")
			case "unknown":
				args = append(args, "--owner-spki-der=override")
			case "positional":
				args = append(args, "extra")
			case "bad-time":
				args[9] = "yesterday"
			case "empty-time":
				args[9] = ""
			case "duplicate-time":
				args = append(args, "--at", args[9])
			}
			var out, stderr bytes.Buffer
			if code := run(args, bytes.NewReader(q), &out, &stderr); code != 2 || out.Len() != 0 || stderr.String() != verifyUsage+"\n" {
				t.Fatal("usage contract", code, out.String(), stderr.String())
			}
		})
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"grants", "verify", "--help"}, nil, &out, &stderr); code != 0 || out.Len() != 0 || stderr.String() != verifyUsage+"\n" {
		t.Fatal("help contract", code, stderr.String())
	}
}

// Claim: Enrollment/file errors and bounded or nonregular inputs refuse with exit 1 and never reach private or execution factories.
func TestLocalVerifyCLIInputs(t *testing.T) {
	for _, mode := range []string{"config-absent", "config-mode", "config-symlink", "config-limit", "certificate-limit", "certificate-directory", "certificate-fifo", "request-limit", "stdin-limit", "stdin-absent", "malformed", "wall-clock"} {
		t.Run(mode, func(t *testing.T) {
			args, q := verifyCLIFixture(t)
			want := "refused: required-state-unavailable\n"
			var input io.Reader = bytes.NewReader(q)
			switch mode {
			case "config-absent":
				args[3] += ".absent"
			case "config-mode":
				if err := os.Chmod(args[3], 0644); err != nil {
					t.Fatal(err)
				}
			case "config-symlink":
				if err := os.Symlink(args[3], args[3]+".link"); err != nil {
					t.Fatal(err)
				}
				args[3] += ".link"
			case "config-limit":
				if err := os.WriteFile(args[3], bytes.Repeat([]byte{'x'}, 8193), 0600); err != nil {
					t.Fatal(err)
				}
				want = "refused: input-limit-exceeded\n"
			case "certificate-limit":
				if err := os.WriteFile(args[5], bytes.Repeat([]byte{'x'}, 98305), 0600); err != nil {
					t.Fatal(err)
				}
				want = "refused: cannot read bounded certificate envelope\n"
			case "certificate-directory", "certificate-fifo":
				args[5] = t.TempDir()
				if mode == "certificate-fifo" {
					args[5] = filepath.Join(args[5], "fifo")
					if err := syscall.Mkfifo(args[5], 0600); err != nil {
						t.Fatal(err)
					}
				}
				want = "refused: cannot read bounded certificate envelope\n"
			case "request-limit", "stdin-limit":
				reader := bytes.NewReader(bytes.Repeat([]byte{'x'}, 12290))
				input = reader
				if mode == "request-limit" {
					args[7] = filepath.Join(t.TempDir(), "large.json")
					if err := os.WriteFile(args[7], bytes.Repeat([]byte{'x'}, 12289), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					t.Cleanup(func() {
						if reader.Len() != 1 {
							t.Error("stdin was not bounded at maximum+1", reader.Len())
						}
					})
				}
				want = "refused: cannot read bounded local request envelope\n"
			case "stdin-absent":
				input = nil
				want = "refused: cannot read bounded local request envelope\n"
			case "malformed":
				input = bytes.NewReader(append(q, '\n'))
				want = "refused: bad-encoding\n"
			case "wall-clock":
				args = args[:8]
				want = "refused: grant validity has expired\n"
			}
			var out, stderr bytes.Buffer
			if code := run(args, input, &out, &stderr); code != 1 || out.Len() != 0 || stderr.String() != want {
				t.Fatal("bounded input refusal", code, out.String(), stderr.String(), "want", want)
			}
		})
	}
}
