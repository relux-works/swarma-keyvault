package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Only public fixture material is written; there is no vault or provider setup.
func prepareCLIFixture(t *testing.T) ([]string, []byte, string) {
	t.Helper()
	curve := elliptic.P256()
	spki, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "public.der")
	if err := os.WriteFile(path, spki, 0600); err != nil {
		t.Fatal(err)
	}
	draft := []byte(`{"audience":{"deployment_id":"fixture","executor_id":"fixture"},"certificate_id":"fixture","cycles":[{"channel":"encrypted-dm","cycle_id":"codex-dm","runtime":"codex"}],"expires_at":"2026-11-04T03:00:00Z","name":"fixture","not_before":"2026-11-04T02:00:00Z","organization":"fixture","subject":{"account_mxid":"@fixture:example.invalid","device_ed25519":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_id":"FIXTURE"}}`)
	return append([]string{"grants", "prepare", "--plan", "-", "--owner-mxid", "@owner:example.invalid", "--issuer-spki-der", path},
		"--owner-key", fixtureOwnerService+"/grants-owner-v1", "--owner-key-version", "1"), draft, dir
}

// The real CLI path authors exact canonical stdout without LF, prints all
// fields and an independently calculated domain digest to the review stream,
// and writes no files. File/stdin and standard flag spellings stay compatible.
func TestPrepareCLI(t *testing.T) {
	for _, mode := range []string{"stdin", "file", "equals"} {
		t.Run(mode, func(t *testing.T) {
			args, draft, dir := prepareCLIFixture(t)
			if mode == "file" {
				args[3] = filepath.Join(dir, "draft.json")
				if err := os.WriteFile(args[3], draft, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "equals" {
				args = []string{"grants", "prepare", "-plan=-", "--owner-mxid=@owner:example.invalid", "-issuer-spki-der=" + args[7],
					"--owner-key=" + fixtureOwnerService + "/grants-owner-v1", "--owner-key-version=1"}
			}
			before, _ := os.ReadDir(dir)
			var out, review bytes.Buffer
			if code := run(args, bytes.NewReader(draft), &out, &review); code != 0 {
				t.Fatalf("code%d: %s", code, review.String())
			}
			if out.Len() == 0 || bytes.HasSuffix(out.Bytes(), []byte{'\n'}) {
				t.Fatal("payload missing or newline appended")
			}
			var payload map[string]any
			if err := json.Unmarshal(out.Bytes(), &payload); err != nil || payload["type"] != "grants-certificate-1" {
				t.Fatal("not a certificate payload", err)
			}
			digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), out.Bytes()...))
			parts := strings.SplitN(review.String(), "\n", 5)
			if len(parts) != 5 || !strings.HasPrefix(parts[0], "Owner key pin: ") || !strings.Contains(parts[1], "UNSIGNED") || !strings.HasSuffix(parts[3], hex.EncodeToString(digest[:])) {
				t.Fatal("review missing unsigned status/digest")
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(parts[4])); err != nil || !bytes.Equal(compact.Bytes(), out.Bytes()) {
				t.Fatal("review differs from exact stdout", err)
			}
			after, _ := os.ReadDir(dir)
			if len(after) != len(before) {
				t.Fatal("prepare created files")
			}
		})
	}
}

type mustNotRead struct{}

func (mustNotRead) Read([]byte) (int, error) { panic("invalid arguments read input") }

// Unknown/duplicate/missing/ambiguous arguments refuse before reading input and
// emit no payload. Prepare flags cannot redirect to a signing/effect operation.
func TestPrepareCLIArguments(t *testing.T) {
	args, _, _ := prepareCLIFixture(t)
	for _, bad := range [][]string{
		nil, {"grants", "sign"}, {"grants", "prepare"},
		append(append([]string{}, args...), "extra"),
		append(append([]string{}, args...), "--unknown=x"),
		append(append([]string{}, args...), "--owner-mxid=@other:example.invalid"),
		{"grants", "prepare", "--plan=-", "--owner-mxid=@owner:example.invalid", "--issuer-spki-der=-"},
	} {
		var out, errout bytes.Buffer
		if code := run(bad, mustNotRead{}, &out, &errout); code != 2 || out.Len() != 0 {
			t.Fatalf("bad arguments: code%d out%d", code, out.Len())
		}
	}
}

// Bounded input errors cannot produce a review/payload. The direct reader test
// proves the max+1 ingress bound rather than merely observing parser rejection.
func TestPrepareCLIInputs(t *testing.T) {
	args, draft, _ := prepareCLIFixture(t)
	for _, bad := range [][]byte{append(bytes.Clone(draft), '\n'), bytes.Repeat([]byte{'x'}, 65537), []byte(`{}`)} {
		var out, errout bytes.Buffer
		if code := run(args, bytes.NewReader(bad), &out, &errout); code != 1 || out.Len() != 0 || strings.Contains(errout.String(), "UNSIGNED") {
			t.Fatalf("bad input: code%d out%d review%s", code, out.Len(), errout.String())
		}
	}
	input := bytes.NewReader(bytes.Repeat([]byte{'x'}, 65538))
	if raw, err := readInput("-", input, 65536); raw != nil || err == nil || input.Len() != 1 {
		t.Fatal("reader did not stop at max+1")
	}
	args[7] = filepath.Join(t.TempDir(), "absent.der")
	var out, errout bytes.Buffer
	if code := run(args, bytes.NewReader(draft), &out, &errout); code != 1 || out.Len() != 0 || strings.Contains(errout.String(), args[7]) {
		t.Fatal("unavailable public key leaked path or produced payload")
	}
}

type failingOutput struct{ short bool }

func (w failingOutput) Write(p []byte) (int, error) {
	if w.short {
		return len(p) / 2, nil
	}
	return 0, errors.New("fixture write failure")
}

// An unavailable/incomplete owner review prevents payload release. A failed or
// short payload write is reported as failure, not a complete prepared document.
func TestPrepareCLIOutputFailures(t *testing.T) {
	args, draft, _ := prepareCLIFixture(t)
	for _, writer := range []io.Writer{failingOutput{}, failingOutput{short: true}} {
		var out bytes.Buffer
		if code := run(args, bytes.NewReader(draft), &out, writer); code != 1 || out.Len() != 0 {
			t.Fatalf("failed review released payload: code%d out%d", code, out.Len())
		}
		if code := run(args, bytes.NewReader(draft), writer, io.Discard); code != 1 {
			t.Fatal("failed/short payload write reported success")
		}
	}
}

// Ordinary directories, devices and an unopened FIFO refuse before open/read.
// The valid regular-file and stdin controls are exercised by TestPrepareCLI.
// This does not assert protection against a concurrent same-user path swap.
func TestPrepareCLINonRegularInput(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "input.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, os.DevNull, fifo} {
		raw, err := readInput(path, mustNotRead{}, 65536)
		if err == nil || raw != nil || err.Error() != "regular input file required" {
			t.Fatalf("nonregular input accepted: %q %v", path, err)
		}
	}
}

// Public preparation displays the exact independently configured address and
// SPKI hash. Changing only the address alters review while retaining payload
// bytes. Missing exact address refuses before reading the input stream.
func TestPublicPrepareConfiguredKeyAssociation(t *testing.T) {
	args, draft, _ := prepareCLIFixture(t)
	var payloadA, reviewA bytes.Buffer
	if code := run(args, bytes.NewReader(draft), &payloadA, &reviewA); code != 0 {
		t.Fatal("valid preparation refused", code)
	}
	changed := append([]string(nil), args...)
	for i, arg := range changed {
		if arg == "--owner-key" {
			changed[i+1] = "south/grants-owner-v1"
		}
	}
	var payloadB, reviewB bytes.Buffer
	if code := run(changed, bytes.NewReader(draft), &payloadB, &reviewB); code != 0 || !bytes.Equal(payloadA.Bytes(), payloadB.Bytes()) || reviewA.String() == reviewB.String() || !strings.HasPrefix(reviewB.String(), "Owner key pin: key/south/grants-owner-v1@1 sha256:") {
		t.Fatal("address omitted or signed payload changed", code)
	}
	missing := append([]string(nil), args[:8]...)
	var out, diag bytes.Buffer
	if code := run(missing, mustNotRead{}, &out, &diag); code != 2 || out.Len() != 0 {
		t.Fatal("missing address consumed input", code)
	}
}
