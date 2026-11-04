package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func localCLIFixture(t *testing.T) ([]string, []byte, *cliIssueStore) {
	t.Helper()
	issueArgs, payload, store := issueCLIFixture(t)
	var certificate map[string]any
	if err := json.Unmarshal(payload, &certificate); err != nil {
		t.Fatal(err)
	}
	entry := certificate["entries"].([]any)[0].(map[string]any)
	use := entry["uses"].([]any)[0].(map[string]any)
	request := map[string]any{"type": "grants-request-1", "request_id": "local-request", "certificate_id": certificate["certificate_id"], "entry_id": entry["entry_id"], "cycle_id": use["cycle_id"], "operation_use_id": use["operation_use_id"], "subject": certificate["subject"], "audience": certificate["audience"], "action": "repository.create", "target": entry["target"], "expires_at": certificate["expires_at"]}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	record, problem := keyvault.DecodeRecord(store.item.Tag)
	if problem != "" {
		t.Fatal(problem)
	}
	record.Service = "swarma-grants"
	record.Purpose = "requester-local-v1"
	record.UserPresence = false
	store.item.Label = record.Label()
	store.item.Tag, err = keyvault.EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	previous := newRequestManager
	t.Cleanup(func() { newRequestManager = previous })
	newRequestManager = func() *keyvault.Manager { store.factories++; return keyvault.NewManager(store, nil, keyvault.Origin{}) }
	return []string{"grants", "request", "--payload", "-", "--requester-spki-der", issueArgs[5]}, raw, store
}

// Actual requester CLI dispatch signs the distinct local domain once with a
// fake non-presence key; exact payload and signature verify independently.
func TestLocalRequestCLI(t *testing.T) {
	args, payload, store := localCLIFixture(t)
	var out, stderr bytes.Buffer
	if code := run(args, bytes.NewReader(payload), &out, &stderr); code != 0 || store.signs != 1 || store.factories != 1 {
		t.Fatal("request dispatch", code, store.signs, stderr.String())
	}
	var envelope map[string]string
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(envelope["signature"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("swarma-grants/local-request/1\n"), payload...))
	if envelope["type"] != "grants-local-request-1" || !bytes.Equal(raw, payload) || !ecdsa.VerifyASN1(&store.key.PublicKey, digest[:], sig) || stderr.Len() != 0 {
		t.Fatal("local request signature/output mismatch")
	}
}

// The requester cannot select a blind digest/key; bad payloads and unexpected
// presence/generation/pin refuse before a private call. Backend denial does not
// retry, and failed output reports failure after only the one attempt.
func TestLocalRequestCLIRefusals(t *testing.T) {
	for _, mode := range []string{"bad-flags", "malformed", "presence", "generation", "purpose", "store", "extraction", "pin", "denied", "output"} {
		t.Run(mode, func(t *testing.T) {
			args, payload, store := localCLIFixture(t)
			want := 0
			var out, stderr bytes.Buffer
			var writer io.Writer = &out
			switch mode {
			case "bad-flags":
				args = append(args, "--key=other/key")
			case "malformed":
				payload = append(payload, '\n')
			case "presence", "generation", "purpose", "store", "extraction":
				r, _ := keyvault.DecodeRecord(store.item.Tag)
				if mode == "presence" {
					r.UserPresence = true
				} else if mode == "generation" {
					r.Version = 2
					store.item.Label = r.Label()
				} else if mode == "purpose" {
					r.Purpose = "another-purpose"
					store.item.Label = r.Label()
				} else if mode == "store" {
					r.Store = keyvault.StoreKeychain
				} else {
					r.Extraction = keyvault.ExtractionHuman
				}
				store.item.Tag, _ = keyvault.EncodeRecord(r)
			case "pin":
				_, _, other := issueCLIFixture(t)
				store.item.SPKI = other.item.SPKI
			case "denied":
				store.deny = true
				want = 1
			case "output":
				writer = failingOutput{short: true}
				want = 1
			}
			if code := run(args, bytes.NewReader(payload), writer, &stderr); code == 0 || store.signs != want || out.Len() != 0 {
				t.Fatal("request refusal", code, store.signs, out.Len())
			}
		})
	}
}

func executeCLIFixture(t *testing.T) ([]string, []byte) {
	t.Helper()
	_, _, first := issueCLIFixture(t)
	_, _, second := issueCLIFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"type": "grants-local-enrollment-1", "owner_mxid": grants.LocalOwnerMXID, "owner_spki": base64.RawURLEncoding.EncodeToString(first.item.SPKI), "requester_spki": base64.RawURLEncoding.EncodeToString(second.item.SPKI), "subject": map[string]any{"account_mxid": "@fixture:example.invalid", "device_id": "FIXTURE", "device_ed25519": strings.Repeat("A", 43)}, "audience": map[string]any{"deployment_id": "fixture", "executor_id": "fixture"}, "cycle": map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}, "organization": grants.LocalOrganization, "name": grants.LocalRepository, "state_dir": root, "gh_path": "/fixture/gh"}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "enrollment.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	certificate := filepath.Join(root, "certificate.json")
	if err := os.WriteFile(certificate, []byte("certificate fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"grants", "execute", "--config", file, "--certificate", certificate, "--request", "-"}, []byte("request fixture")
}

// These CLI tests cover argument/config/IO dispatch only. The fake executor is
// not authority or provider validation; those are covered by mediator/docking
// tests using actual signature checks, journal replay and the process adapter.
func TestLocalExecuteCLIDispatch(t *testing.T) {
	args, request := executeCLIFixture(t)
	previous := executeLocal
	t.Cleanup(func() { executeLocal = previous })
	calls := 0
	executeLocal = func(_ *grants.LocalEnrollment, c, q []byte) (*grants.LocalOutcome, error) {
		calls++
		if string(c) != "certificate fixture" || !bytes.Equal(q, request) {
			t.Fatal("CLI substituted received bytes")
		}
		return &grants.LocalOutcome{State: "succeeded", RepositoryID: "42"}, nil
	}
	var out, stderr bytes.Buffer
	if code := run(args, bytes.NewReader(request), &out, &stderr); code != 0 || calls != 1 || !strings.Contains(out.String(), `"state":"succeeded"`) {
		t.Fatal("executor dispatch", code, calls, stderr.String())
	}
	if code := run(args, bytes.NewReader(request), failingOutput{}, &stderr); code != 1 || calls != 2 {
		t.Fatal("output failure retried executor", code, calls)
	}
}

// Unknown pin overrides, duplicate arguments, loose/symlink enrollment and
// oversized requests cannot reach even the executor seam.
func TestLocalExecuteCLIRefusals(t *testing.T) {
	for _, mode := range []string{"pin-override", "duplicate", "permissions", "symlink", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			args, request := executeCLIFixture(t)
			previous := executeLocal
			t.Cleanup(func() { executeLocal = previous })
			calls := 0
			executeLocal = func(*grants.LocalEnrollment, []byte, []byte) (*grants.LocalOutcome, error) { calls++; return nil, nil }
			switch mode {
			case "pin-override":
				args = append(args, "--owner-spki-der=other")
			case "duplicate":
				args = append(args, "--request=-")
			case "permissions":
				if err := os.Chmod(args[3], 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				original := args[3]
				args[3] = original + ".link"
				if err := os.Symlink(original, args[3]); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				request = bytes.Repeat([]byte{'x'}, 12289)
			}
			var out, stderr bytes.Buffer
			if code := run(args, bytes.NewReader(request), &out, &stderr); code == 0 || calls != 0 || out.Len() != 0 {
				t.Fatal("unsafe executor dispatch", code, calls)
			}
		})
	}
}
