package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

// These are signer component controls. They do not qualify a reverse verifier
// or wrapper. Both owner identities use freshly generated synthetic keys.
func TestExpectedOwnerSigner(t *testing.T) {
	root := t.TempDir()
	custody := filepath.Join(root, "actors")
	if err := generate(custody); err != nil {
		t.Fatal(err)
	}
	ownerFile, requesterFile := filepath.Join(custody, "owner.der"), filepath.Join(custody, "requester.der")
	ownerDER, requesterDER := read(t, ownerFile), read(t, requesterFile)
	ownerKey := filepath.Join(custody, "owner.pk8")
	owner := keyAt(t, ownerKey)
	payloadPath := filepath.Join(root, "prepared.json")
	const domain = "swarma-grants/local-certificate/1"
	check := func(t *testing.T, label string, args []string, want int, diagnostic string) []byte {
		t.Helper()
		var out, stderr bytes.Buffer
		code := run(args, &out, &stderr)
		t.Logf("%s exit=%d stdout_bytes=%d stderr=%q", label, code, out.Len(), stderr.String())
		if code != want || !strings.Contains(stderr.String(), diagnostic) {
			t.Fatalf("%s: exit=%d stderr=%q", label, code, stderr.String())
		}
		if want != 0 && out.Len() != 0 {
			t.Fatal("refusal emitted output")
		}
		return bytes.Clone(out.Bytes())
	}
	for _, identity := range []struct{ owner, subject string }{
		{fixtureOwnerPrincipal, "@agent-south:example.invalid"},
		{"@owner-south:example.invalid", "@agent-north:example.invalid"},
	} {
		t.Run(identity.owner, func(t *testing.T) {
			draft := map[string]any{"certificate_id": "lab-owner-control", "subject": map[string]any{"account_mxid": identity.subject, "device_id": "LAB-AGENT"}, "audience": map[string]any{"deployment_id": "lab-thin-slice", "executor_id": "lab-verify-only"}, "cycles": []any{map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}}, "not_before": "2026-11-07T14:00:00Z", "expires_at": "2026-11-09T14:00:00Z", "organization": grants.LocalOrganization, "name": grants.LocalRepository}
			prepared, err := grants.PrepareLocalRepositoryCertificate(jsonBytes(t, draft), identity.owner, ownerDER, requesterDER)
			if err != nil {
				t.Fatal(err)
			}
			save(t, payloadPath, prepared.Payload)
			base := []string{"certificate", "--payload", payloadPath, "--digest", hex.EncodeToString(prepared.Digest[:]), "--key", ownerKey, "--owner-spki", ownerFile, "--requester-spki", requesterFile}
			explicit := append(append([]string(nil), base...), "--owner-mxid", identity.owner)
			positive := func(label string, args []string) {
				t.Helper()
				raw := check(t, label, args, 0, "")
				var outer map[string]string
				if err := json.Unmarshal(raw, &outer); err != nil {
					t.Fatal(err)
				}
				payload, err := base64.RawURLEncoding.DecodeString(outer["payload"])
				if err != nil || !bytes.Equal(payload, prepared.Payload) || outer["type"] != "grants-signed-local-certificate-1" || len(raw) >= 98304 {
					t.Fatal("exact envelope contract changed")
				}
				sig, err := base64.RawURLEncoding.DecodeString(outer["signature"])
				if err != nil || !ecdsa.VerifyASN1(&owner.PublicKey, prepared.Digest[:], sig) {
					t.Fatal("signature invalid")
				}
				var pair struct{ R, S *big.Int }
				rest, err := asn1.Unmarshal(sig, &pair)
				if err != nil || len(rest) != 0 || pair.S == nil || pair.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(owner.Params().N), 1)) > 0 {
					t.Fatal("noncanonical signature")
				}
				if digestFor(domain, payload) != base[4] || digestFor("swarma-grants/certificate/1", payload) == base[4] {
					t.Fatal("domain changed")
				}
			}
			positive("explicit-owner-positive", explicit)
			check(t, "missing-explicit-owner", base, 2, "")
			// An absent key makes reaching key loading observable in diagnostics.
			preflight := append([]string(nil), explicit...)
			preflight[6] = filepath.Join(custody, "ABSENT.pk8")
			for _, value := range []string{"@other:example.invalid", "invalid", "@owner-south:", "@owner-south:bad host", "@owner-south:example.invalid\n", strings.Repeat("x", 513)} {
				args := append([]string(nil), preflight...)
				args[len(args)-1] = value
				if value == "@other:example.invalid" {
					check(t, "wrong-owner-before-key", args, 1, "issuer-untrusted")
				} else {
					check(t, "malformed-owner-before-key", args, 2, "")
				}
			}
			for _, option := range [][]string{{"--owner-mxid="}, {"--owner-mxid", ""}, {"--owner-mxid"}, {"--owner-mxid", identity.owner, "--owner-mxid=" + identity.owner}, {"-owner-mxid", identity.owner, "--owner-mxid", identity.owner}, {"--owner-mxid=" + identity.owner, "-owner-mxid=" + identity.owner}} {
				check(t, "empty-missing-or-duplicate-owner", append(append([]string(nil), base...), option...), 2, "")
			}
			for _, mode := range []string{"keygen", "unknown"} {
				args := []string{mode, "--owner-mxid", identity.owner, "--dir", filepath.Join(root, "must-not-exist")}
				check(t, "wrong-mode-before-effects", args, 2, "")
				if _, err := os.Stat(args[4]); !os.IsNotExist(err) {
					t.Fatal("wrong mode created custody")
				}
			}
			operationPath := filepath.Join(root, "operation.json")
			operation := map[string]any{"type": "grants-local-operation-1", "request_id": "lab-owner-mode-control", "certificate_id": draft["certificate_id"], "entry_id": "repo-create", "cycle_id": "codex-dm", "operation_use_id": "codex-dm/create", "subject": draft["subject"], "audience": draft["audience"], "action": "repository.create", "target": map[string]any{"organization": grants.LocalOrganization, "name": grants.LocalRepository, "visibility": "private"}, "expires_at": "2026-11-08T14:00:00Z"}
			save(t, operationPath, jsonBytes(t, operation))
			prepareArgs := []string{"prepare-request", "--payload", operationPath, "--requester-spki", requesterFile}
			rd := check(t, "valid-request-preparation", prepareArgs, 0, "")
			requestArgs := []string{"request", "--payload", operationPath, "--requester-spki", requesterFile, "--digest", string(rd), "--key", filepath.Join(custody, "requester.pk8")}
			for _, args := range [][]string{prepareArgs, requestArgs} {
				check(t, "valid-mode-without-owner", args, 0, "")
				wrongMode := append(append([]string(nil), args...), "--owner-mxid", identity.owner)
				if args[0] == "request" {
					wrongMode[8] = filepath.Join(custody, "ABSENT.pk8")
				}
				check(t, "owner-option-wrong-mode-before-key", wrongMode, 2, "")
				check(t, "valid-mode-neighbor", args, 0, "")
			}
			for _, field := range []string{"purpose", "owner", "requester", "scope", "same-pins", "digest", "key"} {
				args := append([]string(nil), preflight...)
				var changed map[string]any
				if err := json.Unmarshal(prepared.Payload, &changed); err != nil {
					t.Fatal(err)
				}
				want := "issuer-untrusted"
				switch field {
				case "purpose":
					changed["issuer"].(map[string]any)["purpose"] = "other-purpose"
					want = "bad-schema"
				case "owner":
					changed["issuer"].(map[string]any)["owner_mxid"] = "@other:example.invalid"
				case "requester":
					args[10] = filepath.Join(custody, "adversary.der")
					want = "requester-key-mismatch"
				case "same-pins":
					args[10] = ownerFile
					want = "requester-key-mismatch"
				case "scope":
					changed["entries"].([]any)[0].(map[string]any)["target"].(map[string]any)["name"] = "other-repository"
					changed["entries"].([]any)[1].(map[string]any)["target"].(map[string]any)["name"] = "other-repository"
					want = "resource-mismatch"
				case "digest":
					args[4] = strings.Repeat("0", 64)
					want = "prepared digest mismatch"
				case "key":
					args[6] = filepath.Join(custody, "adversary.pk8")
					want = "test key does not match public pin"
				}
				if field == "purpose" || field == "owner" || field == "scope" {
					raw := jsonBytes(t, changed)
					save(t, payloadPath, raw)
					args[4] = digestFor(domain, raw)
				}
				check(t, "refuse-"+field, args, 1, want)
				save(t, payloadPath, prepared.Payload)
				positive("valid-neighbor-after-"+field, explicit)
			}
		})
	}
}

var fixtureExport = flag.String("lab-public-output", "", "optional absolute public-only fixture output directory")
var fixtureCustody = flag.String("lab-private-custody", "", "optional private local throwaway actor custody directory")

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func save(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("fixture write failed")
	}
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture read failed")
	}
	return raw
}
func keyAt(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	v, err := x509.ParsePKCS8PrivateKey(read(t, path))
	if err != nil {
		t.Fatal("test key parse failed")
	}
	return v.(*ecdsa.PrivateKey)
}
func digestFor(domain string, raw []byte) string {
	d := sha256.Sum256(append([]byte(domain+"\n"), raw...))
	return hex.EncodeToString(d[:])
}
func envelope(t *testing.T, key *ecdsa.PrivateKey, domain, kind string, raw []byte) []byte {
	t.Helper()
	d := sha256.Sum256(append([]byte(domain+"\n"), raw...))
	s, err := lowS(key, d)
	if err != nil {
		t.Fatal(err)
	}
	return jsonBytes(t, map[string]string{"type": kind, "payload": base64.RawURLEncoding.EncodeToString(raw), "signature": base64.RawURLEncoding.EncodeToString(s)})
}

// This test drives the real unchanged release CLI as a separate process. The
// adversarial envelope constructor is test-only and never exposed by the tool.
func TestPreparedSignerUnchangedCLI(t *testing.T) {
	kv := os.Getenv("KEYVAULT_BIN")
	if kv == "" {
		t.Skip("integration requires explicitly built unchanged KEYVAULT_BIN")
	}
	tool := filepath.Join(filepath.Dir(kv), "labtestsigner")
	root := t.TempDir()
	custody := *fixtureCustody
	if custody == "" {
		custody = filepath.Join(root, "actors")
	}
	if err := generate(custody); err != nil {
		t.Fatal(err)
	}
	ownerFile, requesterFile := filepath.Join(custody, "owner.der"), filepath.Join(custody, "requester.der")
	ownerKey, requesterKey := filepath.Join(custody, "owner.pk8"), filepath.Join(custody, "requester.pk8")
	owner, requester, adversary := keyAt(t, ownerKey), keyAt(t, requesterKey), keyAt(t, filepath.Join(custody, "adversary.pk8"))
	ownerDER, requesterDER := read(t, ownerFile), read(t, requesterFile)
	const at = "2026-11-07T14:00:00Z"
	const certDomain = "swarma-grants/local-certificate/1"
	const reqDomain = "swarma-grants/local-request/2"
	subject := map[string]any{"account_mxid": "@ivan-agent:example.invalid", "device_id": "LAB-IVAN-AGENT"}
	audience := map[string]any{"deployment_id": "lab-thin-slice", "executor_id": "lab-verify-only"}
	cycle := map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}
	draft := map[string]any{"certificate_id": "lab-alexis-to-ivan-agent", "subject": subject, "audience": audience, "cycles": []any{cycle}, "not_before": at, "expires_at": "2026-11-09T14:00:00Z", "organization": "relux-works", "name": "matrix-grants-poc-261031"}
	request := map[string]any{"type": "grants-local-operation-1", "request_id": "lab-request-create", "certificate_id": draft["certificate_id"], "entry_id": "repo-create", "cycle_id": "codex-dm", "operation_use_id": "codex-dm/create", "subject": subject, "audience": audience, "action": "repository.create", "target": map[string]any{"organization": "relux-works", "name": "matrix-grants-poc-261031", "visibility": "private"}, "expires_at": "2026-11-08T14:00:00Z"}
	config := map[string]any{"type": "grants-local-enrollment-2", "owner_mxid": fixtureOwnerPrincipal, "owner_spki": base64.RawURLEncoding.EncodeToString(ownerDER), "requester_spki": base64.RawURLEncoding.EncodeToString(requesterDER), "subject": subject, "audience": audience, "cycle": cycle, "organization": "relux-works", "name": "matrix-grants-poc-261031", "state_dir": "/inert-lab/ABSENT-STATE", "gh_path": "/inert-lab/ABSENT-PROVIDER"}
	records := []map[string]any{}
	invoke := func(label, binary string, args []string, want int, contains string) ([]byte, []byte) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		start := time.Now().UTC()
		err := cmd.Run()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal("process could not run", label)
			}
		}
		records = append(records, map[string]any{"control": label, "started_at": start.Format(time.RFC3339Nano), "finished_at": time.Now().UTC().Format(time.RFC3339Nano), "exit": code, "stdout": out.String(), "stderr": stderr.String()})
		t.Logf("%s exit=%d stdout_bytes=%d stderr=%q", label, code, out.Len(), stderr.String())
		if code != want || (contains != "" && !strings.Contains(out.String()+stderr.String(), contains)) {
			t.Fatalf("%s: exit=%d stdout=%s stderr=%s", label, code, out.String(), stderr.String())
		}
		return bytes.Clone(out.Bytes()), bytes.Clone(stderr.Bytes())
	}
	draftPath, payloadPath, requestPayloadPath := filepath.Join(root, "draft.json"), filepath.Join(root, "prepared.json"), filepath.Join(root, "operation.json")
	save(t, draftPath, jsonBytes(t, draft))
	prepared, review := invoke("local-prepare", kv, []string{"grants", "local-prepare", "--plan", draftPath, "--owner-mxid", fixtureOwnerPrincipal, "--issuer-spki-der", ownerFile, "--requester-spki-der", requesterFile}, 0, "SHA256(domain + LF + exact payload)")
	save(t, payloadPath, prepared)
	match := regexp.MustCompile(`SHA256\(domain \+ LF \+ exact payload\): ([0-9a-f]{64})`).FindSubmatch(review)
	if len(match) != 2 {
		t.Fatal("prepared review digest missing")
	}
	certDigest := string(match[1])
	if certDigest != digestFor(certDomain, prepared) {
		t.Fatal("CLI exact digest disagreement")
	}
	certArgs := []string{"certificate", "--payload", payloadPath, "--digest", certDigest, "--key", ownerKey, "--owner-spki", ownerFile, "--requester-spki", requesterFile, "--owner-mxid", fixtureOwnerPrincipal}
	certificate, _ := invoke("sign-prepared-certificate", tool, certArgs, 0, "")
	requestRaw := jsonBytes(t, request)
	save(t, requestPayloadPath, requestRaw)
	rd, _ := invoke("prepare-request", tool, []string{"prepare-request", "--payload", requestPayloadPath, "--requester-spki", requesterFile}, 0, "")
	if string(rd) != digestFor(reqDomain, requestRaw) {
		t.Fatal("request digest disagreement")
	}
	reqArgs := []string{"request", "--payload", requestPayloadPath, "--digest", string(rd), "--key", requesterKey, "--requester-spki", requesterFile}
	signedRequest, _ := invoke("sign-prepared-request", tool, reqArgs, 0, "")
	configPath, certPath, reqPath := filepath.Join(root, "enrollment.json"), filepath.Join(root, "certificate.json"), filepath.Join(root, "request.json")
	save(t, configPath, jsonBytes(t, config))
	save(t, certPath, certificate)
	save(t, reqPath, signedRequest)
	verifyArgs := []string{"grants", "verify", "--config", configPath, "--certificate", certPath, "--request", reqPath, "--at", at, "--owner-mxid", fixtureOwnerPrincipal}
	verify := func(label, want string) { t.Helper(); invoke(label, kv, verifyArgs, 1, want) }
	positive := func(label string) { t.Helper(); invoke(label, kv, verifyArgs, 0, `"verdict":"accepted"`) }
	positive("valid-prepared-envelopes")
	for _, which := range []string{"certificate", "request"} {
		args := append([]string(nil), certArgs...)
		if which == "request" {
			args = append([]string(nil), reqArgs...)
		}
		args[6] = filepath.Join(custody, "adversary.pk8")
		invoke("signer-wrong-"+which+"-key", tool, args, 1, "test key does not match public pin")
		args = append([]string(nil), certArgs...)
		if which == "request" {
			args = append([]string(nil), reqArgs...)
		}
		args[4] = strings.Repeat("0", 64)
		invoke("signer-modified-"+which+"-digest", tool, args, 1, "prepared digest mismatch")
	}
	// Correct mathematical signatures under wrong keys must fail at the CLI.
	save(t, certPath, envelope(t, adversary, certDomain, "grants-signed-local-certificate-1", prepared))
	verify("verify-wrong-owner-key", "signature-invalid")
	save(t, certPath, certificate)
	save(t, reqPath, envelope(t, adversary, reqDomain, "grants-local-request-2", requestRaw))
	verify("verify-wrong-requester-key", "signature-invalid")
	save(t, reqPath, signedRequest)
	// Independent owner/requester pin changes cannot be selected by envelopes.
	for _, field := range []string{"owner_spki", "requester_spki"} {
		old := config[field]
		config[field] = base64.RawURLEncoding.EncodeToString(read(t, filepath.Join(custody, "adversary.der")))
		save(t, configPath, jsonBytes(t, config))
		want := "issuer-untrusted"
		if field == "requester_spki" {
			want = "requester-key-mismatch"
		}
		verify("verify-wrong-"+field, want)
		config[field] = old
		save(t, configPath, jsonBytes(t, config))
	}
	for _, mode := range []string{"action", "target", "expiry", "modified-payload", "wrong-domain"} {
		var changed map[string]any
		if err := json.Unmarshal(requestRaw, &changed); err != nil {
			t.Fatal(err)
		}
		want := "resource-mismatch"
		switch mode {
		case "action":
			changed["action"] = "repository.delete"
			changed["entry_id"] = "repo-delete"
			changed["operation_use_id"] = "codex-dm/delete"
			changed["target"] = map[string]any{"organization": "relux-works", "name": "matrix-grants-poc-261031", "repository_id": "42", "create_operation_use_id": "codex-dm/create", "create_result_digest": strings.Repeat("a", 64)}
		case "target":
			changed["target"].(map[string]any)["name"] = "other-repository"
		case "expiry":
			changed["expires_at"] = at
			want = "expired"
		case "modified-payload":
			changed["request_id"] = "modified-after-signing"
			want = "signature-invalid"
		case "wrong-domain":
			want = "signature-invalid"
		}
		bad := envelope(t, requester, reqDomain, "grants-local-request-2", jsonBytes(t, changed))
		if mode == "modified-payload" {
			var outer map[string]string
			json.Unmarshal(signedRequest, &outer)
			outer["payload"] = base64.RawURLEncoding.EncodeToString(jsonBytes(t, changed))
			bad = jsonBytes(t, outer)
		}
		if mode == "wrong-domain" {
			bad = envelope(t, requester, "swarma-grants/local-operation/1", "grants-local-request-2", requestRaw)
		}
		save(t, reqPath, bad)
		verify("verify-"+mode, want)
		save(t, reqPath, signedRequest)
		positive("valid-neighbor-after-" + mode)
	}
	// Owner/purpose and the certificate domain are explicit independent bindings.
	for _, mode := range []string{"owner", "purpose", "domain"} {
		var changed map[string]any
		json.Unmarshal(prepared, &changed)
		want := "issuer-untrusted"
		domain := certDomain
		if mode == "owner" {
			changed["issuer"].(map[string]any)["owner_mxid"] = "@other:example.invalid"
		}
		if mode == "purpose" {
			changed["issuer"].(map[string]any)["purpose"] = "other-purpose"
			want = "bad-schema"
		}
		if mode == "domain" {
			domain = "swarma-grants/certificate/1"
			want = "signature-invalid"
		}
		save(t, certPath, envelope(t, owner, domain, "grants-signed-local-certificate-1", jsonBytes(t, changed)))
		verify("verify-certificate-"+mode, want)
		save(t, certPath, certificate)
	}
	// A mathematically equivalent high-S signature and trailing DER are refused.
	for _, mode := range []string{"high-S", "trailing-DER"} {
		var outer map[string]string
		json.Unmarshal(signedRequest, &outer)
		signature, _ := base64.RawURLEncoding.DecodeString(outer["signature"])
		if mode == "high-S" {
			var pair struct{ R, S *big.Int }
			asn1.Unmarshal(signature, &pair)
			pair.S.Sub(requester.Params().N, pair.S)
			signature, _ = asn1.Marshal(pair)
		} else {
			signature = append(signature, 0)
		}
		outer["signature"] = base64.RawURLEncoding.EncodeToString(signature)
		save(t, reqPath, jsonBytes(t, outer))
		verify("verify-"+mode, "refused:")
		save(t, reqPath, signedRequest)
	}
	positive("restored-positive")
	if len(certificate) >= 98304 || len(signedRequest) >= 12288 {
		t.Fatal("wire size limit exceeded")
	}
	for _, path := range []string{config["state_dir"].(string), config["gh_path"].(string)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("verify touched effect path")
		}
	}
	if *fixtureExport != "" {
		if !filepath.IsAbs(*fixtureExport) {
			t.Fatal("absolute export required")
		}
		if err := os.MkdirAll(*fixtureExport, 0700); err != nil {
			t.Fatal(err)
		}
		ownerHash, requesterHash := sha256.Sum256(ownerDER), sha256.Sum256(requesterDER)
		pins := map[string]any{"owner_name": "id/swarma-poc-alexis", "requester_name": "id/swarma-poc-ivan-agent", "owner_spki": config["owner_spki"], "requester_spki": config["requester_spki"], "owner_spki_sha256": hex.EncodeToString(ownerHash[:]), "requester_spki_sha256": hex.EncodeToString(requesterHash[:]), "certificate_digest": certDigest, "request_digest": string(rd), "certificate_domain": certDomain, "request_domain": reqDomain, "certificate_bytes": len(certificate), "request_bytes": len(signedRequest), "observed_at": at, "effects_performed": false, "hardware_evidence": false}
		for name, raw := range map[string][]byte{"certificate.json": certificate, "request.json": signedRequest, "enrollment.json": jsonBytes(t, config), "prepared-certificate.json": prepared, "prepared-certificate-review.txt": review, "prepared-request.json": requestRaw, "pins.json": jsonBytes(t, pins), "owner.der": ownerDER, "requester.der": requesterDER} {
			save(t, filepath.Join(*fixtureExport, name), raw)
		}
		save(t, "/evidence/integration-controls.json", jsonBytes(t, records))
	}
}
