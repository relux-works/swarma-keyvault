package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type localFixture struct {
	owner, requester             *ecdsa.PrivateKey
	ownerDER, requesterDER       []byte
	certificate, request, config map[string]any
	now                          time.Time
}

func localTestFixture(t *testing.T) *localFixture {
	t.Helper()
	owner, ownerDER, _ := certificateSignatureFixture(t)
	requester, requesterDER, _ := certificateSignatureFixture(t)
	c, q := declaredMatchFixture("repository.create", "codex-dm")
	c["type"], q["type"] = "grants-local-certificate-1", "grants-local-operation-1"
	delete(c["subject"].(map[string]any), "device_ed25519")
	delete(q["subject"].(map[string]any), "device_ed25519")
	requesterHash := sha256.Sum256(requesterDER)
	c["requester_spki_sha256"] = hex.EncodeToString(requesterHash[:])
	issuer := c["issuer"].(map[string]any)
	issuer["owner_mxid"] = LocalOwnerMXID
	pin := sha256.Sum256(ownerDER)
	issuer["key_id"] = "sha256:" + hex.EncodeToString(pin[:])
	cycle := map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}
	c["cycles"] = []any{cycle}
	for _, value := range c["entries"].([]any) {
		e := value.(map[string]any)
		target := e["target"].(map[string]any)
		target["organization"], target["name"] = LocalOrganization, LocalRepository
		use := "codex-dm/create"
		if e["action"] == "repository.delete" {
			use = "codex-dm/delete"
		}
		e["uses"] = []any{map[string]any{"cycle_id": "codex-dm", "operation_use_id": use}}
	}
	q["target"] = map[string]any{"organization": LocalOrganization, "name": LocalRepository, "visibility": "private"}
	config := map[string]any{"type": "grants-local-enrollment-2", "owner_mxid": LocalOwnerMXID,
		"owner_spki": base64.RawURLEncoding.EncodeToString(ownerDER), "requester_spki": base64.RawURLEncoding.EncodeToString(requesterDER),
		"subject": q["subject"], "audience": q["audience"], "cycle": cycle, "organization": LocalOrganization, "name": LocalRepository,
		"state_dir": t.TempDir(), "gh_path": filepath.Join(string(filepath.Separator), "fixture", "gh")}
	if err := os.Chmod(config["state_dir"].(string), 0700); err != nil {
		t.Fatal(err)
	}
	return &localFixture{owner: owner, requester: requester, ownerDER: ownerDER, requesterDER: requesterDER, certificate: c, request: q, config: config, now: declaredMatchTime()}
}

func (f *localFixture) envelopes(t *testing.T) ([]byte, []byte) {
	t.Helper()
	certificate := signedCertificateFixture(t, f.owner, f.certificate, "swarma-grants/local-certificate/1")
	var certOuter map[string]any
	if err := json.Unmarshal(certificate, &certOuter); err != nil {
		t.Fatal(err)
	}
	certOuter["type"] = "grants-signed-local-certificate-1"
	certificate = requestTestBytes(t, certOuter)
	request := signedCertificateFixture(t, f.requester, f.request, "swarma-grants/local-request/2")
	var outer map[string]any
	if err := json.Unmarshal(request, &outer); err != nil {
		t.Fatal(err)
	}
	outer["type"] = "grants-local-request-2"
	return certificate, requestTestBytes(t, outer)
}

// The independent fixture signs the distinct local domain. A checked object
// retains exact caller bytes and the expected subject/audience/single cycle.
func TestLocalAttestationAndEnrollment(t *testing.T) {
	f := localTestFixture(t)
	c, q := f.envelopes(t)
	e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
	if err != nil {
		t.Fatal(err)
	}
	checked, err := e.check(c, q, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checked.certificate, c) || !bytes.Equal(checked.attestation, q) || checked.request.logicalUseKey() != (logicalUseKey{"certificate-A", "repo-create", "codex-dm/create"}) {
		t.Fatal("checked identity/bytes changed")
	}
	c[0] = 'x'
	q[0] = 'x'
	if checked.certificate[0] == 'x' || checked.attestation[0] == 'x' {
		t.Fatal("checked bytes alias caller")
	}
	plan, err := PrepareLocalRequest(requestTestBytes(t, f.request), f.requesterDER)
	if err != nil {
		t.Fatal(err)
	}
	_, request := f.envelopes(t)
	parsed, err := parseLocalAttestation(request)
	if err != nil {
		t.Fatal(err)
	}
	emitted, err := plan.SignedEnvelope(parsed.signature)
	if err != nil || !bytes.Equal(emitted, request) {
		t.Fatal("typed local envelope differs", err)
	}
}

// Every forbidden variant has a valid neighbor and a specific refusal. Copied
// subject JSON under another key cannot satisfy the separately enrolled pin.
func TestLocalCheckRefusals(t *testing.T) {
	for _, mode := range []string{"owner-pin", "requester-pin", "requester-key", "subject", "audience", "cycle", "use", "target", "unsigned", "changed", "expired", "not-yet"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			c, q := f.envelopes(t)
			e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.check(c, q, f.now); err != nil {
				t.Fatal("valid neighbor", err)
			}
			want := error(errSignatureInvalid)
			now := f.now
			switch mode {
			case "owner-pin":
				e.owner.spkiDER = f.requesterDER
				want = errIssuerUntrusted
			case "requester-pin":
				e.requesterDER = f.ownerDER
				want = errRequesterMismatch
			case "requester-key":
				f.requester = f.owner
				_, q = f.envelopes(t)
			case "subject":
				f.request["subject"] = map[string]any{"account_mxid": "@copied:example.invalid", "device_id": "DEVICE-A"}
				_, q = f.envelopes(t)
				want = errSubjectMismatch
			case "audience":
				f.request["audience"] = map[string]any{"deployment_id": "other", "executor_id": "executor-A"}
				_, q = f.envelopes(t)
				want = errAudienceMismatch
			case "cycle":
				f.request["cycle_id"] = "claude-dm"
				_, q = f.envelopes(t)
				want = errScheduleMismatch
			case "use":
				f.request["operation_use_id"] = "other"
				_, q = f.envelopes(t)
				want = errScheduleMismatch
			case "target":
				f.request["target"].(map[string]any)["name"] = "other"
				_, q = f.envelopes(t)
				want = errResourceMismatch
			case "unsigned":
				c = requestTestBytes(t, f.certificate)
				want = errBadSchema
			case "changed":
				var outer map[string]string
				_ = json.Unmarshal(q, &outer)
				outer["payload"] = base64.RawURLEncoding.EncodeToString(bytes.ReplaceAll(requestTestBytes(t, f.request), []byte("request-A"), []byte("request-B")))
				q = requestTestBytes(t, outer)
			case "expired":
				now = time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)
				want = ErrExpired
			case "not-yet":
				now = time.Date(2026, 11, 2, 9, 59, 59, 0, time.UTC)
				want = ErrNotYetValid
			}
			if checked, err := e.check(c, q, now); !errors.Is(err, want) || checked != nil {
				t.Fatalf("wanted %v, got %v", want, err)
			}
		})
	}
}

// New local grammar preserves existing request/certificate profiles and refuses
// oversized/noncanonical outer fields before decoding, plus wrong domain/type.
func TestLocalEnvelopeBounds(t *testing.T) {
	f := localTestFixture(t)
	_, good := f.envelopes(t)
	for _, mode := range []string{"newline", "duplicate", "unknown", "padded", "payload-limit", "signature-limit", "wrong-type", "wrong-domain"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := parseLocalAttestation(good); err != nil {
				t.Fatal("valid neighbor", err)
			}
			var outer map[string]any
			_ = json.Unmarshal(good, &outer)
			raw := good
			switch mode {
			case "newline":
				raw = append(bytes.Clone(good), '\n')
			case "duplicate":
				raw = bytes.Replace(good, []byte(`{"payload":`), []byte(`{"payload":"x","payload":`), 1)
			case "unknown":
				outer["public_key"] = "x"
				raw = requestTestBytes(t, outer)
			case "padded":
				outer["payload"] = outer["payload"].(string) + "="
				raw = requestTestBytes(t, outer)
			case "payload-limit":
				outer["payload"] = strings.Repeat("A", 10924)
				raw = requestTestBytes(t, outer)
			case "signature-limit":
				outer["signature"] = strings.Repeat("A", 97)
				raw = requestTestBytes(t, outer)
			case "wrong-type":
				outer["type"] = "grants-signed-certificate-1"
				raw = requestTestBytes(t, outer)
			case "wrong-domain":
				raw = signedCertificateFixture(t, f.requester, f.request, "swarma-grants/request/1")
				_ = json.Unmarshal(raw, &outer)
				outer["type"] = "grants-local-request-2"
				raw = requestTestBytes(t, outer)
			}
			if mode == "wrong-domain" {
				e, _ := ParseLocalEnrollment(requestTestBytes(t, f.config))
				c, _ := f.envelopes(t)
				if _, err := e.check(c, raw, f.now); !errors.Is(err, errSignatureInvalid) {
					t.Fatal("wrong domain accepted", err)
				}
			} else if _, err := parseLocalAttestation(raw); err == nil {
				t.Fatal("forbidden local representation accepted")
			}
		})
	}
}
