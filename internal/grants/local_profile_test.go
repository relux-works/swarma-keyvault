package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func localProfileFixture(t *testing.T) *localFixture {
	t.Helper()
	f := localTestFixture(t)
	for _, value := range []map[string]any{f.certificate, f.request} {
		old := value["subject"].(map[string]any)
		value["subject"] = map[string]any{"account_mxid": old["account_mxid"], "device_id": old["device_id"]}
	}
	f.certificate["type"] = "grants-local-certificate-1"
	hash := sha256.Sum256(f.requesterDER)
	f.certificate["requester_spki_sha256"] = hex.EncodeToString(hash[:])
	f.request["type"] = "grants-local-operation-1"
	return f
}

// Distinct complete local schemas accept two declared subject fields; Matrix
// parsers keep requiring their real Ed25519 field and reject local documents.
func TestLocalProfilesClosedAndSeparate(t *testing.T) {
	f := localProfileFixture(t)
	c, q := requestTestBytes(t, f.certificate), requestTestBytes(t, f.request)
	if _, err := parseLocalCertificateProjection(c); err != nil {
		t.Fatal(err)
	}
	if _, err := parseLocalOperationProjection(q); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCertificateProjection(c); !errors.Is(err, errBadSchema) {
		t.Fatal("Matrix accepted local certificate", err)
	}
	if _, err := parseRequestProjection(q); !errors.Is(err, errBadSchema) {
		t.Fatal("Matrix accepted local operation", err)
	}
	mc, mq := declaredMatchFixture("repository.create", "codex-dm")
	if _, err := parseCertificateProjection(requestTestBytes(t, mc)); err != nil {
		t.Fatal("valid Matrix certificate", err)
	}
	if _, err := parseRequestProjection(requestTestBytes(t, mq)); err != nil {
		t.Fatal("valid Matrix request", err)
	}
	if _, err := parseLocalCertificateProjection(requestTestBytes(t, mc)); !errors.Is(err, errBadSchema) {
		t.Fatal("local accepted Matrix certificate", err)
	}
	if _, err := parseLocalOperationProjection(requestTestBytes(t, mq)); !errors.Is(err, errBadSchema) {
		t.Fatal("local accepted Matrix request", err)
	}
	for _, mode := range []string{"missing-pin", "upper-pin", "short-pin", "unknown", "device-key"} {
		t.Run(mode, func(t *testing.T) {
			f := localProfileFixture(t)
			if _, err := parseLocalCertificateProjection(requestTestBytes(t, f.certificate)); err != nil {
				t.Fatal("valid neighbor", err)
			}
			switch mode {
			case "missing-pin":
				delete(f.certificate, "requester_spki_sha256")
			case "upper-pin":
				f.certificate["requester_spki_sha256"] = strings.Repeat("A", 64)
			case "short-pin":
				f.certificate["requester_spki_sha256"] = "abc"
			case "unknown":
				f.certificate["extra"] = "unknown"
			case "device-key":
				f.certificate["subject"].(map[string]any)["device_ed25519"] = strings.Repeat("A", 43)
			}
			if got, err := parseLocalCertificateProjection(requestTestBytes(t, f.certificate)); got != nil || !errors.Is(err, errBadSchema) {
				t.Fatalf("wanted schema refusal, got %v", err)
			}
		})
	}
	delete(mc["subject"].(map[string]any), "device_ed25519")
	if got, err := parseCertificateProjection(requestTestBytes(t, mc)); got != nil || !errors.Is(err, errBadSchema) {
		t.Fatal("Matrix missing key accepted", err)
	}
}

// These literal independent oracles distinguish correlation, signature domain,
// and one changed payload byte. The checked parser must retain exact input.
func TestLocalOperationCorrelationLiteral(t *testing.T) {
	raw := []byte(`{"action":"repository.create","audience":{"deployment_id":"fixture-deployment","executor_id":"fixture-executor"},"certificate_id":"fixture-certificate","cycle_id":"fixture-cycle","entry_id":"fixture-entry","expires_at":"2026-11-05T00:00:00Z","operation_use_id":"fixture-cycle/create","request_id":"fixture-request-A","subject":{"account_mxid":"@Fixture:example.invalid","device_id":"fixture-device"},"target":{"name":"matrix-grants-poc-261031","organization":"relux-works","visibility":"private"},"type":"grants-local-operation-1"}`)
	q, err := parseLocalOperationProjection(raw)
	if err != nil || !bytes.Equal(q.raw, raw) {
		t.Fatal("exact local payload", err)
	}
	check := func(raw []byte, want string) {
		t.Helper()
		got := localOperationDigest(raw)
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("digest %x, want %s", got, want)
		}
	}
	check(q.raw, "5aaf7fb3450ca100bd2fe82e41358123160832cac90003ff75580b5117a264a5")
	sign := localRequestDigest(raw)
	if hex.EncodeToString(sign[:]) != "7949e6e3f9b07b97c13498365c62fbd5c0928832a9f1ffa50d102f6842ad4ee4" || sign == localOperationDigest(raw) {
		t.Fatal("signature/correlation confused")
	}
	check(bytes.Replace(raw, []byte("fixture-request-A"), []byte("fixture-request-B"), 1), "2ecce53ac51622e1236a64d94a48545d9768f5bfb267c13e57d62945e0b5bd7e")
}

// The local operation's closed schema rejects missing/extra subject and top
// level fields; lexical faults and limits have their own precise error class.
func TestLocalOperationClosedRefusals(t *testing.T) {
	for _, mode := range []string{"missing-device", "missing-account", "ed-key", "unknown", "duplicate", "newline", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			good := requestTestBytes(t, f.request)
			if _, err := parseLocalOperationProjection(good); err != nil {
				t.Fatal("valid neighbor", err)
			}
			want := error(errBadSchema)
			switch mode {
			case "missing-device":
				delete(f.request["subject"].(map[string]any), "device_id")
			case "missing-account":
				delete(f.request["subject"].(map[string]any), "account_mxid")
			case "ed-key":
				f.request["subject"].(map[string]any)["device_ed25519"] = strings.Repeat("A", 43)
			case "unknown":
				f.request["requester_spki_sha256"] = strings.Repeat("a", 64)
			}
			raw := requestTestBytes(t, f.request)
			switch mode {
			case "duplicate":
				raw = bytes.Replace(good, []byte(`{"action":`), []byte(`{"action":"repository.create","action":`), 1)
				want = errBadEncoding
			case "newline":
				raw = append(bytes.Clone(good), '\n')
				want = errBadEncoding
			case "oversize":
				raw = bytes.Repeat([]byte{'x'}, 8193)
				want = errInputLimit
			}
			if got, err := parseLocalOperationProjection(raw); got != nil || !errors.Is(err, want) {
				t.Fatal("operation refusal", mode, err)
			}
		})
	}
}

// New local profiles inherit the contracted lexical byte/string budgets.
// These lexical fixtures intentionally make no claim of typed authority.
func TestLocalProfileLexicalBudgets(t *testing.T) {
	for _, profile := range []wireProfile{localCertificateWire, localCertificateEnvelopeWire, localOperationWire, localRequest2EnvelopeWire, localEnrollment2Wire} {
		if node, err := parseCanonical([]byte(`{}`), profile); err != nil || node == nil {
			t.Fatal("positive lexical neighbor", profile, err)
		}
		limit := 8192
		switch profile {
		case localCertificateWire:
			limit = 65536
		case localCertificateEnvelopeWire:
			limit = 98304
		case localRequest2EnvelopeWire:
			limit = 12288
		}
		if node, err := parseCanonical(bytes.Repeat([]byte{'x'}, limit+1), profile); node != nil || !errors.Is(err, errInputLimit) {
			t.Fatal("overall byte budget", profile, err)
		}
	}
	for _, profile := range []wireProfile{localCertificateEnvelopeWire, localRequest2EnvelopeWire} {
		limit := 10923
		if profile == localCertificateEnvelopeWire {
			limit = 87382
		}
		for _, field := range []struct {
			name  string
			limit int
		}{{"payload", limit}, {"signature", 96}} {
			good := []byte(`{"` + field.name + `":"` + strings.Repeat("A", field.limit) + `"}`)
			if _, err := parseCanonical(good, profile); err != nil {
				t.Fatal("envelope string limit", profile, field.name, err)
			}
			bad := []byte(`{"` + field.name + `":"` + strings.Repeat("A", field.limit+1) + `"}`)
			if _, err := parseCanonical(bad, profile); !errors.Is(err, errInputLimit) {
				t.Fatal("envelope string overflow", profile, field.name, err)
			}
		}
	}
}
