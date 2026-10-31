package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func encodeResultTest(t *testing.T, v map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func resultTestObject(state string) map[string]any {
	v := map[string]any{"type": "grants-result-1", "state": state, "request_digest": strings.Repeat("a", 64), "certificate_id": "cert-1", "entry_id": "repo-create", "cycle_id": "codex-dm", "operation_use_id": "codex-dm/create", "action": "repository.create", "reservation_id": "reserve-1", "observed_at": "2026-10-31T13:00:01Z", "audit_sequence": "9007199254740993"}
	switch state {
	case "blocked":
		v["code"] = "expired"
	case "succeeded":
		v["dispatch_id"] = "dispatch-1"
		v["provider_receipt_digest"] = strings.Repeat("b", 64)
		v["repository"] = map[string]any{"provider": "github", "repository_id": "18446744073709551615", "organization": "relux-works", "name": "matrix-grants-poc-261031", "visibility": "private"}
	case "failed":
		v["dispatch_id"] = "dispatch-1"
		v["provider_receipt_digest"] = strings.Repeat("b", 64)
		v["code"] = "provider-refused-no-effect"
	case "unknown":
		v["dispatch_id"] = "dispatch-1"
		v["code"] = "dispatch-outcome-unknown"
	case "refused":
		v = map[string]any{"type": "grants-result-1", "state": "refused", "input_sha256": strings.Repeat("c", 64), "code": "bad-schema", "observed_at": "2026-10-31T13:00:01Z"}
	case "availability":
		v = map[string]any{"type": "grants-error-1", "code": "clock-unavailable", "input_sha256": strings.Repeat("c", 64)}
	}
	return v
}

// Eight independent exact accepted-contract vectors exercise the public shape
// only. JSON acceptance never authenticates a result, state, time or dispatch.
func TestOriginalResultProjectionVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/result_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Name, Raw, WantError, Kind, State string }
	// Explicit tags map the independent fixture's error spelling.
	var entries []struct {
		Name      string `json:"name"`
		Raw       string `json:"raw"`
		WantError string `json:"want_error"`
		Kind      string `json:"kind"`
		State     string `json:"state"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		rows = append(rows, struct{ Name, Raw, WantError, Kind, State string }{e.Name, e.Raw, e.WantError, e.Kind, e.State})
	}
	if len(rows) != 8 {
		t.Fatal("lost original vectors", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			input := []byte(row.Raw)
			before := bytes.Clone(input)
			got, err := parseResultProjection(input)
			if row.WantError != "" {
				if !errors.Is(err, errBadSchema) || got != nil {
					t.Fatal("expected exact schema refusal", got, err)
				}
			} else {
				if err != nil || got == nil {
					t.Fatal("valid projection shape", err)
				}
				if got.kind != row.Kind || got.state != row.State || !bytes.Equal(got.raw, input) {
					t.Fatal("projection binding changed", got)
				}
			}
			if !bytes.Equal(input, before) {
				t.Fatal("original wire mutated")
			}
		})
	}
}

// Each union member has an exact closed field set. Removing/wrong-typing any
// required field or adding a foreign field refuses, with a nearby valid control.
func TestResultProjectionClosedFields(t *testing.T) {
	states := []string{"reserved", "blocked", "succeeded", "failed", "unknown", "refused", "availability"}
	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			valid := resultTestObject(state)
			for field := range valid {
				for _, mode := range []string{"missing", "wrong-type"} {
					t.Run(field+"/"+mode, func(t *testing.T) {
						v := resultTestObject(state)
						if mode == "missing" {
							delete(v, field)
						} else {
							v[field] = true
						}
						got, err := parseResultProjection(encodeResultTest(t, v))
						if !errors.Is(err, errBadSchema) || got != nil {
							t.Fatal("invalid closed shape accepted", got, err)
						}
					})
				}
			}
			for _, field := range []string{"dispatch_id", "repository", "provider_receipt_digest", "code", "observed_at", "reservation_id", "input_sha256", "bogus"} {
				if _, exists := valid[field]; exists {
					continue
				}
				v := resultTestObject(state)
				v[field] = "forbidden"
				got, err := parseResultProjection(encodeResultTest(t, v))
				if !errors.Is(err, errBadSchema) || got != nil {
					t.Fatalf("foreign %s accepted: %v %v", field, got, err)
				}
			}
			input := encodeResultTest(t, valid)
			got, err := parseResultProjection(input)
			if err != nil || got == nil {
				t.Fatal("valid after rejection", err)
			}
			if state != "refused" && state != "availability" && got.auditSequence != 9007199254740993 {
				t.Fatal("audit integer lost precision", got.auditSequence)
			}
			if state == "succeeded" && (got.repository == nil || got.repository.repositoryID != ^uint64(0)) {
				t.Fatal("repository uint64 mismatch", got.repository)
			}
			saved := bytes.Clone(got.raw)
			input[0] = '['
			if !bytes.Equal(got.raw, saved) {
				t.Fatal("retained exact bytes alias caller mutation")
			}
		})
	}
}

// The closed code vocabularies are independently listed from the contract;
// neighboring state/code substitutions and implicit success all refuse.
func TestResultProjectionCodesAndStates(t *testing.T) {
	codes := map[string][]string{
		"blocked":      {"expired", "certificate-revoked", "certificate-superseded", "required-state-unavailable", "clock-unavailable", "provider-instance-capability-unavailable"},
		"unknown":      {"dispatch-outcome-unknown", "required-audit-unknown", "cleanup-unknown"},
		"failed":       {"provider-refused-no-effect"},
		"availability": {"clock-unavailable", "receiver-unavailable", "issuer-unavailable", "store-unavailable", "provider-unavailable", "result-boundary-unavailable"},
		"refused":      {"bad-encoding", "bad-schema", "issuer-untrusted", "signature-invalid", "subject-mismatch", "receiver-unavailable", "receiver-unverified", "audience-mismatch", "schedule-mismatch", "resource-mismatch", "not-yet-valid", "expired", "lifetime-exceeded", "certificate-revoked", "certificate-superseded", "request-id-collision", "use-already-reserved", "paired-create-unavailable", "instance-mismatch", "provider-instance-capability-unavailable", "required-state-unavailable", "clock-unavailable", "certificate-id-collision", "revocation-id-collision", "predecessor-unavailable", "predecessor-authority-mismatch", "bad-lifecycle-reference", "lifecycle-reference-limit", "predecessor-obligations-unsettled", "input-limit-exceeded", "state-capacity-exceeded"},
	}
	for state, allowed := range codes {
		for _, code := range allowed {
			v := resultTestObject(state)
			v["code"] = code
			if got, err := parseResultProjection(encodeResultTest(t, v)); err != nil || got == nil || got.code != code {
				t.Fatal("declared code refused", state, code, err)
			}
		}
		for _, code := range []string{"", "OK", "success", "Bad-schema", "network-error", "404-not-found", "dispatch-id-unavailable"} {
			v := resultTestObject(state)
			v["code"] = code
			if got, err := parseResultProjection(encodeResultTest(t, v)); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("unknown code accepted", state, code, err)
			}
		}
	}
	for _, state := range []string{"", "success", "SUCCESS", "pending", "failed-no-intent"} {
		v := resultTestObject("reserved")
		v["state"] = state
		if got, err := parseResultProjection(encodeResultTest(t, v)); !errors.Is(err, errBadSchema) || got != nil {
			t.Fatal("unknown state accepted", state, got, err)
		}
	}
	v := resultTestObject("reserved")
	v["type"] = "grants-result-2"
	if got, err := parseResultProjection(encodeResultTest(t, v)); !errors.Is(err, errBadSchema) || got != nil {
		t.Fatal("future result type accepted", got, err)
	}
}

// Field and nested repository counterexamples preserve grammar/schema error
// separation and leave no partial typed result. They imply no provider binding.
func TestResultProjectionFieldRefusals(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{"request_digest", strings.Repeat("A", 64)}, {"certificate_id", "_bad"},
		{"audit_sequence", "0"}, {"audit_sequence", "01"}, {"audit_sequence", "18446744073709551616"},
		{"audit_sequence", 1}, {"observed_at", "2026-10-31T13:00:01+00:00"},
		{"action", "repository.rename"}, {"reservation_id", ""},
	}
	for _, test := range cases {
		v := resultTestObject("reserved")
		v[test.field] = test.value
		got, err := parseResultProjection(encodeResultTest(t, v))
		if !errors.Is(err, errBadSchema) || got != nil {
			t.Fatal(test.field, test.value, got, err)
		}
	}
	for _, field := range []string{"provider", "repository_id", "organization", "name", "visibility"} {
		v := resultTestObject("succeeded")
		repo := v["repository"].(map[string]any)
		delete(repo, field)
		if got, err := parseResultProjection(encodeResultTest(t, v)); !errors.Is(err, errBadSchema) || got != nil {
			t.Fatal("missing nested field", field, got, err)
		}
	}
	for field, value := range map[string]any{"provider": "gitlab", "repository_id": "0", "visibility": "public", "organization": true, "name": 1, "extra": "x"} {
		v := resultTestObject("succeeded")
		v["repository"].(map[string]any)[field] = value
		if got, err := parseResultProjection(encodeResultTest(t, v)); !errors.Is(err, errBadSchema) || got != nil {
			t.Fatal("bad nested field", field, got, err)
		}
	}
	raw := encodeResultTest(t, resultTestObject("reserved"))
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), []byte(`{"type":"grants-result-1","type":"grants-result-1"}`), []byte(`null`)} {
		if got, err := parseResultProjection(bad); !errors.Is(err, errBadEncoding) || got != nil {
			t.Fatal("lexical failure misclassified", got, err)
		}
	}
	if got, err := parseResultProjection([]byte(strings.Repeat(" ", 8193))); !errors.Is(err, errInputLimit) || got != nil {
		t.Fatal("result byte cap", got, err)
	}
	a, e1 := parseResultProjection(raw)
	b, e2 := parseResultProjection(raw)
	if e1 != nil || e2 != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("valid controls differ", a, b, e1, e2)
	}
}
