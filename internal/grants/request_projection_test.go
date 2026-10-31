package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func requestTestObject(action string) map[string]any {
	target := map[string]any{"organization": "ExampleOrg", "name": "example-repo", "visibility": "private"}
	if action == "repository.delete" {
		target = map[string]any{"organization": "ExampleOrg", "name": "example-repo", "repository_id": "42", "create_operation_use_id": "cycle-A/create", "create_result_digest": strings.Repeat("a", 64)}
	}
	return map[string]any{"type": "grants-request-1", "request_id": "request-A", "certificate_id": "certificate-A", "entry_id": "entry-A", "cycle_id": "cycle-A", "operation_use_id": "cycle-A/use", "subject": map[string]any{"account_mxid": "@Subject:Example.Invalid", "device_id": "Device+/= A", "device_ed25519": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "audience": map[string]any{"deployment_id": "deployment-A", "executor_id": "executor-A"}, "action": action, "target": target, "expires_at": "2026-11-01T00:00:00Z"}
}
func requestTestBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Both action variants require the exact outer fields and recursively closed
// subject/audience/target shapes; refusals return no partial request object.
func TestRequestProjectionClosedFields(t *testing.T) {
	for _, action := range []string{"repository.create", "repository.delete"} {
		valid := requestTestObject(action)
		good := func() {
			t.Helper()
			if v, e := parseRequestProjection(requestTestBytes(t, valid)); e != nil || v == nil {
				t.Fatal("positive", e)
			}
		}
		good()
		for field := range valid {
			for _, mode := range []string{"missing", "integer", "boolean", "array", "wrong-container", "invalid-value"} {
				t.Run(action+"/"+field+"/"+mode, func(t *testing.T) {
					good()
					v := subobjectCopy(valid)
					nested := field == "subject" || field == "audience" || field == "target"
					switch mode {
					case "missing":
						delete(v, field)
					case "integer":
						v[field] = 1
					case "boolean":
						v[field] = true
					case "array":
						v[field] = []any{}
					case "wrong-container":
						if nested {
							v[field] = "object"
						} else {
							v[field] = map[string]any{}
						}
					case "invalid-value":
						if nested {
							v[field] = map[string]any{}
						} else {
							v[field] = ""
						}
					}
					if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
						t.Fatal("schema refusal", e)
					}
					good()
				})
			}
		}
		v := subobjectCopy(valid)
		v["extra"] = true
		if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("extra", e)
		}
		good()
		for _, field := range []string{"subject", "audience", "target"} {
			v := subobjectCopy(valid)
			nested := subobjectCopy(valid[field].(map[string]any))
			nested["extra"] = true
			v[field] = nested
			if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
				t.Fatal("nested extra", field, e)
			}
			good()
		}
	}
}

// Create/delete target variants cannot be swapped or extended into one
// another. Successful projection retains exact fields but does not bind them
// to a certificate, real receiver, actual created instance or provider receipt.
func TestRequestProjectionVariantAndValues(t *testing.T) {
	for _, action := range []string{"repository.create", "repository.delete"} {
		valid := requestTestObject(action)
		raw := requestTestBytes(t, valid)
		got, e := parseRequestProjection(raw)
		if e != nil || got == nil {
			t.Fatal(e)
		}
		if got.action != action || got.requestID != "request-A" || got.certificateID != "certificate-A" || got.entryID != "entry-A" || got.cycleID != "cycle-A" || got.operationUseID != "cycle-A/use" || got.subject.accountMXID != "@Subject:Example.Invalid" || got.audience.executorID != "executor-A" || got.expiresAt.Format("2006-01-02T15:04:05Z") != "2026-11-01T00:00:00Z" {
			t.Fatal("wrong fields")
		}
		if action == "repository.create" {
			if got.createTarget == nil || got.deleteTarget != nil || got.createTarget.visibility != "private" {
				t.Fatal("create variant")
			}
		} else {
			if got.deleteTarget == nil || got.createTarget != nil || got.deleteTarget.repositoryID != 42 {
				t.Fatal("delete variant")
			}
		}
		other := "repository.create"
		if action == other {
			other = "repository.delete"
		}
		v := subobjectCopy(valid)
		v["target"] = requestTestObject(other)["target"]
		if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("cross target", e)
		}
		for field, bad := range map[string]string{"type": "grants-certificate-1", "action": "repository.update", "expires_at": "2026-02-30T00:00:00Z", "request_id": "bad id"} {
			v := subobjectCopy(valid)
			v[field] = bad
			if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
				t.Fatal("bad scalar", field, e)
			}
			if got, e := parseRequestProjection(raw); got == nil || e != nil {
				t.Fatal("valid neighbor", e)
			}
		}
		for _, field := range []string{"request_id", "certificate_id", "entry_id", "cycle_id", "operation_use_id"} {
			v := subobjectCopy(valid)
			v[field] = "A" + strings.Repeat("x", 127)
			if got, e := parseRequestProjection(requestTestBytes(t, v)); got == nil || e != nil {
				t.Fatal("ID128", e)
			}
			v[field] = "A" + strings.Repeat("x", 128)
			if got, e := parseRequestProjection(requestTestBytes(t, v)); got != nil || !errors.Is(e, errInputLimit) {
				t.Fatal("ID129", e)
			}
		}
	}
}

// Received canonical bytes are copied, never repaired; the byte bound and
// canonical encoding refusals produce no request or reservation/effect.
func TestRequestProjectionRepresentationAndOwnership(t *testing.T) {
	raw := requestTestBytes(t, requestTestObject("repository.create"))
	owned := append([]byte(nil), raw...)
	got, e := parseRequestProjection(raw)
	if e != nil || got == nil {
		t.Fatal(e)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if !bytes.Equal(got.raw, owned) || got.subject.deviceID != "Device+/= A" {
		t.Fatal("ownership")
	}
	for _, bad := range [][]byte{nil, []byte(`null`), append(append([]byte(nil), owned...), '\n')} {
		if got, e := parseRequestProjection(bad); got != nil || !errors.Is(e, errBadEncoding) {
			t.Fatal("encoding", e)
		}
		if got, e := parseRequestProjection(owned); got == nil || e != nil {
			t.Fatal("valid after encoding", e)
		}
	}
	if got, e := parseRequestProjection(bytes.Repeat([]byte{'x'}, 8193)); got != nil || !errors.Is(e, errInputLimit) {
		t.Fatal("request8193", e)
	}
}
