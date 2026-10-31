package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func revocationTestObject() map[string]any {
	return map[string]any{"type": "grants-revocation-1", "revocation_id": "revocation-A", "certificate_id": "certificate-A", "issuer": map[string]any{"owner_mxid": "@Owner:Example.Invalid", "key_id": "sha256:" + strings.Repeat("a", 64), "purpose": "grants-owner-v1"}, "effective_at": "2026-10-31T00:00:00Z", "reason_code": "owner-revoked"}
}
func revocationTestBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Every outer revocation field is required with its declared type; issuer is
// recursively closed, and no failed parse returns a usable partial object.
func TestRevocationProjectionClosedFields(t *testing.T) {
	valid := revocationTestObject()
	positive := func() {
		t.Helper()
		if v, e := parseRevocationProjection(revocationTestBytes(t, valid)); e != nil || v == nil {
			t.Fatal("positive", e)
		}
	}
	positive()
	for field := range valid {
		for _, mode := range []string{"missing", "integer", "boolean", "array", "wrong-container", "invalid-value"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				positive()
				v := subobjectCopy(valid)
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
					if field == "issuer" {
						v[field] = "issuer"
					} else {
						v[field] = map[string]any{}
					}
				case "invalid-value":
					if field == "issuer" {
						v[field] = map[string]any{}
					} else {
						v[field] = ""
					}
				}
				got, e := parseRevocationProjection(revocationTestBytes(t, v))
				if got != nil || !errors.Is(e, errBadSchema) {
					t.Fatal("schema refusal", e)
				}
				positive()
			})
		}
	}
	v := subobjectCopy(valid)
	v["extra"] = true
	if got, e := parseRevocationProjection(revocationTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
		t.Fatal("extra", e)
	}
	positive()
	for _, root := range []any{true, 1, "revocation", []any{}} {
		if got, e := parseRevocationProjection(revocationTestBytes(t, root)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("root", e)
		}
		positive()
	}
	for _, reason := range []string{"owner-revoked", "superseded", "compromised"} {
		v := subobjectCopy(valid)
		v["reason_code"] = reason
		got, e := parseRevocationProjection(revocationTestBytes(t, v))
		if e != nil || got == nil || got.reasonCode != reason {
			t.Fatal("exact reason", e)
		}
	}
}

// Canonical bytes and decoded fields survive caller mutation; encoding and
// byte/ID bounds refuse before producing a projection. No clock/lifecycle
// transition or actual issuer/signature authentication is exercised here.
func TestRevocationProjectionRepresentations(t *testing.T) {
	valid := revocationTestObject()
	raw := revocationTestBytes(t, valid)
	owned := append([]byte(nil), raw...)
	got, e := parseRevocationProjection(raw)
	if e != nil || got == nil {
		t.Fatal(e)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if !bytes.Equal(got.raw, owned) || got.certificateID != "certificate-A" || got.revocationID != "revocation-A" || got.issuer.ownerMXID != "@Owner:Example.Invalid" || got.effectiveAt.Format("2006-01-02T15:04:05Z") != "2026-10-31T00:00:00Z" {
		t.Fatal("retained bytes/fields")
	}
	for _, bad := range [][]byte{nil, append(append([]byte(nil), owned...), '\n'), []byte(`null`), []byte(`{"type":"grants-revocation-1","type":"grants-revocation-1"}`)} {
		if v, e := parseRevocationProjection(bad); v != nil || !errors.Is(e, errBadEncoding) {
			t.Fatal("encoding", e)
		}
		if v, e := parseRevocationProjection(owned); v == nil || e != nil {
			t.Fatal("positive after encoding", e)
		}
	}
	if v, e := parseRevocationProjection(bytes.Repeat([]byte{'x'}, 4097)); v != nil || !errors.Is(e, errInputLimit) {
		t.Fatal("payload4097", e)
	}
	for _, field := range []string{"revocation_id", "certificate_id"} {
		v := subobjectCopy(valid)
		v[field] = "A" + strings.Repeat("x", 127)
		if got, e := parseRevocationProjection(revocationTestBytes(t, v)); got == nil || e != nil {
			t.Fatal("ID128", e)
		}
		v[field] = "A" + strings.Repeat("x", 128)
		if got, e := parseRevocationProjection(revocationTestBytes(t, v)); got != nil || !errors.Is(e, errInputLimit) {
			t.Fatal("ID129", e)
		}
	}
	for field, bad := range map[string]string{"type": "grants-certificate-1", "reason_code": "other", "effective_at": "2026-02-30T00:00:00Z", "certificate_id": "bad id"} {
		v := subobjectCopy(valid)
		v[field] = bad
		if got, e := parseRevocationProjection(revocationTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("bad scalar", field, e)
		}
		if got, e := parseRevocationProjection(owned); got == nil || e != nil {
			t.Fatal("positive after scalar", e)
		}
	}
}
