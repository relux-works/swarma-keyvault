package grants

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func identityObjectCases(t *testing.T) []subobjectCase {
	t.Helper()
	return []subobjectCase{
		{"issuer", map[string]any{"owner_mxid": "@Owner:Example.Invalid", "key_id": "sha256:" + strings.Repeat("a", 64), "purpose": "grants-owner-v1"}, func(n *wireValue) error {
			v, e := parseIssuerNode(n)
			if e != nil && v != nil {
				t.Fatal("partial issuer")
			}
			return e
		}},
		{"subject", map[string]any{"account_mxid": "@Subject:Example.Invalid", "device_id": "Device+/= A", "device_ed25519": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, func(n *wireValue) error {
			v, e := parseSubjectNode(n)
			if e != nil && v != nil {
				t.Fatal("partial subject")
			}
			return e
		}},
	}
}

// Closed issuer/subject representations reject missing, extra, wrong-typed
// and invalid scalar fields while returning no partially decoded identity.
func TestIdentityObjectsClosedFields(t *testing.T) {
	for _, c := range identityObjectCases(t) {
		good := func() {
			t.Helper()
			if e := c.check(subobjectNode(t, c.valid)); e != nil {
				t.Fatal("positive", e)
			}
		}
		good()
		for field := range c.valid {
			for _, mode := range []string{"missing", "integer", "boolean", "array", "object", "invalid-text"} {
				t.Run(c.name+"/"+field+"/"+mode, func(t *testing.T) {
					v := subobjectCopy(c.valid)
					switch mode {
					case "missing":
						delete(v, field)
					case "integer":
						v[field] = 1
					case "boolean":
						v[field] = true
					case "array":
						v[field] = []any{}
					case "object":
						v[field] = map[string]any{}
					case "invalid-text":
						v[field] = ""
					}
					good()
					if e := c.check(subobjectNode(t, v)); !errors.Is(e, errBadSchema) {
						t.Fatal("schema refusal", e)
					}
					good()
				})
			}
		}
		v := subobjectCopy(c.valid)
		v["extra"] = "x"
		if e := c.check(subobjectNode(t, v)); !errors.Is(e, errBadSchema) {
			t.Fatal("extra", e)
		}
		good()
		for _, root := range []any{true, 1, "identity", []any{}} {
			if e := c.check(subobjectNode(t, root)); !errors.Is(e, errBadSchema) {
				t.Fatal("root", e)
			}
			good()
		}
		if e := c.check(nil); !errors.Is(e, errBadSchema) {
			t.Fatal("nil", e)
		}
		good()
	}
}

// Exact identity bytes and public key bytes are retained; the fingerprint is
// derived from those32 bytes, with no enrollment or signature verification.
func TestIdentityObjectsExactValues(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	subject, e := parseSubjectNode(subobjectNode(t, map[string]any{"account_mxid": "@Legacy:EXAMPLE.Invalid", "device_id": "Device+/= A", "device_ed25519": base64.RawURLEncoding.EncodeToString(key)}))
	if e != nil || subject == nil {
		t.Fatal(e)
	}
	if subject.accountMXID != "@Legacy:EXAMPLE.Invalid" || subject.deviceID != "Device+/= A" || subject.deviceFingerprint != sha256.Sum256(key) {
		t.Fatal("identity/fingerprint changed")
	}
	for i, b := range key {
		if subject.deviceEd25519[i] != b {
			t.Fatal("key changed")
		}
	}
	issuer, e := parseIssuerNode(subobjectNode(t, map[string]any{"owner_mxid": "@Owner:EXAMPLE.Invalid", "key_id": "sha256:" + strings.Repeat("a", 64), "purpose": "grants-owner-v1"}))
	if e != nil || issuer == nil || issuer.ownerMXID != "@Owner:EXAMPLE.Invalid" || issuer.keyID != "sha256:"+strings.Repeat("a", 64) || issuer.purpose != "grants-owner-v1" {
		t.Fatal("issuer values", e)
	}
	for _, keyID := range []string{"SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63), strings.Repeat("a", 71)} {
		v := map[string]any{"owner_mxid": "@Owner:example.invalid", "key_id": keyID, "purpose": "grants-owner-v1"}
		if got, e := parseIssuerNode(subobjectNode(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("key ID", e)
		}
		v["key_id"] = "sha256:" + strings.Repeat("a", 64)
		if got, e := parseIssuerNode(subobjectNode(t, v)); got == nil || e != nil {
			t.Fatal("issuer neighbor", e)
		}
	}
	for _, purpose := range []string{"grants-owner-v2", "release-signing", "Grants-owner-v1"} {
		v := map[string]any{"owner_mxid": "@Owner:example.invalid", "key_id": "sha256:" + strings.Repeat("a", 64), "purpose": purpose}
		if got, e := parseIssuerNode(subobjectNode(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("purpose", e)
		}
	}
}
