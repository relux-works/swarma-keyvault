package grants

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func requestUseKeyFixture(t *testing.T, request map[string]any) logicalUseKey {
	t.Helper()
	raw := requestTestBytes(t, request)
	before := bytes.Clone(raw)
	parsed, err := parseRequestProjection(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.logicalUseKey()
	if !bytes.Equal(raw, before) {
		t.Fatal("request input changed")
	}
	return key
}

// Distinct certificate, entry and use namespaces remain distinct in comparable
// keys obtained through the real request parser. The map is an in-process test
// witness only; it implements no durable ledger or concurrent reservation.
func TestLogicalUseNamespaceThreeAxes(t *testing.T) {
	identities := []logicalUseKey{
		{"certificate-A", "repo-create", "shared-use"},
		{"certificate-A", "repo-delete", "shared-use"},
		{"certificate-B", "repo-create", "shared-use"},
		{"certificate-A", "repo-create", "other-use"},
	}
	seen := make(map[logicalUseKey]int)
	for i, expected := range identities {
		_, request := declaredMatchFixture("repository.create", "claude-dm")
		request["certificate_id"], request["entry_id"], request["operation_use_id"] = expected.certificateID, expected.entryID, expected.operationUseID
		key := requestUseKeyFixture(t, request)
		if _, exists := seen[key]; exists {
			t.Fatalf("namespace collision at row %d", i)
		}
		seen[key] = i
	}
	if len(seen) != 4 {
		t.Fatal("expected four distinct logical uses")
	}
	for i, expected := range identities {
		if row, ok := seen[expected]; !ok || row != i {
			t.Fatalf("lost exact identity at row %d", i)
		}
	}
}

// Repeated use IDs across CREATE/DELETE entries are legitimate under the
// complete certificate decoder and matcher. Rejecting all repeats would break
// the accepted wire contract; repeating within one entry remains forbidden.
func TestLogicalUseNamespaceCompatibleRepeatedIDs(t *testing.T) {
	certificate, _ := declaredMatchFixture("repository.create", "claude-dm")
	entries := certificate["entries"].([]any)
	for _, e := range entries {
		for _, use := range e.(map[string]any)["uses"].([]any) {
			u := use.(map[string]any)
			u["operation_use_id"] = u["cycle_id"].(string) + "/shared"
		}
	}
	raw := requestTestBytes(t, certificate)
	if _, err := parseCertificateProjection(raw); err != nil {
		t.Fatal("legitimate repeated IDs across entries", err)
	}
	seen := make(map[logicalUseKey]bool)
	for _, action := range []string{"repository.create", "repository.delete"} {
		_, request := declaredMatchFixture(action, "claude-dm")
		request["operation_use_id"] = "claude-dm/shared"
		if action == "repository.delete" {
			request["target"].(map[string]any)["create_operation_use_id"] = "claude-dm/shared"
		}
		if err := checkDeclaredRequestMatch(raw, requestTestBytes(t, request), "claude", "encrypted-dm", declaredMatchTime()); err != nil {
			t.Fatal("matching compatible use", err)
		}
		key := requestUseKeyFixture(t, request)
		if seen[key] {
			t.Fatal("CREATE and DELETE use aliased")
		}
		seen[key] = true
	}
	if len(seen) != 2 {
		t.Fatal("expected two distinct entry namespaces")
	}
	uses := entries[0].(map[string]any)["uses"].([]any)
	uses[1].(map[string]any)["operation_use_id"] = uses[0].(map[string]any)["operation_use_id"]
	if _, err := parseCertificateProjection(requestTestBytes(t, certificate)); !errors.Is(err, errBadSchema) {
		t.Fatal("duplicate use ID inside one entry", err)
	}
	if _, err := parseCertificateProjection(raw); err != nil {
		t.Fatal("unchanged valid neighbor", err)
	}
}

// Equality excludes correlation/time/cycle declarations. A changed cycle cannot
// manufacture a fresh logical use: the same key remains and matching refuses
// the unsigned cycle substitution. Equality alone proves no request authority.
func TestLogicalUseNamespaceCorrelationAndCycle(t *testing.T) {
	certificate, request := declaredMatchFixture("repository.create", "claude-dm")
	key := requestUseKeyFixture(t, request)
	for _, variant := range []struct{ field, value string }{
		{"request_id", "another-request"},
		{"expires_at", "2026-11-02T11:15:00Z"},
		{"cycle_id", "codex-group"},
	} {
		t.Run(variant.field, func(t *testing.T) {
			_, changed := declaredMatchFixture("repository.create", "claude-dm")
			changed[variant.field] = variant.value
			if got := requestUseKeyFixture(t, changed); got != key {
				t.Fatal("declaration manufactured another logical use")
			}
			if variant.field == "cycle_id" {
				if err := checkDeclaredRequestMatch(requestTestBytes(t, certificate), requestTestBytes(t, changed), "codex", "encrypted-group", declaredMatchTime()); !errors.Is(err, errScheduleMismatch) {
					t.Fatal("cycle substitution", err)
				}
			}
		})
	}
	if err := checkDeclaredRequestMatch(requestTestBytes(t, certificate), requestTestBytes(t, request), "claude", "encrypted-dm", declaredMatchTime()); err != nil {
		t.Fatal("valid cycle neighbor", err)
	}
	if got := requestUseKeyFixture(t, request); got != key {
		t.Fatal("identical tuple changed identity")
	}
}

// Valid opaque IDs can contain delimiters and differ only by case; structured
// fields keep these legitimate identities distinct without normalization.
func TestLogicalUseNamespaceExactFields(t *testing.T) {
	identities := []logicalUseKey{
		{"a:b", "c", "d"}, {"a", "b:c", "d"}, {"a", "b", "c:d"},
		{"A", "b", "c:d"}, {"a", "B", "c:d"}, {"a", "b", "C:d"},
		{strings.Repeat("x", 128), "a/b.c_d-e:f", "a/b.c_d-e:f"},
	}
	seen := make(map[logicalUseKey]bool)
	for _, expected := range identities {
		_, request := declaredMatchFixture("repository.create", "claude-dm")
		request["certificate_id"], request["entry_id"], request["operation_use_id"] = expected.certificateID, expected.entryID, expected.operationUseID
		got := requestUseKeyFixture(t, request)
		if got != expected || seen[got] {
			t.Fatal("field boundary/case lost")
		}
		seen[got] = true
	}
	if len(seen) != 7 {
		t.Fatal("valid identity forms collided")
	}
}

// Incomplete or out-of-contract namespace fields cannot yield a parsed request
// or derived key. Valid nearby input still parses, with exact controlled errors.
func TestLogicalUseNamespaceInvalidFields(t *testing.T) {
	for _, field := range []string{"certificate_id", "entry_id", "operation_use_id"} {
		for _, invalid := range []struct {
			name, value string
			want        error
		}{{"empty", "", errBadSchema}, {"illegal", "a+b", errBadSchema}, {"oversized", strings.Repeat("x", 129), errInputLimit}} {
			t.Run(field+"/"+invalid.name, func(t *testing.T) {
				_, request := declaredMatchFixture("repository.create", "claude-dm")
				good := requestUseKeyFixture(t, request)
				request[field] = invalid.value
				if projection, err := parseRequestProjection(requestTestBytes(t, request)); projection != nil || !errors.Is(err, invalid.want) {
					t.Fatalf("got projection=%v error=%v, want nil/%v", projection != nil, err, invalid.want)
				}
				_, valid := declaredMatchFixture("repository.create", "claude-dm")
				if requestUseKeyFixture(t, valid) != good {
					t.Fatal("valid neighbor changed")
				}
			})
		}
	}
}
