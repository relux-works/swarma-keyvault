package grants

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func declaredMatchFixture(action, cycleID string) (map[string]any, map[string]any) {
	subject := func() map[string]any {
		return map[string]any{"account_mxid": "@agent:example.invalid", "device_id": "DEVICE-A", "device_ed25519": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	}
	audience := func() map[string]any {
		return map[string]any{"deployment_id": "deployment-A", "executor_id": "executor-A"}
	}
	createTarget := func() map[string]any {
		return map[string]any{"organization": "ExampleOrg", "name": "grant-test", "visibility": "private"}
	}
	cycles, createUses, deleteUses := []any{}, []any{}, []any{}
	for _, runtime := range []string{"claude", "codex"} {
		for _, channel := range []string{"dm", "group"} {
			id := runtime + "-" + channel
			cycles = append(cycles, map[string]any{"cycle_id": id, "runtime": runtime, "channel": "encrypted-" + channel})
			createUses = append(createUses, map[string]any{"cycle_id": id, "operation_use_id": id + "/create"})
			deleteUses = append(deleteUses, map[string]any{"cycle_id": id, "operation_use_id": id + "/delete"})
		}
	}
	certificate := map[string]any{
		"type": "grants-certificate-1", "certificate_id": "certificate-A",
		"issuer":  map[string]any{"owner_mxid": "@owner:example.invalid", "key_id": "sha256:" + strings.Repeat("a", 64), "purpose": "grants-owner-v1"},
		"subject": subject(), "audience": audience(), "not_before": "2026-11-02T10:00:00Z", "expires_at": "2026-11-02T12:00:00Z", "supersedes": []any{}, "cycles": cycles,
		"entries": []any{
			map[string]any{"entry_id": "repo-create", "action": "repository.create", "target": createTarget(), "uses": createUses},
			map[string]any{"entry_id": "repo-delete", "action": "repository.delete", "target": map[string]any{"organization": "ExampleOrg", "name": "grant-test", "paired_create_entry": "repo-create"}, "uses": deleteUses},
		},
	}
	entryID, operationUseID, target := "repo-create", cycleID+"/create", createTarget()
	if action == "repository.delete" {
		entryID, operationUseID = "repo-delete", cycleID+"/delete"
		target = map[string]any{"organization": "ExampleOrg", "name": "grant-test", "repository_id": "42", "create_operation_use_id": cycleID + "/create", "create_result_digest": strings.Repeat("b", 64)}
	}
	request := map[string]any{"type": "grants-request-1", "request_id": "request-A", "certificate_id": "certificate-A", "entry_id": entryID, "cycle_id": cycleID, "operation_use_id": operationUseID, "subject": subject(), "audience": audience(), "action": action, "target": target, "expires_at": "2026-11-02T11:30:00Z"}
	return certificate, request
}

func declaredMatchTime() time.Time { return time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC) }

// All eight declared CREATE/DELETE uses match their exact signed-plan-shaped
// fields. These unsigned fixtures prove matching only, not signature, current
// lifecycle, receiver authentication, durable reservation or provider effects.
func TestDeclaredRequestMatchFourCycles(t *testing.T) {
	for _, runtime := range []string{"claude", "codex"} {
		for _, channel := range []string{"dm", "group"} {
			for _, action := range []string{"repository.create", "repository.delete"} {
				t.Run(runtime+"/"+channel+"/"+action, func(t *testing.T) {
					certificate, request := declaredMatchFixture(action, runtime+"-"+channel)
					if err := checkDeclaredRequestMatch(requestTestBytes(t, certificate), requestTestBytes(t, request), runtime, "encrypted-"+channel, declaredMatchTime()); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

// Independently varied request declarations refuse with their intended class;
// a valid neighbor before and after each case excludes reject-all behavior.
// Case-sensitive exact comparisons cover account servers, device bytes,
// audience, both resource variants, and cross-cycle logical-use substitution.
func TestDeclaredRequestMatchRefusals(t *testing.T) {
	tests := []struct {
		name, action string
		change       func(map[string]any)
		want         error
	}{
		{"certificate", "repository.create", func(r map[string]any) { r["certificate_id"] = "certificate-B" }, errScheduleMismatch},
		{"account-server", "repository.create", func(r map[string]any) { r["subject"].(map[string]any)["account_mxid"] = "@agent:other.invalid" }, errSubjectMismatch},
		{"account-case", "repository.create", func(r map[string]any) { r["subject"].(map[string]any)["account_mxid"] = "@Agent:example.invalid" }, errSubjectMismatch},
		{"device", "repository.create", func(r map[string]any) { r["subject"].(map[string]any)["device_id"] = "DEVICE-B" }, errSubjectMismatch},
		{"device-key", "repository.create", func(r map[string]any) {
			r["subject"].(map[string]any)["device_ed25519"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		}, errSubjectMismatch},
		{"deployment", "repository.create", func(r map[string]any) { r["audience"].(map[string]any)["deployment_id"] = "deployment-B" }, errAudienceMismatch},
		{"executor", "repository.create", func(r map[string]any) { r["audience"].(map[string]any)["executor_id"] = "executor-B" }, errAudienceMismatch},
		{"unknown-cycle", "repository.create", func(r map[string]any) { r["cycle_id"] = "missing-cycle" }, errScheduleMismatch},
		{"unknown-entry", "repository.create", func(r map[string]any) { r["entry_id"] = "missing-entry" }, errScheduleMismatch},
		{"unknown-use", "repository.create", func(r map[string]any) { r["operation_use_id"] = "new-use" }, errScheduleMismatch},
		{"cross-cycle-use", "repository.create", func(r map[string]any) { r["operation_use_id"] = "claude-group/create" }, errScheduleMismatch},
		{"create-organization", "repository.create", func(r map[string]any) { r["target"].(map[string]any)["organization"] = "OtherOrg" }, errResourceMismatch},
		{"create-repository", "repository.create", func(r map[string]any) { r["target"].(map[string]any)["name"] = "other-repo" }, errResourceMismatch},
		{"create-case", "repository.create", func(r map[string]any) { r["target"].(map[string]any)["name"] = "Grant-test" }, errResourceMismatch},
		{"public-create", "repository.create", func(r map[string]any) { r["target"].(map[string]any)["visibility"] = "public" }, errBadSchema},
		{"delete-organization", "repository.delete", func(r map[string]any) { r["target"].(map[string]any)["organization"] = "OtherOrg" }, errResourceMismatch},
		{"delete-repository", "repository.delete", func(r map[string]any) { r["target"].(map[string]any)["name"] = "other-repo" }, errResourceMismatch},
		{"delete-paired-use", "repository.delete", func(r map[string]any) {
			r["target"].(map[string]any)["create_operation_use_id"] = "claude-group/create"
		}, errScheduleMismatch},
		{"wrong-action", "repository.delete", func(r map[string]any) { r["entry_id"] = "repo-create"; r["operation_use_id"] = "claude-dm/create" }, errResourceMismatch},
		{"extended-expiry", "repository.create", func(r map[string]any) { r["expires_at"] = "2026-11-02T12:00:01Z" }, errScheduleMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate, request := declaredMatchFixture(test.action, "claude-dm")
			c, good := requestTestBytes(t, certificate), requestTestBytes(t, request)
			checkGood := func() {
				t.Helper()
				if err := checkDeclaredRequestMatch(c, good, "claude", "encrypted-dm", declaredMatchTime()); err != nil {
					t.Fatal("valid neighbor", err)
				}
			}
			checkGood()
			test.change(request)
			if err := checkDeclaredRequestMatch(c, requestTestBytes(t, request), "claude", "encrypted-dm", declaredMatchTime()); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			checkGood()
		})
	}
}

// Runtime/channel inputs must match their declared cycle exactly; absence or
// unknown values never select a default. These strings remain unauthenticated.
func TestDeclaredRequestMatchContext(t *testing.T) {
	c, r := declaredMatchFixture("repository.create", "claude-dm")
	for _, context := range [][2]string{{"codex", "encrypted-dm"}, {"claude", "encrypted-group"}, {"", "encrypted-dm"}, {"claude", ""}, {"Claude", "encrypted-dm"}, {"claude", "direct"}} {
		if err := checkDeclaredRequestMatch(requestTestBytes(t, c), requestTestBytes(t, r), context[0], context[1], declaredMatchTime()); !errors.Is(err, errScheduleMismatch) {
			t.Fatal(context, err)
		}
	}
	if err := checkDeclaredRequestMatch(requestTestBytes(t, c), requestTestBytes(t, r), "claude", "encrypted-dm", declaredMatchTime()); err != nil {
		t.Fatal("valid context", err)
	}
}

// Exact supplied instants implement half-open validity for BOTH documents;
// subsecond expiry neighbors are not rounded and no clock/skew is invented.
func TestDeclaredRequestMatchTime(t *testing.T) {
	for _, test := range []struct {
		name, requestExpiry string
		at                  time.Time
		want                error
	}{
		{"not-started", "2026-11-02T12:00:00Z", time.Date(2026, 11, 2, 9, 59, 59, 999999999, time.UTC), ErrNotYetValid},
		{"exact-start", "2026-11-02T12:00:00Z", time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), nil},
		{"before-certificate-expiry", "2026-11-02T12:00:00Z", time.Date(2026, 11, 2, 11, 59, 59, 999999999, time.UTC), nil},
		{"certificate-expiry", "2026-11-02T12:00:00Z", time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC), ErrExpired},
		{"before-request-expiry", "2026-11-02T11:30:00Z", time.Date(2026, 11, 2, 11, 29, 59, 999999999, time.UTC), nil},
		{"request-expiry", "2026-11-02T11:30:00Z", time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC), ErrExpired},
		{"unsupported-observation", "2026-11-02T12:00:00Z", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), ErrInvalidObservation},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, r := declaredMatchFixture("repository.create", "claude-dm")
			r["expires_at"] = test.requestExpiry
			if err := checkDeclaredRequestMatch(requestTestBytes(t, c), requestTestBytes(t, r), "claude", "encrypted-dm", test.at); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

// The matching boundary invokes the real canonical decoders, rejects malformed
// inputs in either position, and leaves exact input bytes unchanged on success
// and refusal. It has no write/effect callback or authorization result object.
func TestDeclaredRequestMatchParsingAndOwnership(t *testing.T) {
	c, r := declaredMatchFixture("repository.create", "claude-dm")
	certificate, request := requestTestBytes(t, c), requestTestBytes(t, r)
	certBefore, requestBefore := bytes.Clone(certificate), bytes.Clone(request)
	for _, pair := range [][2][]byte{{nil, request}, {certificate, nil}, {append(bytes.Clone(certificate), '\n'), request}, {certificate, append(bytes.Clone(request), '\n')}} {
		if err := checkDeclaredRequestMatch(pair[0], pair[1], "claude", "encrypted-dm", declaredMatchTime()); !errors.Is(err, errBadEncoding) {
			t.Fatal("encoding refusal", err)
		}
	}
	if err := checkDeclaredRequestMatch(certificate, request, "claude", "encrypted-dm", declaredMatchTime()); err != nil {
		t.Fatal("valid neighbor", err)
	}
	if err := checkDeclaredRequestMatch(certificate, request, "codex", "encrypted-dm", declaredMatchTime()); !errors.Is(err, errScheduleMismatch) {
		t.Fatal(err)
	}
	if !bytes.Equal(certificate, certBefore) || !bytes.Equal(request, requestBefore) {
		t.Fatal("input mutated")
	}
}
