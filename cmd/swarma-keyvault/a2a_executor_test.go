package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Explicit initialization works with empty pinned registries and no executable
// or grant present. It cannot be repeated to erase history; later read-only
// verification failure also leaves the initialized journal unchanged.
func TestA2AExecutorCLIStateInitialization(t *testing.T) {
	_, _, owner := issueCLIFixture(t)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	keys := a2aCLIBytes(t, map[string]any{"type": "grants-a2a-key-registry-1", "keys": map[string]any{}})
	registry := a2aCLIBytes(t, map[string]any{"type": "grants-a2a-grants-registry-1", "key_registry_sha256": a2aCLIHash(keys), "grants": map[string]any{}, "revoked": []any{}})
	c := map[string]any{"type": "grants-a2a-executor-config-1", "owner_mxid": "@owner:example.invalid", "owner_spki": base64.RawURLEncoding.EncodeToString(owner.item.SPKI), "owner_spki_sha256": a2aCLIHash(owner.item.SPKI), "audience": "@alice:test.local", "room_id": "!fixture:test.local", "topic": "alpha", "thread_root": "$ev001", "declared_from": "bob", "declared_to": "alice", "key_registry": base64.RawURLEncoding.EncodeToString(keys), "key_registry_sha256": a2aCLIHash(keys), "grant_registry": base64.RawURLEncoding.EncodeToString(registry), "grant_registry_sha256": a2aCLIHash(registry), "state_dir": state, "state_epoch": strings.Repeat("ab", 32), "a2a_path": filepath.Join(dir, "not-installed"), "a2a_sha256": strings.Repeat("cd", 32), "a2a_identity": "alice", "a2a_connection": "fixture-connection", "a2a_config_dir": filepath.Join(dir, "own-config"), "gh_path": filepath.Join(dir, "not-a-provider"), "gh_sha256": strings.Repeat("ef", 32)}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, a2aCLIBytes(t, c), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"grants", "a2a-state-init", "--config", path}
	var out, diag bytes.Buffer
	if code := run(args, nil, &out, &diag); code != 0 || out.String() != `{"type":"grants-a2a-state-initialized-1"}` || owner.factories != 0 || owner.signs != 0 {
		t.Fatal("explicit inert init", code, out.String(), diag.String())
	}
	journal := filepath.Join(state, "a2a.journal")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diag.Reset()
	if code := run(args, nil, &out, &diag); code != 1 || out.Len() != 0 {
		t.Fatal("repeat init", code, out.String(), diag.String())
	}
	out.Reset()
	diag.Reset()
	if code := run([]string{"grants", "a2a-verify", "--config", path, "--event", "$fixture"}, nil, &out, &diag); code != 1 || out.Len() != 0 {
		t.Fatal("missing projection binary", code, out.String(), diag.String())
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("init/read-only failure changed history", err)
	}
}

// Every executor command rejects missing/duplicate/unknown input before any
// configuration or process access; --help is its nearby successful control.
func TestA2AExecutorCLIFlags(t *testing.T) {
	for _, command := range []string{"a2a-verify", "a2a-state-init", "a2a-execute"} {
		for _, flags := range [][]string{nil, {"--config", "-"}, {"--config", "x", "--config", "y"}, {"--projection", "x"}, {"--config", "x", "--event", "$a", "--event", "$b"}, {"--config", "x", "extra"}} {
			var out, diag bytes.Buffer
			args := append([]string{"grants", command}, flags...)
			if code := run(args, strings.NewReader("not a trust config"), &out, &diag); code != 2 || out.Len() != 0 {
				t.Fatal(command, flags, code, out.String(), diag.String())
			}
		}
		var out, diag bytes.Buffer
		if code := run([]string{"grants", command, "--help"}, nil, &out, &diag); code != 0 || out.Len() != 0 || !strings.Contains(diag.String(), command) {
			t.Fatal("help control", command, code, diag.String())
		}
	}
}

// A malformed separately supplied public config never emits success or starts
// the runtime route; stdin cannot override it or provide observed event bytes.
func TestA2AExecutorCLIBadConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"type":"unknown"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"a2a-verify", "a2a-state-init", "a2a-execute"} {
		args := []string{"grants", command, "--config", path}
		if command != "a2a-state-init" {
			args = append(args, "--event", "$fixture")
		}
		var out, diag bytes.Buffer
		if code := run(args, strings.NewReader(`{"observation_status":"observed"}`), &out, &diag); code != 1 || out.Len() != 0 || !strings.Contains(diag.String(), "a2a-executor-config-invalid") {
			t.Fatal(command, code, out.String(), diag.String())
		}
	}
}
