package grants

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// muServiceRig turns the docking fixture into a receiver configuration with a
// fake a2a (the test binary) and a pinned fake task-board script.
func muServiceRig(t *testing.T) (*muDock, map[string]any, string) {
	t.Helper()
	g := newMUDock(t)
	dir := t.TempDir()
	a2aDir := filepath.Join(dir, "events")
	snapPath := filepath.Join(dir, "snapshot.json")
	state := filepath.Join(dir, "state")
	for _, d := range []string{a2aDir, state} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(snapPath, g.snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYVAULT_MU_A2A_DIR", a2aDir)
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	board, _ := script(t, `{"ok":true,"result":{"id":"TASK-fixture-created"}}`, 0)
	b64 := base64.RawURLEncoding.EncodeToString
	cfg := map[string]any{
		"type": "mu-receiver-config-1", "grant_root": g.root.id, "audience": muDockAud, "grants": []string{b64(g.grant)},
		"agents":                []map[string]any{{"mxid": muDockSender, "key": g.sender.id, "attestation": b64(g.att), "generation": 1}},
		"publisher_attestation": b64(g.pubAtt), "publisher_key": g.pub.id, "publisher_snapshot_path": snapPath, "root_revocations": []string{},
		"state_dir": state, "state_epoch": hex.EncodeToString(make([]byte, 31)) + "01",
		"owner": "owner:fixture-primary", "room_scope": "swarma-space", "modules": []string{"swarma-keyvault"}, "paused": []string{},
		"registry_owners": map[string]string{"@fixture-principal-5:example.invalid": "owner:fixture-3"}, "time_authority_seconds": 300,
		"a2a":        map[string]any{"path": exe, "sha256": fileSHA(t, exe), "profile": "fixture-profile", "identity": "fixture-receiver", "config_dir": dir, "room": muDockRoom},
		"task_board": map[string]any{"path": board, "sha256": fileSHA(t, board), "board_dir": dir, "parent": "STORY-fixture-parent"},
	}
	return g, cfg, a2aDir
}

func muEventRecord(t *testing.T, dir string, e MUEnvelopeEvent) {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	raw, _ := json.Marshal(map[string]string{"type": "a2a.event-envelope-input/1", "sender_mxid": e.Sender, "receiver_mxid": e.Receiver,
		"requested_room_id": e.Room, "requested_event_id": e.EventID, "returned_room_id": e.Room, "returned_event_id": e.EventID,
		"envelope_base64": b64(e.Envelope), "body_text_base64": b64(e.Text)})
	if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(e.EventID, "$")+".json"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func muServiceFrom(t *testing.T, cfg map[string]any) (*MUService, error) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ParseMUService(raw)
}

// Claim: the configured service runs the sitting through the pinned a2a
// projection and the pinned task-board: an in-scope request creates a task
// (receipt with element id), its replay refuses, and the secondary-owner
// account.manage refuses before reservation. The service clock is set to
// the fixture time; the snapshot is the fixture's fresh one.
func TestMUServiceSitting(t *testing.T) {
	g, cfg, a2aDir := muServiceRig(t)
	svc, err := muServiceFrom(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	svc.receiver.now = func() time.Time { return g.now }
	if err := svc.InitState(); err != nil {
		t.Fatal(err)
	}
	g.request("$s1", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault", "title": "Review"}, "sender assigns: review")
	muEventRecord(t, a2aDir, g.events["$s1"])
	out, err := svc.Execute(context.Background(), "$s1")
	if err != nil || out.State != "succeeded" || !strings.Contains(string(out.Receipt), "TASK-fixture-created") {
		t.Fatal("in-scope request", out, err)
	}
	if _, err := svc.Execute(context.Background(), "$s1"); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("replay admitted", err)
	}
	g.request("$s2", "account.manage", "account-scope", "owner:fixture-primary", map[string]string{"account": "@fixture-principal-5:example.invalid"}, "retire a secondary-owner account")
	muEventRecord(t, a2aDir, g.events["$s2"])
	if _, err := svc.Execute(context.Background(), "$s2"); !errors.Is(err, ErrMUScope) {
		t.Fatal("out-of-scope admitted", err)
	}
}

// Claim: the configuration is refused for an unknown field, a wrong type,
// a relative path, a bad epoch, a time authority outside 1..300 s, a
// duplicate agent, a root revocation not signed by the pinned root, an
// audience carrying the TEST marker prefix "test:", and an audience the
// issuer cannot mint (whitespace, non-ASCII, over 255 bytes). Positive
// controls: the fixture configuration, a 255-byte audience, and "TEST:"
// in upper case, which is not the case-sensitive marker.
func TestMUServiceConfigRefusals(t *testing.T) {
	g, cfg, _ := muServiceRig(t)
	if _, err := muServiceFrom(t, cfg); err != nil {
		t.Fatal("valid control refused", err)
	}
	for _, aud := range []string{strings.Repeat("a", 255), "TEST:grant-service"} {
		_, c2, _ := muServiceRig(t)
		c2["audience"] = aud
		if _, err := muServiceFrom(t, c2); err != nil {
			t.Fatal("admissible audience refused", aud, err)
		}
	}
	other := newMUKey(t)
	p, err := mugrant.BuildSnapshot(other.id, g.now, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := base64.RawURLEncoding.EncodeToString(other.sign(t, p))
	mutations := map[string]func(map[string]any){
		"unknown-field":  func(c map[string]any) { c["expected_sender"] = "x" },
		"wrong-type":     func(c map[string]any) { c["type"] = "mu-receiver-config-2" },
		"relative-state": func(c map[string]any) { c["state_dir"] = "state" },
		"bad-epoch":      func(c map[string]any) { c["state_epoch"] = "00" },
		"time-zero":      func(c map[string]any) { c["time_authority_seconds"] = 0 },
		"time-long":      func(c map[string]any) { c["time_authority_seconds"] = 301 },
		"duplicate-agent": func(c map[string]any) {
			a := c["agents"].([]map[string]any)
			c["agents"] = append(a, a[0])
		},
		"foreign-root-revocation": func(c map[string]any) { c["root_revocations"] = []string{foreign} },
		"test-audience":           func(c map[string]any) { c["audience"] = "test:grant-service" },
		"audience-space":          func(c map[string]any) { c["audience"] = "grant service" },
		"audience-zwsp-test":      func(c map[string]any) { c["audience"] = "\u200btest:grant-service" },
		"audience-fullwidth":      func(c map[string]any) { c["audience"] = "test\uff1agrant-service" },
		"audience-256":            func(c map[string]any) { c["audience"] = strings.Repeat("a", 256) },
	}
	for name, mutate := range mutations {
		_, cfg2, _ := muServiceRig(t)
		mutate(cfg2)
		if _, err := muServiceFrom(t, cfg2); !errors.Is(err, ErrMUConfig) {
			t.Error("config admitted", name, err)
		}
	}
}

// Claim (wiring): the configured service's receiver verifies through a
// platform adapter that hands over its snapshots before verification, so
// pre-absorption is active in production rather than a silent no-op.
func TestMUServiceSnapshotSourceWired(t *testing.T) {
	_, cfg, _ := muServiceRig(t)
	svc, err := muServiceFrom(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.receiver.verifier.(MUSnapshotSource); !ok {
		t.Fatal("service receiver verifier does not supply verified snapshots")
	}
}

// Claim: the configured service pins exactly its revocation publisher as the
// receiver's snapshot signer, so a journal from another publisher refuses.
func TestMUServicePinsPublisherSigner(t *testing.T) {
	g, cfg, _ := muServiceRig(t)
	svc, err := muServiceFrom(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s := svc.receiver.config.Signers; len(s) != 1 || !s[g.pub.id] {
		t.Fatal("service signers", s)
	}
}
