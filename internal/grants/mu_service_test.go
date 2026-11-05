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
	board, _ := script(t, `{"ok":true,"result":{"id":"TASK-261105-dockxx"}}`, 0)
	b64 := base64.RawURLEncoding.EncodeToString
	cfg := map[string]any{
		"type": "mu-receiver-config-1", "grant_root": g.root.id, "audience": muDockAud, "grants": []string{b64(g.grant)},
		"agents":                []map[string]any{{"mxid": muDockMeta, "key": g.meta.id, "attestation": b64(g.att), "generation": 1}},
		"publisher_attestation": b64(g.pubAtt), "publisher_key": g.pub.id, "publisher_snapshot_path": snapPath, "root_revocations": []string{},
		"state_dir": state, "state_epoch": hex.EncodeToString(make([]byte, 31)) + "01",
		"owner": "owner:alexis", "room_scope": "swarma-space", "modules": []string{"swarma-keyvault"}, "paused": []string{},
		"registry_owners": map[string]string{"@ivan-agent:relux.works": "owner:ivan"}, "time_authority_seconds": 300,
		"a2a":        map[string]any{"path": exe, "sha256": fileSHA(t, exe), "profile": "keyvault-gr", "identity": "keyvault.orch-altair", "config_dir": dir, "room": muDockRoom},
		"task_board": map[string]any{"path": board, "sha256": fileSHA(t, board), "board_dir": dir, "parent": "STORY-261105-dock"},
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
// (receipt with element id), its replay refuses, and the Ivan-side
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
	g.request("$s1", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault", "title": "Review"}, "Meta assigns: review")
	muEventRecord(t, a2aDir, g.events["$s1"])
	out, err := svc.Execute(context.Background(), "$s1")
	if err != nil || out.State != "succeeded" || !strings.Contains(string(out.Receipt), "TASK-261105-dockxx") {
		t.Fatal("in-scope request", out, err)
	}
	if _, err := svc.Execute(context.Background(), "$s1"); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("replay admitted", err)
	}
	g.request("$s2", "account.manage", "account-scope", "owner:alexis", map[string]string{"account": "@ivan-agent:relux.works"}, "retire an Ivan-side account")
	muEventRecord(t, a2aDir, g.events["$s2"])
	if _, err := svc.Execute(context.Background(), "$s2"); !errors.Is(err, ErrMUScope) {
		t.Fatal("out-of-scope admitted", err)
	}
}

// Claim: the configuration is refused for an unknown field, a wrong type,
// a relative path, a bad epoch, a time authority outside 1..300 s, a
// duplicate agent and a root revocation not signed by the pinned root.
func TestMUServiceConfigRefusals(t *testing.T) {
	g, cfg, _ := muServiceRig(t)
	if _, err := muServiceFrom(t, cfg); err != nil {
		t.Fatal("valid control refused", err)
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
	}
	for name, mutate := range mutations {
		_, cfg2, _ := muServiceRig(t)
		mutate(cfg2)
		if _, err := muServiceFrom(t, cfg2); !errors.Is(err, ErrMUConfig) {
			t.Error("config admitted", name, err)
		}
	}
}
