package grants

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func muEffectDecision() MUDecision {
	d := muDecision("sha256:"+strings.Repeat("ab", 32), "n1", "until_expiry")
	d.Arguments = map[string]string{"module": "swarma-keyvault", "title": "Review the integrated multi-use grant solution"}
	return d
}

// script writes an executable fake task-board that records each start in
// marker and prints out (or exits with code).
func script(t *testing.T, out string, code int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	path := filepath.Join(dir, "task-board")
	body := "#!/bin/sh\nprintf x >> '" + marker + "'\nprintf '%s' '" + out + "'\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return path, marker
}

func started(marker string) int {
	b, _ := os.ReadFile(marker)
	return len(b)
}

// Claim: the effect creates exactly one task through the real installed
// task-board CLI on a throwaway board, named from the request hash, with a
// receipt carrying the created element id. Limit: docking with whatever
// task-board is installed on PATH; skipped when it is absent.
func TestMUTaskBoardAssignDocking(t *testing.T) {
	bin, err := exec.LookPath("task-board")
	if err != nil {
		t.Skip("task-board not installed: docking not run")
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		t.Skip("task-board path unresolved: docking not run")
	}
	// The CLI keeps its mutation locks under TMPDIR, outside --board-dir; give
	// it a private TMPDIR so the run leaves nothing behind.
	t.Setenv("TMPDIR", t.TempDir())
	board := filepath.Join(t.TempDir(), ".task-board")
	if err := os.Mkdir(board, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(dsl string) string {
		out, err := exec.Command(bin, "--board-dir", board, "m", dsl).Output()
		if err != nil {
			t.Skip("task-board unusable in this environment: docking not run")
		}
		var r struct{ Result struct{ ID string } }
		if json.Unmarshal(out, &r) != nil || r.Result.ID == "" {
			t.Fatal("setup create", string(out))
		}
		return r.Result.ID
	}
	epic := run(`create(type=epic, name="mu-docking")`)
	story := run(`create(type=story, name="mu-docking-story", parent=` + epic + `)`)
	e := TaskBoardAssign{Path: bin, SHA256: fileSHA(t, bin), BoardDir: board, Parent: story}
	receipt, err := e.Execute(context.Background(), muEffectDecision())
	if err != nil {
		t.Fatal("effect refused", err)
	}
	var r map[string]string
	if err := json.Unmarshal(receipt, &r); err != nil || r["type"] != "mu-work-assign-receipt/1" || !strings.HasPrefix(r["element_id"], "TASK-") {
		t.Fatal("receipt", string(receipt))
	}
	out, err := exec.Command(bin, "--board-dir", board, "q", "get("+r["element_id"]+") { name parent description }").Output()
	if err != nil || !strings.Contains(string(out), `"name":"granted-`) || !strings.Contains(string(out), story) || !strings.Contains(string(out), "Review the integrated multi-use grant solution") {
		t.Fatal("created element", err, string(out))
	}
}

// Claim: every invalid request is refused before any process starts.
func TestMUTaskBoardAssignRefusesBeforeLaunch(t *testing.T) {
	path, marker := script(t, `{"ok":true,"result":{"id":"TASK-1"}}`, 0)
	good := TaskBoardAssign{Path: path, SHA256: fileSHA(t, path), BoardDir: t.TempDir(), Parent: "STORY-1"}
	cases := map[string]func(*TaskBoardAssign, *MUDecision){
		"other-action":   func(e *TaskBoardAssign, d *MUDecision) { d.Action = "account.manage" },
		"quote-title":    func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["title"] = `x", parent=EVIL` },
		"backslash":      func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["title"] = `x\y` },
		"control-title":  func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["title"] = "x\ny" },
		"long-title":     func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["title"] = strings.Repeat("я", muTitleLimit+1) },
		"empty-title":    func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["title"] = "" },
		"bad-module":     func(e *TaskBoardAssign, d *MUDecision) { d.Arguments["module"] = "../x" },
		"bad-parent":     func(e *TaskBoardAssign, d *MUDecision) { e.Parent = "STORY-1) delete(" },
		"relative-board": func(e *TaskBoardAssign, d *MUDecision) { e.BoardDir = "board" },
		"hash-drift":     func(e *TaskBoardAssign, d *MUDecision) { e.SHA256 = strings.Repeat("0", 64) },
		"bad-grant-id":   func(e *TaskBoardAssign, d *MUDecision) { d.GrantID = "grant-U" },
	}
	for name, mutate := range cases {
		e, d := good, muEffectDecision()
		mutate(&e, &d)
		if _, err := e.Execute(context.Background(), d); !errors.Is(err, ErrMUEffect) {
			t.Fatal("refusal expected", name, err)
		}
	}
	if started(marker) != 0 {
		t.Fatal("a refused request started a process")
	}
	if _, err := good.Execute(context.Background(), muEffectDecision()); err != nil || started(marker) != 1 {
		t.Fatal("valid neighbour", err, started(marker))
	}
}

// Claim: a failed, unconfirmed or mismatched CLI result is refused (the
// receiver turns it into UNKNOWN), after exactly one start.
func TestMUTaskBoardAssignFailedResults(t *testing.T) {
	for name, c := range map[string]struct {
		out  string
		code int
	}{
		"exit-1":     {`{"ok":true,"result":{"id":"TASK-1"}}`, 1},
		"ok-false":   {`{"ok":false,"errors":[]}`, 0},
		"bad-json":   {`not json`, 0},
		"not-task":   {`{"ok":true,"result":{"id":"STORY-1"}}`, 0},
		"wrong-name": {`{"ok":true,"result":{"id":"TASK-1","name":"other"}}`, 0},
	} {
		path, marker := script(t, c.out, c.code)
		e := TaskBoardAssign{Path: path, SHA256: fileSHA(t, path), BoardDir: t.TempDir(), Parent: "STORY-1"}
		if _, err := e.Execute(context.Background(), muEffectDecision()); !errors.Is(err, ErrMUEffect) || started(marker) != 1 {
			t.Fatal("failed result accepted or not run once", name, err, started(marker))
		}
	}
}
