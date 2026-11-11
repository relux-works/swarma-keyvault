package seedsetup

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Actual child setup distinguishes a refused exec from a child that ran and
// lost its public reply. Only Apple's inert true/false programs are executed;
// the PTY receives no fixture words because neither program asks for them.
func TestPublicChildDispatchState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	home := t.TempDir()
	missing := filepath.Join(home, "absent-binary")
	if r := command(ctx, home, missing); r.started || len(r.raw) != 0 {
		t.Fatal("missing exec reported dispatched")
	}
	if r := command(ctx, home, "/usr/bin/true"); !r.started || r.exit != 0 || len(r.raw) != 0 {
		t.Fatal("valid child did not start", r.exit)
	}
	target := publicTarget{"fixture-north", "fixture-south", 1, 1, 1}
	w := workflow{out: &bytes.Buffer{}}
	notStarted := publicFixtureRestore(ctx, home, missing, target)
	if notStarted.started {
		t.Fatal("missing PTY exec reported dispatched")
	}
	if _, err := w.mutationReply(notStarted, target, "restore"); err == nil || err.Error() != "vault_child_not_started" {
		t.Fatal("prestart refusal became uncertain", err)
	}
	ran := publicFixtureRestore(ctx, home, "/usr/bin/false", target)
	if !ran.started {
		t.Fatal("inert PTY child was not started")
	}
	if _, err := w.mutationReply(ran, target, "restore"); err == nil || err.Error() != unknownMutation {
		t.Fatal("dispatched lost reply lost uncertainty", err)
	}
}
