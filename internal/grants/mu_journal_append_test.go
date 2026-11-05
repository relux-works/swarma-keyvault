package grants

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: with the BSD append-only flag (user variant uappnd, same open
// semantics as the root-set sappnd) on mu.journal, the receiver still replays
// and appends: two in-scope requests succeed and the journal only grows. The
// same flag refuses a truncating open and a rename of the journal, so the
// fixture really is append-only. Limit: uappnd stands in for sappnd; a root
// process can still clear either flag.
func TestMUJournalAppendOnlyFlag(t *testing.T) {
	g := newMURig(t)
	g.v.decisions["$1"] = muDecision("grant-U", "a1", "until_expiry")
	if _, err := g.handle("$1"); err != nil {
		t.Fatal("first request refused", err)
	}
	path := filepath.Join(g.state.Directory, "mu.journal")
	if err := unix.Chflags(path, unix.UF_APPEND); err != nil {
		t.Skip("cannot set uappnd here:", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(path, 0) })
	before := len(g.journal(t))
	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		f.Close()
		t.Fatal("append-only fixture admitted a truncating open")
	}
	if err := os.Rename(path, path+".old"); err == nil {
		t.Fatal("append-only fixture admitted a rename")
	}
	g.v.decisions["$2"] = muDecision("grant-U", "a2", "until_expiry")
	if out, err := g.handle("$2"); err != nil || out.State != "succeeded" {
		t.Fatal("receiver failed on an append-only journal", out, err)
	}
	if after := len(g.journal(t)); after <= before {
		t.Fatal("journal did not grow", before, after)
	}
	g.v.decisions["$3"] = muDecision("grant-U", "a2", "until_expiry")
	if _, err := g.handle("$3"); !errors.Is(err, ErrMUNonceHeld) {
		t.Fatal("replay after reopen on the flagged journal not refused", err)
	}
	if g.effect.calls != 2 {
		t.Fatal("effects", g.effect.calls)
	}
}
