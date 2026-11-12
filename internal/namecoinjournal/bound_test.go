package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// The descriptor commitment survives completion/restart and subsequent real
// history advancement, while a legacy unbound attempt cannot supply one.
// This is authenticated pure-model evidence, not durable/native execution.
func TestBoundAttemptHistoryAndLegacyRefusal(t *testing.T) {
	a := fixtureAnchor(t)
	defer a.Clear()
	l, err := a.RestoreLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := AttemptID{3}
	commit := sha256.Sum256([]byte("exact immutable public attempt descriptor"))
	tr, err := l.DispatchBound(id, []Outpoint{fixtureInput()}, commit)
	if err != nil {
		t.Fatal(err)
	}
	var history [][]byte
	l = addTransition(t, a, &history, tr)
	got, err := l.Commitment(id)
	if err != nil || got != commit {
		t.Fatal("descriptor binding lost", err)
	}
	result := []byte("exact public completed result")
	tr, err = l.Complete(id, result)
	if err != nil {
		t.Fatal(err)
	}
	l = addTransition(t, a, &history, tr)
	tr, err = l.Dispatch(AttemptID{4}, []Outpoint{{Transaction: [32]byte{8}}})
	if err != nil {
		t.Fatal(err)
	}
	l = addTransition(t, a, &history, tr)
	if _, err = l.Commitment(AttemptID{4}); !errors.Is(err, ErrUnknown) {
		t.Fatal("legacy attempt invented descriptor authority")
	}
	got, err = l.Commitment(id)
	if err != nil || got != commit {
		t.Fatal("later history replaced prior descriptor")
	}
	outcome, hash, err := l.Outcome(id)
	if err != nil || outcome != Signed || hash != sha256.Sum256(result) {
		t.Fatal("historical completed result lost", err)
	}
	protected, err := a.EncodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	restarted, err := DecodeProtected(protected, fixtureBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Clear()
	material := fixtureMaterial()
	defer clear(material)
	if err = restarted.VerifyAccount(material); err != nil {
		t.Fatal(err)
	}
	l, err = restarted.RestoreLedger(history)
	if err != nil {
		t.Fatal(err)
	}
	got, err = l.Commitment(id)
	if err != nil || got != commit {
		t.Fatal("restart lost exact binding", err)
	}
	bad := bytes.Clone(history[0])
	bad[50+7+32] ^= 1 // first committed descriptor byte in the physical frame
	corrupt := append([][]byte(nil), history...)
	corrupt[0] = bad
	if _, err = restarted.RestoreLedger(corrupt); !errors.Is(err, ErrUnknown) {
		t.Fatal("descriptor tamper admitted")
	}
}

// Bound dispatch forbids truncation, unsupported tags and duplicate effects;
// the valid control must restore first so rejection is not setup failure.
func TestBoundRecordRejectionsAndResultLimits(t *testing.T) {
	l := newLedger()
	id := AttemptID{1}
	tr, err := l.DispatchBound(id, []Outpoint{fixtureInput()}, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = apply(newLedger(), tr.Body); err != nil {
		t.Fatal("valid bound body refused", err)
	}
	for _, bad := range [][]byte{tr.Body[:len(tr.Body)-1], append(bytes.Clone(tr.Body), 0), append([]byte("KVNT3\x00"), tr.Body[6:]...), append(append(bytes.Clone(tr.Body[:6]), byte(Signed)), tr.Body[7:]...)} {
		if _, err = apply(newLedger(), bad); !errors.Is(err, ErrUnknown) {
			t.Fatal("malformed bound body admitted")
		}
	}
	if _, err = tr.Ledger.DispatchBound(AttemptID{2}, []Outpoint{fixtureInput()}, [32]byte{10}); !errors.Is(err, ErrReplay) {
		t.Fatal("new descriptor/request bypassed outpoint fence")
	}
	if _, err = tr.Ledger.Complete(id, make([]byte, 4*1024*1024+1)); err != nil {
		t.Fatal("base64-sized valid result refused")
	}
	if _, err = tr.Ledger.Complete(id, make([]byte, 8*1024*1024+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized result admitted")
	}
	for _, identity := range []string{"fixture/recovery@2147483647", "-/recovery@1"} {
		b := fixtureBinding()
		b.Group = identity
		if !b.valid() {
			t.Fatal("existing legitimate identity refused")
		}
	}
	b := fixtureBinding()
	b.Group = "fixture/recovery@2147483648"
	if b.valid() {
		t.Fatal("unsupported retained generation admitted")
	}
}
