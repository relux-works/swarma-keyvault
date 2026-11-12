package namecoinjournal

import (
	"bytes"
	"errors"
	"testing"
)

func fixtureInput() Outpoint { return Outpoint{Transaction: [32]byte{7}, Index: 1} }
func addTransition(t *testing.T, a *Anchor, history *[][]byte, tr Transition) *Ledger {
	t.Helper()
	raw, e := a.Append(tr.Body)
	if e != nil {
		t.Fatal(e)
	}
	*history = append(*history, raw)
	l, e := a.RestoreLedger(*history)
	if e != nil {
		t.Fatal(e)
	}
	return l
}

// Positive complete-result reconstruction is paired with different-request-ID
// replay of the same outpoint. This proves the pure model, not OS serialization,
// real ECDSA, signed-result verification, fsync or protected-item confinement.
func TestReplayFenceSurvivesDifferentRequestsAndRestart(t *testing.T) {
	a := fixtureAnchor(t)
	l, e := a.RestoreLedger(nil)
	if e != nil {
		t.Fatal(e)
	}
	id := AttemptID{1}
	var history [][]byte
	tr, e := l.Dispatch(id, []Outpoint{fixtureInput()})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = l.Outcome(id); !errors.Is(e, ErrMissing) {
		t.Fatal("transition mutated source ledger")
	}
	l = addTransition(t, a, &history, tr)
	outcome, _, e := l.Outcome(id)
	if e != nil || outcome != Unknown {
		t.Fatal("dispatch must be uncertain")
	}
	if _, e = l.Dispatch(AttemptID{2}, []Outpoint{fixtureInput()}); !errors.Is(e, ErrReplay) {
		t.Fatal("request ID bypass")
	}
	tr, e = l.Complete(id, []byte("public complete result fixture"))
	if e != nil {
		t.Fatal(e)
	}
	l = addTransition(t, a, &history, tr)
	outcome, hash, e := l.Outcome(id)
	if e != nil || outcome != Signed || hash == [32]byte{} {
		t.Fatal("completed result missing")
	}
	protected, e := a.EncodeProtected()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(protected)
	restarted, e := DecodeProtected(protected, fixtureBinding())
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Clear()
	unverified, e := restarted.RestoreLedger(history)
	if e != nil {
		t.Fatal(e)
	}
	if outcome, _, err := unverified.Outcome(id); outcome != Unknown || !errors.Is(err, ErrUnknown) {
		t.Fatal("stored-key consistency claimed authentic signed state")
	}
	if e = restarted.VerifyAccount(fixtureMaterial()); e != nil {
		t.Fatal(e)
	}
	l, e = restarted.RestoreLedger(history)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = l.Dispatch(AttemptID{3}, []Outpoint{fixtureInput()}); !errors.Is(e, ErrReplay) {
		t.Fatal("restart unfenced input")
	}
	if _, e = l.Complete(id, []byte("another result")); e == nil {
		t.Fatal("signed result overwritten")
	}
	// A different outpoint is a positive non-replay control.
	p := fixtureInput()
	p.Index++
	if _, e = l.Dispatch(AttemptID{4}, []Outpoint{p}); e != nil {
		t.Fatal("unrelated input incorrectly fenced")
	}
}

// Interrupted journal/anchor/result stages are not treated as another first run.
// These are representation mismatch witnesses; real process/power-loss durable
// ordering and Keychain readback remain native integration requirements.
func TestPartialEffectsAndUnknownRemainFenced(t *testing.T) {
	a := fixtureAnchor(t)
	l, e := a.RestoreLedger(nil)
	if e != nil {
		t.Fatal(e)
	}
	id := AttemptID{5}
	tr, e := l.Dispatch(id, []Outpoint{fixtureInput()})
	if e != nil {
		t.Fatal(e)
	}
	frame, e := EncodeFrame(Frame{Sequence: 1, Previous: genesis(fixtureBinding()), Body: tr.Body})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.CheckChain([][]byte{frame}); !errors.Is(e, ErrUnknown) {
		t.Fatal("journal ahead accepted")
	}
	var history [][]byte
	l = addTransition(t, a, &history, tr)
	if e = a.CheckChain(nil); !errors.Is(e, ErrUnknown) {
		t.Fatal("anchor ahead/truncation accepted")
	}
	tr, e = l.MarkUnknown(id)
	if e != nil {
		t.Fatal(e)
	}
	l = addTransition(t, a, &history, tr)
	if _, e = l.Dispatch(AttemptID{6}, []Outpoint{fixtureInput()}); !errors.Is(e, ErrReplay) {
		t.Fatal("UNKNOWN lost fence")
	}
	if _, e = l.Complete(id, []byte("late result")); e == nil {
		t.Fatal("UNKNOWN silently resumed")
	}
	if _, e = l.Dispatch(AttemptID{7}, []Outpoint{fixtureInput(), fixtureInput()}); !errors.Is(e, ErrInvalid) {
		t.Fatal("duplicate input")
	}
	if _, e = l.Dispatch(AttemptID{8}, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("empty input set")
	}
	var absent *Anchor
	if _, e = absent.RestoreLedger(nil); !errors.Is(e, ErrMissing) {
		t.Fatal("missing anchor initialized")
	}
}

// Frame chain checks include positive exact bytes, wrong order/predecessor,
// corruption and incomplete tails. Opaque body acceptance alone is explicitly
// weaker than typed replay: an authentic malformed body must still be refused.
func TestFramesAndTypedHistory(t *testing.T) {
	f := Frame{Sequence: 1, Previous: [32]byte{9}, Body: []byte{0, 1, 2}}
	raw, e := EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	expected := append([]byte("KVNF1\x00\x00\x00\x00\x00\x00\x00\x00\x01"), f.Previous[:]...)
	expected = append(expected, 0, 0, 0, 3, 0, 1, 2)
	if !bytes.Equal(raw, expected) {
		t.Fatal("frame layout")
	}
	decoded, e := DecodeFrame(raw)
	if e != nil || decoded.Sequence != f.Sequence || decoded.Previous != f.Previous || !bytes.Equal(decoded.Body, f.Body) {
		t.Fatal("frame roundtrip")
	}
	for i := 0; i < len(raw); i++ {
		if _, e = DecodeFrame(raw[:i]); e == nil {
			t.Fatal("truncated frame")
		}
	}
	if _, e = DecodeFrame(append(bytes.Clone(raw), 0)); e == nil {
		t.Fatal("trailing frame")
	}
	a := fixtureAnchor(t)
	bad, e := a.Append([]byte("not a typed transition"))
	if e != nil {
		t.Fatal(e)
	}
	if e = a.CheckChain([][]byte{bad}); e != nil {
		t.Fatal("physical positive required")
	}
	if _, e = a.RestoreLedger([][]byte{bad}); !errors.Is(e, ErrUnknown) {
		t.Fatal("opaque body trusted")
	}
	b := fixtureAnchor(t)
	l, e := b.RestoreLedger(nil)
	if e != nil {
		t.Fatal(e)
	}
	tr, e := l.Dispatch(AttemptID{1}, []Outpoint{fixtureInput()})
	if e != nil {
		t.Fatal(e)
	}
	good, e := b.Append(tr.Body)
	if e != nil {
		t.Fatal(e)
	}
	for i := range good {
		altered := bytes.Clone(good)
		altered[i] ^= 1
		if e = b.CheckChain([][]byte{altered}); e == nil {
			t.Fatalf("chain corruption accepted %d", i)
		}
	}
	if e = b.CheckChain([][]byte{good, good}); e == nil {
		t.Fatal("duplicate frame")
	}
	if _, e = b.Append(nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("empty body")
	}
	if _, e = EncodeFrame(Frame{Sequence: 1, Body: make([]byte, MaxBody+1)}); e == nil {
		t.Fatal("body bound")
	}
}
