package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Outpoint is public transaction identity; request correlation does not partition
// its replay fence. The byte order is the engine's fixed internal txid order.
type Outpoint struct {
	Transaction [32]byte
	Index       uint32
}
type AttemptID [32]byte

type Outcome uint8

const (
	Dispatched Outcome = 1
	Signed     Outcome = 2
	Unknown    Outcome = 3
)

type attempt struct {
	inputs     []Outpoint
	outcome    Outcome
	result     [32]byte
	commitment [32]byte
	bound      bool
}

// Ledger is an in-memory model reconstructed from complete, authenticated history.
// It has no reset/unfence operation. Persisted DISPATCHED is already a fence;
// uncertainty, request-ID changes and process death never release an input.
// This model does not establish actual signature production or storage ordering.
type Ledger struct {
	attempts       map[AttemptID]attempt
	used           map[Outpoint]AttemptID
	accountMatched bool
}

func newLedger() *Ledger {
	return &Ledger{attempts: make(map[AttemptID]attempt), used: make(map[Outpoint]AttemptID)}
}
func (l *Ledger) clone() *Ledger {
	next := newLedger()
	next.accountMatched = l.accountMatched
	for id, a := range l.attempts {
		a.inputs = append([]Outpoint(nil), a.inputs...)
		next.attempts[id] = a
	}
	for p, id := range l.used {
		next.used[p] = id
	}
	return next
}

// Transition is a proposed immutable update and its exact local body. It is not
// completion evidence. The native engine must use a crash-safe journal/anchor
// sequence under the gate, then rederive account integrity before private use.
type Transition struct {
	Ledger *Ledger
	Body   []byte
}

func (l *Ledger) Dispatch(id AttemptID, inputs []Outpoint) (Transition, error) {
	return l.dispatch(id, inputs, nil)
}

// DispatchBound additionally commits the exact immutable public attempt
// descriptor. Its authenticated bytes bind plan/phase/slot and independently
// selected policy/pins, rather than trusting a later caller-created receipt.
func (l *Ledger) DispatchBound(id AttemptID, inputs []Outpoint, commitment [32]byte) (Transition, error) {
	return l.dispatch(id, inputs, &commitment)
}
func (l *Ledger) dispatch(id AttemptID, inputs []Outpoint, commitment *[32]byte) (Transition, error) {
	if l == nil || l.attempts == nil || len(inputs) < 1 || len(inputs) > 4096 {
		return Transition{}, ErrInvalid
	}
	if _, exists := l.attempts[id]; exists {
		return Transition{}, ErrReplay
	}
	seen := make(map[Outpoint]bool, len(inputs))
	for _, p := range inputs {
		if seen[p] {
			return Transition{}, ErrInvalid
		}
		seen[p] = true
	}
	for _, p := range inputs {
		if _, exists := l.used[p]; exists {
			return Transition{}, ErrReplay
		}
	}
	next := l.clone()
	next.attempts[id] = attempt{inputs: append([]Outpoint(nil), inputs...), outcome: Dispatched}
	if commitment != nil {
		a := next.attempts[id]
		a.bound = true
		a.commitment = *commitment
		next.attempts[id] = a
	}
	for _, p := range inputs {
		next.used[p] = id
	}
	raw := []byte("KVNT1\x00")
	if commitment != nil {
		raw = []byte("KVNT2\x00")
	}
	raw = append(raw, byte(Dispatched))
	raw = append(raw, id[:]...)
	if commitment != nil {
		raw = append(raw, commitment[:]...)
	}
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(inputs)))
	for _, p := range inputs {
		raw = append(raw, p.Transaction[:]...)
		raw = binary.BigEndian.AppendUint32(raw, p.Index)
	}
	return Transition{next, raw}, nil
}

// Complete records the hash of the exact complete result. It never synthesizes
// or verifies transaction signatures. Completion requires the actual engine's
// verification and durable result/readback before this state is reported usable.
func (l *Ledger) Complete(id AttemptID, exactResult []byte) (Transition, error) {
	// A4MiB decoded PSBT plus base64,128 signatures and receipt fits8MiB.
	if len(exactResult) == 0 || len(exactResult) > 8*1024*1024 {
		return Transition{}, ErrInvalid
	}
	return l.finish(id, Signed, sha256.Sum256(exactResult))
}
func (l *Ledger) MarkUnknown(id AttemptID) (Transition, error) {
	return l.finish(id, Unknown, [32]byte{})
}
func (l *Ledger) finish(id AttemptID, outcome Outcome, result [32]byte) (Transition, error) {
	if l == nil {
		return Transition{}, ErrInvalid
	}
	a, exists := l.attempts[id]
	if !exists || a.outcome != Dispatched {
		return Transition{}, ErrUnknown
	}
	next := l.clone()
	a.outcome = outcome
	a.result = result
	next.attempts[id] = a
	raw := []byte("KVNT1\x00")
	raw = append(raw, byte(outcome))
	raw = append(raw, id[:]...)
	raw = append(raw, result[:]...)
	return Transition{next, raw}, nil
}

// Outcome never treats a missing or unfinished request as proof nothing signed.
// Signed classification also requires account rederivation in the source anchor;
// this fact is never serialized or supplied as a caller boolean. The exact result
// still needs protected provenance/hash and public signature verification.
func (l *Ledger) Outcome(id AttemptID) (Outcome, [32]byte, error) {
	if l == nil {
		return Unknown, [32]byte{}, ErrMissing
	}
	a, exists := l.attempts[id]
	if !exists {
		return Unknown, [32]byte{}, ErrMissing
	}
	if a.outcome != Signed {
		return Unknown, [32]byte{}, nil
	}
	if !l.accountMatched {
		return Unknown, [32]byte{}, ErrUnknown
	}
	return Signed, a.result, nil
}

// Commitment is consistency evidence from the checked history; it does not
// claim account rederivation. A usable SIGNED outcome still requires Outcome's
// independent accountMatched gate and verification of the exact result bytes.
func (l *Ledger) Commitment(id AttemptID) ([32]byte, error) {
	if l == nil {
		return [32]byte{}, ErrMissing
	}
	a, ok := l.attempts[id]
	if !ok {
		return [32]byte{}, ErrMissing
	}
	if !a.bound {
		return [32]byte{}, ErrUnknown
	}
	return a.commitment, nil
}

func apply(l *Ledger, raw []byte) (*Ledger, error) {
	if len(raw) > MaxBody {
		return nil, ErrUnknown
	}
	d := decoder{raw: raw}
	magic := d.take(6)
	bound := bytes.Equal(magic, []byte("KVNT2\x00"))
	if !bound && !bytes.Equal(magic, []byte("KVNT1\x00")) {
		return nil, ErrUnknown
	}
	tag := d.take(1)
	var outcome Outcome
	if len(tag) == 1 {
		outcome = Outcome(tag[0])
	}
	var id AttemptID
	copy(id[:], d.take(32))
	var commitment [32]byte
	if bound {
		if outcome != Dispatched {
			return nil, ErrUnknown
		}
		copy(commitment[:], d.take(32))
	}
	var tr Transition
	var err error
	switch outcome {
	case Dispatched:
		n := d.u32()
		if n < 1 || n > 4096 {
			return nil, ErrUnknown
		}
		inputs := make([]Outpoint, int(n))
		for i := range inputs {
			copy(inputs[i].Transaction[:], d.take(32))
			inputs[i].Index = d.u32()
		}
		if !d.end() {
			return nil, ErrUnknown
		}
		if bound {
			tr, err = l.DispatchBound(id, inputs, commitment)
		} else {
			tr, err = l.Dispatch(id, inputs)
		}
	case Signed, Unknown:
		var result [32]byte
		copy(result[:], d.take(32))
		if !d.end() || outcome == Unknown && result != [32]byte{} {
			return nil, ErrUnknown
		}
		tr, err = l.finish(id, outcome, result)
	default:
		return nil, ErrUnknown
	}
	if err != nil {
		return nil, ErrUnknown
	}
	return tr.Ledger, nil
}

// RestoreLedger refuses missing state and validates both physical and typed
// history against the existing anchor. Empty history is valid only for its
// authenticated genesis. No load/sign/reconcile path creates another anchor.
func (a *Anchor) RestoreLedger(records [][]byte) (*Ledger, error) {
	if a == nil {
		return nil, ErrMissing
	}
	if len(records) > 65536 {
		return nil, ErrUnknown
	}
	total := 0
	for _, raw := range records {
		if len(raw) > MaxBody+50 {
			return nil, ErrUnknown
		}
		total += len(raw)
		if total > 64*1024*1024 {
			return nil, ErrUnknown
		}
	}
	// The caller must not concurrently mutate its slices. Own a single snapshot
	// before either physical verification or typed replay, with bounded allocation.
	snapshot := make([][]byte, len(records))
	for i := range records {
		snapshot[i] = append([]byte(nil), records[i]...)
	}
	if err := a.CheckChain(snapshot); err != nil {
		return nil, err
	}
	l := newLedger()
	a.mu.Lock()
	l.accountMatched = a.accountMatched && a.authentic()
	a.mu.Unlock()
	for _, raw := range snapshot {
		f, err := DecodeFrame(raw)
		if err != nil {
			return nil, ErrUnknown
		}
		l, err = apply(l, f.Body)
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}
