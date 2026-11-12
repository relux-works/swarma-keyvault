package namecoinjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

const MaxBody = 256 * 1024

// Frame is a local physical record, not a facade wire or a public receipt.
// Body is opaque here: lifecycle validation is a separate obligation. A hash
// chain alone cannot authenticate an attacker-replaced file or detect rollback.
type Frame struct {
	Sequence uint64
	Previous [32]byte
	Body     []byte
}

func EncodeFrame(f Frame) ([]byte, error) {
	if f.Sequence == 0 || len(f.Body) == 0 || len(f.Body) > MaxBody {
		return nil, ErrInvalid
	}
	raw := []byte("KVNF1\x00")
	raw = binary.BigEndian.AppendUint64(raw, f.Sequence)
	raw = append(raw, f.Previous[:]...)
	raw = lp(raw, f.Body)
	return raw, nil
}
func DecodeFrame(raw []byte) (Frame, error) {
	var f Frame
	if len(raw) > MaxBody+50 {
		return f, ErrInvalid
	}
	d := decoder{raw: raw}
	d.magic("KVNF1\x00")
	f.Sequence = d.u64()
	copy(f.Previous[:], d.take(32))
	f.Body = append([]byte(nil), d.blob(MaxBody)...)
	if !d.end() || f.Sequence == 0 || len(f.Body) == 0 {
		return Frame{}, ErrInvalid
	}
	return f, nil
}

// Append changes in-memory state only. Persist/fsync the complete fenced record
// and protected anchor/readback before ECDSA; any partial durable outcome is
// UNKNOWN. The caller must not treat a successful pure append as durable.
func (a *Anchor) Append(body []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.authentic() || a.sequence == math.MaxUint64 {
		return nil, ErrUnknown
	}
	raw, err := EncodeFrame(Frame{Sequence: a.sequence + 1, Previous: a.head, Body: body})
	if err != nil {
		return nil, err
	}
	a.sequence++
	a.head = sha256.Sum256(raw)
	a.token = headToken(a.key, a.binding, a.sequence, a.head)
	return raw, nil
}

// CheckChain starts at genesis and requires every record through the exact
// anchor head. Empty/missing/truncated/reordered/replayed files never acquire a
// new genesis. Limits bound work, not storage durability or typed semantics.
func (a *Anchor) CheckChain(records [][]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.authentic() || len(records) > 65536 || uint64(len(records)) != a.sequence {
		return ErrUnknown
	}
	head := genesis(a.binding)
	total := 0
	for i, raw := range records {
		total += len(raw)
		if total > 64*1024*1024 {
			return ErrUnknown
		}
		f, err := DecodeFrame(raw)
		if err != nil || f.Sequence != uint64(i)+1 || f.Previous != head {
			return ErrUnknown
		}
		head = sha256.Sum256(raw)
	}
	if head != a.head {
		return ErrUnknown
	}
	return nil
}
