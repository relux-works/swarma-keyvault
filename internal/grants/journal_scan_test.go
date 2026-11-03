package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// Independent frozen frame bytes yield exact physical summaries at empty, one
// and two-frame EOF boundaries. This does not validate their opaque body records.
func TestJournalScanGolden(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	for _, c := range []struct {
		name  string
		wire  []byte
		count uint64
	}{
		{"empty", nil, 0},
		{"one", first, 1},
		{"two", append(bytes.Clone(first), second...), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := bytes.Clone(c.wire)
			got, err := scanJournalFrames(bytes.NewReader(c.wire), link.epoch, journalScanMaxBytes)
			if err != nil || got == nil || got.frameCount != c.count || got.byteCount != int64(len(c.wire)) {
				t.Fatalf("golden summary: %#v %v", got, err)
			}
			var digest [32]byte
			if len(c.wire) != 0 {
				copy(digest[:], c.wire[len(c.wire)-32:])
			}
			if got.lastDigest != digest || !bytes.Equal(c.wire, before) {
				t.Fatal("wrong last digest or changed input")
			}
		})
	}
}

// Invalid byte budgets are refused before any input read; the largest admitted
// budget and a minimal positive budget both allow an empty physical stream.
func TestJournalScanBudgetAdmission(t *testing.T) {
	first, _, link, _ := journalGoldens(t)
	for _, limit := range []int64{-1, 0, journalScanMaxBytes + 1, math.MaxInt64} {
		r := &journalTrackingReader{data: first}
		if got, err := scanJournalFrames(r, link.epoch, limit); got != nil || err != errJournalScanLimit || r.calls != 0 {
			t.Fatalf("invalid limit%d: %#v %v calls=%d", limit, got, err, r.calls)
		}
	}
	for _, limit := range []int64{1, journalScanMaxBytes} {
		got, err := scanJournalFrames(bytes.NewReader(nil), link.epoch, limit)
		if err != nil || got == nil || *got != (journalScan{}) {
			t.Fatalf("empty positive control limit%d: %#v %v", limit, got, err)
		}
	}
}

// Exact-budget chains are accepted; every tested over-budget variant is refused
// without a prefix summary and consumes at most budget+1 bytes, including a
// single hidden byte following an otherwise complete exact-budget prefix.
func TestJournalScanByteBudget(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	wire := append(bytes.Clone(first), second...)
	got, err := scanJournalFrames(bytes.NewReader(wire), link.epoch, int64(len(wire)))
	if err != nil || got == nil || got.frameCount != 2 || got.byteCount != int64(len(wire)) {
		t.Fatalf("exact budget: %#v %v", got, err)
	}
	for _, c := range []struct {
		name  string
		wire  []byte
		limit int64
	}{
		{"one-over", wire, int64(len(wire) - 1)},
		{"frame-over", wire, int64(len(first))},
		{"single-hidden-byte", append(bytes.Clone(first), 0), int64(len(first))},
		{"header-over", first, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &journalTrackingReader{data: c.wire}
			got, err := scanJournalFrames(r, link.epoch, c.limit)
			if got != nil || err != errJournalScanLimit || int64(r.read) != c.limit+1 {
				t.Fatalf("budget refusal: %#v %v read=%d limit=%d", got, err, r.read, c.limit)
			}
		})
	}
}

// Any nonempty proper second-frame prefix makes the whole scan incomplete with
// no usable summary. A complete first-frame boundary remains a valid control;
// refusal never modifies the caller's bytes or authorizes tail truncation.
func TestJournalScanIncompleteTail(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	if got, err := scanJournalFrames(bytes.NewReader(first), link.epoch, journalScanMaxBytes); got == nil || err != nil {
		t.Fatalf("valid prefix boundary: %#v %v", got, err)
	}
	for n := 1; n < len(second); n++ {
		wire := append(bytes.Clone(first), second[:n]...)
		before := bytes.Clone(wire)
		got, err := scanJournalFrames(bytes.NewReader(wire), link.epoch, journalScanMaxBytes)
		if got != nil || err != errJournalFrameIncomplete || !bytes.Equal(wire, before) {
			t.Fatalf("incomplete tail%d: %#v %v", n, got, err)
		}
	}
}

func journalScanRehash(wire []byte) []byte {
	sum := sha256.Sum256(wire[:len(wire)-32])
	copy(wire[len(wire)-32:], sum[:])
	return wire
}

// Even correctly recomputed physical checksums cannot excuse a duplicate,
// missing/reordered sequence, wrong predecessor or mixed epoch reference.
// A valid two-frame control ensures rejection is not unconditional.
func TestJournalScanRejectsChainChanges(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	if _, err := scanJournalFrames(bytes.NewReader(append(bytes.Clone(first), second...)), link.epoch, journalScanMaxBytes); err != nil {
		t.Fatal("valid chain", err)
	}
	cases := []struct {
		name string
		wire []byte
	}{
		{"duplicate", append(bytes.Clone(first), first...)},
		{"reordered", append(bytes.Clone(second), first...)},
		{"missing-genesis", second},
	}
	for _, c := range []struct {
		name string
		edit func([]byte)
	}{
		{"missing-sequence", func(b []byte) { binary.BigEndian.PutUint64(b[16:24], 3) }},
		{"predecessor", func(b []byte) { b[24] ^= 1 }},
		{"epoch", func(b []byte) { b[56] ^= 1 }},
	} {
		changed := bytes.Clone(second)
		c.edit(changed)
		cases = append(cases, struct {
			name string
			wire []byte
		}{c.name, append(bytes.Clone(first), journalScanRehash(changed)...)})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := scanJournalFrames(bytes.NewReader(c.wire), link.epoch, journalScanMaxBytes)
			if got != nil || err != errJournalFrameLink {
				t.Fatalf("chain refusal: %#v %v", got, err)
			}
		})
	}
}

// Corruption before or after a complete prefix and trailing garbage all return
// no summary with the intended framing error, rather than accepting prefix state.
func TestJournalScanRejectsCorruptStream(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	wire := append(bytes.Clone(first), second...)
	for _, offset := range []int{88, len(first) - 1, len(first) + 88, len(wire) - 1} {
		changed := bytes.Clone(wire)
		changed[offset] ^= 1
		got, err := scanJournalFrames(bytes.NewReader(changed), link.epoch, journalScanMaxBytes)
		if got != nil || err != errJournalFrameChecksum {
			t.Fatalf("corruption at%d: %#v %v", offset, got, err)
		}
	}
	for _, c := range []struct {
		tail []byte
		want error
	}{
		{[]byte{0}, errJournalFrameIncomplete},
		{make([]byte, 88), errJournalFrameFormat},
	} {
		got, err := scanJournalFrames(bytes.NewReader(append(bytes.Clone(wire), c.tail...)), link.epoch, journalScanMaxBytes)
		if got != nil || !errors.Is(err, c.want) {
			t.Fatalf("trailing garbage: %#v %v", got, err)
		}
	}
}

// Reader failures at header/body/boundary positions remain unavailable and
// disclose neither arbitrary diagnostics nor an already-checked prefix summary.
func TestJournalScanReaderFailure(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	wire := append(bytes.Clone(first), second...)
	for _, n := range []int{0, 7, 90, len(first), len(first) + 90, len(wire)} {
		r := io.MultiReader(bytes.NewReader(wire[:n]), journalErrorReader{})
		got, err := scanJournalFrames(r, link.epoch, journalScanMaxBytes)
		if got != nil || err != errJournalFrameRead || strings.Contains(err.Error(), "private") {
			t.Fatalf("reader failure at%d: %#v %v", n, got, err)
		}
	}
}

type journalScanDataErrorReader struct {
	data []byte
	at   int
	read int
	err  error
}

func (r *journalScanDataErrorReader) Read(p []byte) (int, error) {
	if r.read == r.at {
		return 0, r.err
	}
	n := min(len(p), r.at-r.read, len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	r.read += n
	if r.read == r.at {
		return n, r.err
	}
	return n, nil
}

// Errors returned alongside a complete requested header/body are retained even
// when ReadFull would discard them. Ordinary complete golden streams still pass.
func TestJournalScanReaderDataWithError(t *testing.T) {
	first, second, link, _ := journalGoldens(t)
	wire := append(bytes.Clone(first), second...)
	for _, c := range []struct {
		err  error
		want error
	}{
		{errors.New("private data-bearing reader diagnostic"), errJournalFrameRead},
		{io.ErrUnexpectedEOF, errJournalFrameIncomplete},
	} {
		for _, at := range []int{88, len(first), len(first) + 88, len(wire)} {
			r := &journalScanDataErrorReader{data: wire, at: at, err: c.err}
			got, err := scanJournalFrames(r, link.epoch, journalScanMaxBytes)
			if got != nil || err != c.want || strings.Contains(err.Error(), "private") {
				t.Fatalf("data with error at%d: %#v %v", at, got, err)
			}
		}
	}
	if got, err := scanJournalFrames(bytes.NewReader(wire), link.epoch, journalScanMaxBytes); err != nil || got == nil || got.frameCount != 2 {
		t.Fatalf("valid data control: %#v %v", got, err)
	}
}
