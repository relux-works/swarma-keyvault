package grants

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// Fixed byte fixtures use independent big-endian field assembly and SHA-256.
// Their opaque bodies are not valid lifecycle records or authenticated observations.
const journalGoldenFirst = "535747524a4e4c31000101000000007f000000000000000100000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111016f706171756572fc46a8a9c4e521bbbfd512325010a0d54d0d9ad3eac9926d82079683d7130a"
const journalGoldenSecond = "535747524a4e4c31000106000000007d000000000000000272fc46a8a9c4e521bbbfd512325010a0d54d0d9ad3eac9926d82079683d7130a1111111111111111111111111111111111111111111111111111111111111111026e657874c34df480b9c3db257bd2fa37bfe76fb705e16b04d5dbc30ef7c7204796d266d5"

func journalGoldens(t *testing.T) ([]byte, []byte, journalFrameLink, journalFrameLink) {
	t.Helper()
	first, err := hex.DecodeString(journalGoldenFirst)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hex.DecodeString(journalGoldenSecond)
	if err != nil {
		t.Fatal(err)
	}
	a := journalFrameLink{sequence: 1}
	for i := range a.epoch {
		a.epoch[i] = 0x11
	}
	b := journalFrameLink{sequence: 2, epoch: a.epoch}
	copy(b.previous[:], first[len(first)-32:])
	return first, second, a, b
}

// Encoder and reader agree with independent exact bytes, including consecutive
// frame boundaries; successful framing deliberately leaves body interpretation open.
func TestJournalFrameGolden(t *testing.T) {
	first, second, a, b := journalGoldens(t)
	for _, c := range []struct {
		wire []byte
		kind journalFrameKind
		link journalFrameLink
		body []byte
	}{
		{first, journalActivation, a, []byte{1, 'o', 'p', 'a', 'q', 'u', 'e'}},
		{second, journalBlocked, b, []byte{2, 'n', 'e', 'x', 't'}},
	} {
		wire, err := encodeJournalFrame(c.kind, c.link, c.body)
		if err != nil || !bytes.Equal(wire, c.wire) {
			t.Fatalf("golden encode: %x, %v", wire, err)
		}
		frame, err := readJournalFrame(bytes.NewReader(c.wire), c.link)
		if err != nil || frame == nil || frame.kind != c.kind || frame.link != c.link ||
			!bytes.Equal(frame.body, c.body) || !bytes.Equal(frame.digest[:], c.wire[len(c.wire)-32:]) {
			t.Fatalf("golden decode: %#v, %v", frame, err)
		}
	}
	stream := bytes.NewReader(append(bytes.Clone(first), second...))
	if _, err := readJournalFrame(stream, a); err != nil || stream.Len() != len(second) {
		t.Fatalf("first boundary: remaining=%d err=%v", stream.Len(), err)
	}
	frame, err := readJournalFrame(stream, b)
	if err != nil || stream.Len() != 0 {
		t.Fatalf("second boundary: remaining=%d err=%v", stream.Len(), err)
	}
	if got, err := readJournalFrame(stream, journalFrameLink{sequence: 3, previous: frame.digest, epoch: b.epoch}); got != nil || err != io.EOF {
		t.Fatalf("boundary EOF: %#v, %v", got, err)
	}
}

type journalTrackingReader struct {
	data  []byte
	read  int
	calls int
}

func (r *journalTrackingReader) Read(p []byte) (int, error) {
	r.calls++
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.read += n
	return n, nil
}

// Malformed headers and mismatched expected links return no frame and never
// request payload bytes. This observes reads, not an arbitrary reader's time bound.
func TestJournalFrameRejectsHeaders(t *testing.T) {
	first, _, a, _ := journalGoldens(t)
	cases := []struct {
		name string
		edit func([]byte)
		want error
	}{
		{"magic", func(b []byte) { b[0] ^= 1 }, errJournalFrameFormat},
		{"version", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], 2) }, errJournalFrameFormat},
		{"kind-zero", func(b []byte) { b[10] = 0 }, errJournalFrameFormat},
		{"kind-future", func(b []byte) { b[10] = 7 }, errJournalFrameFormat},
		{"flags", func(b []byte) { b[11] = 1 }, errJournalFrameFormat},
		{"length-zero", func(b []byte) { binary.BigEndian.PutUint32(b[12:16], 0) }, errJournalFrameLimit},
		{"length-empty", func(b []byte) { binary.BigEndian.PutUint32(b[12:16], 120) }, errJournalFrameLimit},
		{"length-overflow", func(b []byte) { binary.BigEndian.PutUint32(b[12:16], math.MaxUint32) }, errJournalFrameLimit},
		{"kind-specific-limit", func(b []byte) { b[10] = 6; binary.BigEndian.PutUint32(b[12:16], 192) }, errJournalFrameLimit},
		{"zero-sequence", func(b []byte) { binary.BigEndian.PutUint64(b[16:24], 0) }, errJournalFrameLink},
		{"non-genesis-zero-previous", func(b []byte) { binary.BigEndian.PutUint64(b[16:24], 2) }, errJournalFrameLink},
		{"genesis-nonzero-previous", func(b []byte) { b[24] = 1 }, errJournalFrameLink},
		{"epoch", func(b []byte) { b[56] ^= 1 }, errJournalFrameLink},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wire := bytes.Clone(first)
			c.edit(wire)
			r := &journalTrackingReader{data: wire}
			if got, err := readJournalFrame(r, a); got != nil || !errors.Is(err, c.want) || r.read != 88 || r.calls != 1 {
				t.Fatalf("header rejection: frame=%#v err=%v read=%d calls=%d", got, err, r.read, r.calls)
			}
		})
	}
	_, second, _, b := journalGoldens(t)
	for _, change := range []func(*journalFrameLink){
		func(l *journalFrameLink) { l.sequence++ },
		func(l *journalFrameLink) { l.previous[0] ^= 1 },
		func(l *journalFrameLink) { l.epoch[0] ^= 1 },
	} {
		wrong := b
		change(&wrong)
		r := &journalTrackingReader{data: second}
		if got, err := readJournalFrame(r, wrong); got != nil || err != errJournalFrameLink || r.read != 88 {
			t.Fatalf("wrong expected link: %#v %v, read=%d", got, err, r.read)
		}
	}
	for _, invalid := range []journalFrameLink{{}, {sequence: 2}, {sequence: 1, previous: b.previous}} {
		r := &journalTrackingReader{data: first}
		if got, err := readJournalFrame(r, invalid); got != nil || err != errJournalFrameLink || r.calls != 0 {
			t.Fatalf("invalid expectation consumed input: %#v %v calls=%d", got, err, r.calls)
		}
	}
}

// Every proper prefix of a valid frame is incomplete, distinct from boundary EOF;
// none yields a partial usable frame or makes a repair/truncation decision.
func TestJournalFrameIncomplete(t *testing.T) {
	first, _, a, _ := journalGoldens(t)
	if got, err := readJournalFrame(bytes.NewReader(nil), a); got != nil || err != io.EOF {
		t.Fatalf("empty boundary: %#v %v", got, err)
	}
	for n := 1; n < len(first); n++ {
		if got, err := readJournalFrame(bytes.NewReader(first[:n]), a); got != nil || err != errJournalFrameIncomplete {
			t.Fatalf("prefix%d: %#v %v", n, got, err)
		}
	}
}

// Body and trailer corruption is detected against the retained checksum. This
// detects corruption only; a recomputed checksum does not authenticate a writer.
func TestJournalFrameRejectsCorruption(t *testing.T) {
	first, _, a, _ := journalGoldens(t)
	if _, err := readJournalFrame(bytes.NewReader(first), a); err != nil {
		t.Fatal("valid control", err)
	}
	for _, c := range []struct {
		name   string
		offset int
	}{{"body", 88}, {"trailer", len(first) - 1}} {
		t.Run(c.name, func(t *testing.T) {
			wire := bytes.Clone(first)
			wire[c.offset] ^= 1
			if got, err := readJournalFrame(bytes.NewReader(wire), a); got != nil || err != errJournalFrameChecksum {
				t.Fatalf("accepted corrupt frame: frame=%#v err=%v", got, err)
			}
		})
	}
}

type journalErrorReader struct{}

func (journalErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("private reader diagnostic")
}

// Non-EOF reader failures remain unavailable rather than incomplete/corrupt,
// and arbitrary reader diagnostics are not reflected into public error text.
func TestJournalFrameReaderErrors(t *testing.T) {
	first, _, a, _ := journalGoldens(t)
	for _, n := range []int{0, 7, 90} {
		r := io.MultiReader(bytes.NewReader(first[:n]), journalErrorReader{})
		got, err := readJournalFrame(r, a)
		if got != nil || err != errJournalFrameRead || strings.Contains(err.Error(), "private") {
			t.Fatalf("read failure at%d: %#v %v", n, got, err)
		}
	}
}

// All six provisional physical-kind caps accept their opaque maximum and reject
// max+1/empty without partial encoded output. This is not typed-body compatibility.
func TestJournalFramePhysicalLimits(t *testing.T) {
	_, _, a, _ := journalGoldens(t)
	for _, c := range []struct {
		kind  journalFrameKind
		limit int
	}{
		{journalActivation, 108739}, {journalReservation, 276784},
		{journalDispatchIntent, 1259}, {journalOutcome, 270425},
		{journalRevocation, 18476}, {journalBlocked, 71},
	} {
		body := bytes.Repeat([]byte{'x'}, c.limit)
		wire, err := encodeJournalFrame(c.kind, a, body)
		if err != nil || len(wire) != 88+c.limit+32 {
			t.Fatalf("max kind%d: len=%d err=%v", c.kind, len(wire), err)
		}
		got, err := readJournalFrame(bytes.NewReader(wire), a)
		if err != nil || !bytes.Equal(got.body, body) {
			t.Fatalf("max read kind%d: %v", c.kind, err)
		}
		for _, invalid := range [][]byte{nil, append(body, 'x')} {
			if got, err := encodeJournalFrame(c.kind, a, invalid); got != nil || err != errJournalFrameLimit {
				t.Fatalf("kind%d invalid length%d: len=%d %v", c.kind, len(invalid), len(got), err)
			}
		}
	}
	if got, err := encodeJournalFrame(7, a, []byte{'x'}); got != nil || err != errJournalFrameFormat {
		t.Fatalf("unknown kind: %x %v", got, err)
	}
}

// Returned buffers do not alias the caller's body/input; the final u64 sequence
// is representable, while a wrapped zero successor is refused before any read.
func TestJournalFrameOwnershipAndSequence(t *testing.T) {
	first, _, a, b := journalGoldens(t)
	body := bytes.Clone(first[88 : len(first)-32])
	wire, err := encodeJournalFrame(journalActivation, a, body)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 1
	if !bytes.Equal(wire, first) {
		t.Fatal("encoded wire aliases body")
	}
	frame, err := readJournalFrame(bytes.NewReader(wire), a)
	if err != nil {
		t.Fatal(err)
	}
	wire[88] ^= 1
	if !bytes.Equal(frame.body, first[88:len(first)-32]) {
		t.Fatal("decoded body aliases reader input")
	}
	b.sequence = math.MaxUint64
	wire, err = encodeJournalFrame(journalBlocked, b, []byte{'x'})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readJournalFrame(bytes.NewReader(wire), b); err != nil {
		t.Fatal(err)
	}
	b.sequence++
	r := &journalTrackingReader{data: wire}
	if got, err := readJournalFrame(r, b); got != nil || err != errJournalFrameLink || r.calls != 0 {
		t.Fatalf("sequence wrapped: %#v %v", got, err)
	}
	if got, err := encodeJournalFrame(journalBlocked, b, []byte{'x'}); got != nil || err != errJournalFrameLink {
		t.Fatalf("encoded wrapped sequence: %x %v", got, err)
	}
}
