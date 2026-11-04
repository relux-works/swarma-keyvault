package grants

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
)

// The existing canonical payload and minimal DER fixture prove representation
// only, never a mathematical signature or a reachable protected-history state.
func journalActivationFixture(t *testing.T, p, h int) *journalActivationBody {
	t.Helper()
	certificate := certificateTestObject(t)
	ids := make([]any, p)
	body := &journalActivationBody{observedAt: "2026-11-02T00:00:00Z", audit: 7}
	for i := range ids {
		ids[i] = fmt.Sprintf("prior-%02d", i)
		body.predecessors = append(body.predecessors, journalHistoryRef{uint64(i + 1), 0})
	}
	certificate["supersedes"] = ids
	body.envelope = envelopeTestBytes(certificateTestBytes(t, certificate), envelopeTestDER, "grants-signed-certificate-1")
	for i := 0; i < h; i++ {
		body.heldUses = append(body.heldUses, journalHistoryRef{uint64(i + 100), 0})
	}
	return body
}

// Independent field-by-field assembly follows the stated byte grammar, without
// using the production encoder or validator. It can also construct invalid cases.
func journalActivationTestWire(t *testing.T, body *journalActivationBody) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString(body.observedAt)
	for _, v := range []any{body.audit, uint32(len(body.envelope))} {
		if err := binary.Write(&out, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	out.Write(body.envelope)
	out.WriteByte(byte(len(body.predecessors)))
	for _, ref := range body.predecessors {
		_ = binary.Write(&out, binary.BigEndian, ref.sequence)
		_ = binary.Write(&out, binary.BigEndian, ref.slot)
	}
	_ = binary.Write(&out, binary.BigEndian, uint16(len(body.heldUses)))
	for _, ref := range body.heldUses {
		_ = binary.Write(&out, binary.BigEndian, ref.sequence)
		_ = binary.Write(&out, binary.BigEndian, ref.slot)
	}
	return out.Bytes()
}

func journalActivationEqual(a, b *journalActivationBody) bool {
	return a != nil && b != nil && a.observedAt == b.observedAt && a.audit == b.audit &&
		bytes.Equal(a.envelope, b.envelope) && slicesEqualJournalRefs(a.predecessors, b.predecessors) &&
		slicesEqualJournalRefs(a.heldUses, b.heldUses)
}

func slicesEqualJournalRefs(a, b []journalHistoryRef) bool {
	return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b))
}

// First issue and replacement match independently assembled exact body bytes;
// predecessor order and envelope bytes survive unchanged, without ID resolution.
func TestJournalActivationExactBytes(t *testing.T) {
	for _, counts := range [][2]int{{0, 0}, {2, 2}} {
		body := journalActivationFixture(t, counts[0], counts[1])
		if len(body.predecessors) == 2 {
			body.predecessors[0], body.predecessors[1] = body.predecessors[1], body.predecessors[0]
		}
		want := journalActivationTestWire(t, body)
		wire, err := encodeJournalActivationBody(body, 2000, 7)
		if err != nil || !bytes.Equal(wire, want) || len(wire) != 35+len(body.envelope)+10*(counts[0]+counts[1]) {
			t.Fatalf("exact encoding: len%d err%v", len(wire), err)
		}
		got, err := decodeJournalActivationBody(want, 2000, 7)
		if err != nil || !journalActivationEqual(got, body) {
			t.Fatalf("exact decoding: %#v %v", got, err)
		}
	}
}

// One physical insertion cannot be both a certificate predecessor and a held
// use. Both codec directions reject every tested overlap without partial output
// or input changes; disjoint refs retain their existing ordering and bytes.
// These are representation checks, not evidence of actual history or authority.
func TestJournalActivationDisjointRefs(t *testing.T) {
	for _, counts := range [][2]int{{0, 0}, {1, 0}, {3, 3}} {
		t.Run(fmt.Sprintf("valid-%d-%d", counts[0], counts[1]), func(t *testing.T) {
			body := journalActivationFixture(t, counts[0], counts[1])
			if counts[0] == 3 {
				body.predecessors = []journalHistoryRef{{10, 0}, {30, 0}, {20, 0}}
				body.heldUses = []journalHistoryRef{{1, 0}, {11, 0}, {31, 0}}
			}
			want := journalActivationTestWire(t, body)
			wire, err := encodeJournalActivationBody(body, 2000, 7)
			if err != nil || !bytes.Equal(wire, want) {
				t.Fatalf("valid disjoint encoding: %v", err)
			}
			got, err := decodeJournalActivationBody(want, 2000, 7)
			if err != nil || !journalActivationEqual(got, body) {
				t.Fatalf("valid disjoint decoding: %#v %v", got, err)
			}
		})
	}
	for p := 0; p < 3; p++ {
		for h := 0; h < 3; h++ {
			t.Run(fmt.Sprintf("overlap-predecessor%d-hold%d", p, h), func(t *testing.T) {
				body := journalActivationFixture(t, 3, 3)
				body.predecessors[p] = body.heldUses[h]
				raw := journalActivationTestWire(t, body)
				t.Run("encode", func(t *testing.T) {
					got, err := encodeJournalActivationBody(body, 2000, 7)
					if got != nil || err != errJournalActivationRef {
						t.Fatalf("overlapping insertion encoding: len%d err%v", len(got), err)
					}
					if !bytes.Equal(journalActivationTestWire(t, body), raw) {
						t.Fatal("refusal changed input body")
					}
				})
				t.Run("decode", func(t *testing.T) {
					before := bytes.Clone(raw)
					got, err := decodeJournalActivationBody(raw, 2000, 7)
					if got != nil || err != errJournalActivationRef {
						t.Fatalf("overlapping insertion decoding: %#v err%v", got, err)
					}
					if !bytes.Equal(raw, before) {
						t.Fatal("refusal changed input bytes")
					}
				})
			})
		}
	}
}

// Maximum reference counts use an actually complete canonical payload and past
// numeric refs. This is not a reachable-history, maximum-envelope or authority proof.
func TestJournalActivationMaximumCounts(t *testing.T) {
	body := journalActivationFixture(t, 16, 1024)
	wire, err := encodeJournalActivationBody(body, 2000, 7)
	if err != nil || len(wire) != 35+len(body.envelope)+160+10240 || len(wire) > 108739 {
		t.Fatalf("maximum counts: len%d %v", len(wire), err)
	}
	got, err := decodeJournalActivationBody(wire, 2000, 7)
	if err != nil || !journalActivationEqual(got, body) {
		t.Fatalf("maximum counts decode: %v", err)
	}
}

// Each representation/reference refusal has a nearby valid control and returns
// nil from BOTH encoder and decoder, rather than a partial record or byte prefix.
func TestJournalActivationRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*journalActivationBody)
		want error
	}{
		{"time-alias", func(b *journalActivationBody) { b.observedAt = "2026-11-02 00:00:00Z" }, errJournalActivationFormat},
		{"invalid-date", func(b *journalActivationBody) { b.observedAt = "2026-02-30T00:00:00Z" }, errJournalActivationFormat},
		{"audit-zero", func(b *journalActivationBody) { b.audit = 0 }, errJournalActivationRef},
		{"audit-mismatch", func(b *journalActivationBody) { b.audit = 8 }, errJournalActivationRef},
		{"empty-envelope", func(b *journalActivationBody) { b.envelope = nil }, errJournalActivationLimit},
		{"oversized-envelope", func(b *journalActivationBody) { b.envelope = make([]byte, 98305) }, errJournalActivationLimit},
		{"noncanonical-envelope", func(b *journalActivationBody) { b.envelope = append(b.envelope, '\n') }, errJournalActivationFormat},
		{"unsigned-envelope", func(b *journalActivationBody) {
			var object map[string]any
			if err := json.Unmarshal(b.envelope, &object); err != nil {
				t.Fatal(err)
			}
			delete(object, "signature")
			b.envelope = certificateTestBytes(t, object)
		}, errJournalActivationFormat},
		{"incomplete-payload", func(b *journalActivationBody) {
			b.envelope = envelopeTestBytes([]byte(`{"type":"grants-certificate-1"}`), envelopeTestDER, "grants-signed-certificate-1")
		}, errJournalActivationFormat},
		{"predecessor-count", func(b *journalActivationBody) { b.predecessors = b.predecessors[:1] }, errJournalActivationRef},
		{"duplicate-predecessor", func(b *journalActivationBody) { b.predecessors[1] = b.predecessors[0] }, errJournalActivationRef},
		{"zero-ref", func(b *journalActivationBody) { b.predecessors[0].sequence = 0 }, errJournalActivationRef},
		{"self-ref", func(b *journalActivationBody) { b.predecessors[0].sequence = 2000 }, errJournalActivationRef},
		{"forward-ref", func(b *journalActivationBody) { b.predecessors[0].sequence = 2001 }, errJournalActivationRef},
		{"certificate-slot", func(b *journalActivationBody) { b.predecessors[0].slot = 1 }, errJournalActivationRef},
		{"use-slot", func(b *journalActivationBody) { b.heldUses[0].slot = 1 }, errJournalActivationRef},
		{"use-self-ref", func(b *journalActivationBody) { b.heldUses[0].sequence = 2000 }, errJournalActivationRef},
		{"duplicate-hold", func(b *journalActivationBody) { b.heldUses[1] = b.heldUses[0] }, errJournalActivationRef},
		{"unordered-holds", func(b *journalActivationBody) { b.heldUses[0], b.heldUses[1] = b.heldUses[1], b.heldUses[0] }, errJournalActivationRef},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := journalActivationFixture(t, 2, 2)
			if _, err := encodeJournalActivationBody(body, 2000, 7); err != nil {
				t.Fatal("valid neighbor", err)
			}
			c.edit(body)
			if got, err := encodeJournalActivationBody(body, 2000, 7); got != nil || !errors.Is(err, c.want) {
				t.Fatalf("encoder refusal: %v want%v", err, c.want)
			}
			if got, err := decodeJournalActivationBody(journalActivationTestWire(t, body), 2000, 7); got != nil || !errors.Is(err, c.want) {
				t.Fatalf("decoder refusal: %#v %v want%v", got, err, c.want)
			}
		})
	}
}

// Count overflows, holds without predecessors, invalid context and wrapped-zero
// audit refs are refused; max-u64 refs remain representable without incrementing them.
func TestJournalActivationCountsAndContext(t *testing.T) {
	for _, counts := range [][2]int{{17, 0}, {2, 1025}, {0, 1}} {
		body := journalActivationFixture(t, counts[0], counts[1])
		want := errJournalActivationLimit
		if counts[0] == 0 {
			want = errJournalActivationRef
		}
		if got, err := encodeJournalActivationBody(body, 2000, 7); got != nil || err != want {
			t.Fatalf("counts encoder: %v", err)
		}
		if got, err := decodeJournalActivationBody(journalActivationTestWire(t, body), 2000, 7); got != nil || err != want {
			t.Fatalf("counts decoder: %#v %v", got, err)
		}
	}
	body := journalActivationFixture(t, 0, 0)
	for _, ctx := range [][2]uint64{{0, 7}, {1, 0}} {
		if got, err := encodeJournalActivationBody(body, ctx[0], ctx[1]); got != nil || err != errJournalActivationRef {
			t.Fatalf("invalid context encode: %v", err)
		}
		if got, err := decodeJournalActivationBody(journalActivationTestWire(t, body), ctx[0], ctx[1]); got != nil || err != errJournalActivationRef {
			t.Fatalf("invalid context decode: %#v %v", got, err)
		}
	}
	body.audit = math.MaxUint64
	if got, err := encodeJournalActivationBody(body, math.MaxUint64, math.MaxUint64); got == nil || err != nil {
		t.Fatalf("max refs control: %v", err)
	}
	if got, err := encodeJournalActivationBody(nil, 1, 1); got != nil || err != errJournalActivationFormat {
		t.Fatalf("nil encoder: %v", err)
	}
}

// Every proper prefix and extra byte refuses with a controlled format/limit
// sentinel and no record. Untrusted length/count fields cannot allocate by claim.
func TestJournalActivationLengthRefusals(t *testing.T) {
	body := journalActivationFixture(t, 2, 2)
	wire := journalActivationTestWire(t, body)
	for n := 0; n < len(wire); n++ {
		got, err := decodeJournalActivationBody(wire[:n], 2000, 7)
		if got != nil || (err != errJournalActivationFormat && err != errJournalActivationLimit) {
			t.Fatalf("prefix%d: %#v %v", n, got, err)
		}
	}
	for _, length := range []uint32{0, 98305, math.MaxUint32} {
		bad := bytes.Clone(wire)
		binary.BigEndian.PutUint32(bad[28:32], length)
		if got, err := decodeJournalActivationBody(bad, 2000, 7); got != nil || err != errJournalActivationLimit {
			t.Fatalf("claimed length%d: %#v %v", length, got, err)
		}
	}
	if got, err := decodeJournalActivationBody(append(bytes.Clone(wire), 0), 2000, 7); got != nil || err != errJournalActivationFormat {
		t.Fatalf("trailing byte: %#v %v", got, err)
	}
	if got, err := decodeJournalActivationBody(make([]byte, 108740), 2000, 7); got != nil || err != errJournalActivationLimit {
		t.Fatalf("oversized body: %#v %v", got, err)
	}
}

// Encoding and decoding own their byte/ref buffers; a physical activation frame
// round-trip preserves the exact body but supplies no lifecycle/state acceptance.
func TestJournalActivationOwnershipAndFrame(t *testing.T) {
	body := journalActivationFixture(t, 2, 2)
	wire, err := encodeJournalActivationBody(body, 2000, 7)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(wire)
	body.envelope[0] ^= 1
	body.predecessors[0].sequence = 42
	if !bytes.Equal(before, wire) {
		t.Fatal("encoding aliases input")
	}
	got, err := decodeJournalActivationBody(wire, 2000, 7)
	if err != nil {
		t.Fatal(err)
	}
	wire[32] ^= 1
	if !bytes.Equal(got.envelope, before[32:32+len(got.envelope)]) {
		t.Fatal("decoder aliases raw envelope")
	}
	clean := journalActivationFixture(t, 0, 0)
	clean.audit = 1
	wire, err = encodeJournalActivationBody(clean, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	frameWire, err := encodeJournalFrame(journalActivation, journalFrameLink{sequence: 1}, wire)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := readJournalFrame(bytes.NewReader(frameWire), journalFrameLink{sequence: 1})
	if err != nil || !bytes.Equal(frame.body, wire) {
		t.Fatal("physical round trip", err)
	}
	got, err = decodeJournalActivationBody(frame.body, 1, 1)
	if err != nil || !journalActivationEqual(got, clean) {
		t.Fatal("body round trip", err)
	}
}
