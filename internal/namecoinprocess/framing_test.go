package namecoinprocess

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Neutral framing bytes round trip at both LP limits and do not alias either
// caller buffer. These are opaque bytes, not a valid native custody envelope.
func TestEnvelopeOwnedRoundTrip(t *testing.T) {
	for _, n := range []int{1, MaxEnvelopeBlobBytes} {
		e := OpaqueEnvelope{Blob: bytes.Repeat([]byte{0x37}, n)}
		for i := range e.WrappingPoint {
			e.WrappingPoint[i] = byte(i)
		}
		for i := range e.Ciphertext {
			e.Ciphertext[i] = byte(i + 9)
		}
		for i := range e.Binding {
			e.Binding[i] = byte(i + 19)
		}
		raw, err := EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte("KVNE1\x00"), 0, 0, byte(n>>8), byte(n))
		want = append(want, e.Blob...)
		want = append(want, e.WrappingPoint[:]...)
		want = append(want, e.Ciphertext[:]...)
		want = append(want, e.Binding[:]...)
		if !bytes.Equal(raw, want) {
			t.Fatal("different framing")
		}
		got, err := DecodeEnvelope(raw)
		if err != nil || !bytes.Equal(got.Blob, e.Blob) || got.WrappingPoint != e.WrappingPoint || got.Ciphertext != e.Ciphertext || got.Binding != e.Binding {
			t.Fatal("round trip", err)
		}
		e.Blob[0] ^= 1
		raw[10] ^= 2
		if got.Blob[0] != 0x37 || want[10] != 0x37 {
			t.Fatal("borrowed blob")
		}
	}
}

// Every truncated prefix, surplus byte, wrong magic and invalid LP refuses at
// the byte boundary; no cryptographic or native validation is claimed.
func TestEnvelopeRefusesMalformedFraming(t *testing.T) {
	raw, _ := EncodeEnvelope(OpaqueEnvelope{Blob: []byte{1, 2}})
	for i := 0; i < len(raw); i++ {
		if _, err := DecodeEnvelope(raw[:i]); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
	bad := [][]byte{append(bytes.Clone(raw), 0), bytes.Clone(raw), bytes.Clone(raw), bytes.Clone(raw), bytes.Clone(raw)}
	bad[1][0] ^= 1
	bad[2][5] = 1
	binary.BigEndian.PutUint32(bad[3][6:10], 0)
	binary.BigEndian.PutUint32(bad[4][6:10], MaxEnvelopeBlobBytes+1)
	for i, b := range bad {
		if _, err := DecodeEnvelope(b); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	for _, n := range []int{0, MaxEnvelopeBlobBytes + 1} {
		if _, err := EncodeEnvelope(OpaqueEnvelope{Blob: make([]byte, n)}); err != namecoinwire.ErrInvalidRequest {
			t.Fatal("encode size", n, err)
		}
	}
}
