package namecoinprocess

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func process2MetadataFixture(service, account string, sidecar, record []byte) Process2Metadata {
	var pin [32]byte
	for i := range pin {
		pin[i] = byte(i + 1)
	}
	return Process2Metadata{Service: service, PhysicalAccount: account, AccountPinSHA256: pin, Sidecar: sidecar, Record: record}
}

func process2FrameFixture(blobLength int) Process2CustodyFrame {
	frame := Process2CustodyFrame{
		Metadata: process2MetadataFixture("fixture/service", "fixture/physical-account", []byte("KVNS1 synthetic sidecar"), []byte(`{"schema":"fixture-record/1"}`)),
		Envelope: OpaqueEnvelope{Blob: bytes.Repeat([]byte{0x36}, blobLength)},
	}
	for i := range frame.Envelope.WrappingPoint {
		frame.Envelope.WrappingPoint[i] = byte(i)
	}
	for i := range frame.Envelope.Ciphertext {
		frame.Envelope.Ciphertext[i] = byte(255 - i)
	}
	for i := range frame.Envelope.Binding {
		frame.Envelope.Binding[i] = byte(i ^ 0xa5)
	}
	return frame
}

// The process/2 codecs preserve every bounded byte and return owned fields;
// this does not claim that fixture metadata is semantically valid custody.
func TestProcess2FrameCanonicalRoundTripAndOwnership(t *testing.T) {
	for _, n := range []int{1, MaxEnvelopeBlobBytes} {
		input := process2FrameFixture(n)
		raw, err := EncodeProcess2CustodyFrame(input)
		if err != nil {
			t.Fatalf("blob %d encode: %v", n, err)
		}
		if string(raw[:6]) != "KVCY1\x00" {
			t.Fatalf("blob %d outer header: %x", n, raw[:14])
		}
		metadataLength := binary.BigEndian.Uint32(raw[6:10])
		envelopeLength := binary.BigEndian.Uint32(raw[10:14])
		if int(metadataLength)+int(envelopeLength)+14 != len(raw) || envelopeLength != uint32(envelopeFixedBytes+n) {
			t.Fatalf("blob %d lengths: metadata=%d envelope=%d total=%d", n, metadataLength, envelopeLength, len(raw))
		}
		metadata := raw[14 : 14+int(metadataLength)]
		wantPrefix := append([]byte("KVMD1\x00"), 0, byte(len(input.Metadata.Service)))
		wantPrefix = append(wantPrefix, input.Metadata.Service...)
		wantPrefix = append(wantPrefix, 0, byte(len(input.Metadata.PhysicalAccount)))
		wantPrefix = append(wantPrefix, input.Metadata.PhysicalAccount...)
		wantPrefix = append(wantPrefix, input.Metadata.AccountPinSHA256[:]...)
		if !bytes.HasPrefix(metadata, wantPrefix) || !bytes.Equal(raw[14+int(metadataLength):14+int(metadataLength)+6], []byte("KVNE1\x00")) {
			t.Fatalf("blob %d field order/magic differs", n)
		}
		got, err := DecodeProcess2CustodyFrame(raw)
		if err != nil || got.Metadata.Service != input.Metadata.Service || got.Metadata.PhysicalAccount != input.Metadata.PhysicalAccount ||
			got.Metadata.AccountPinSHA256 != input.Metadata.AccountPinSHA256 || !bytes.Equal(got.Metadata.Sidecar, input.Metadata.Sidecar) ||
			!bytes.Equal(got.Metadata.Record, input.Metadata.Record) || !bytes.Equal(got.Envelope.Blob, input.Envelope.Blob) ||
			got.Envelope.WrappingPoint != input.Envelope.WrappingPoint || got.Envelope.Ciphertext != input.Envelope.Ciphertext || got.Envelope.Binding != input.Envelope.Binding {
			t.Fatalf("blob %d round trip: %v", n, err)
		}
		raw[14+int(metadataLength)+10] ^= 0xff
		input.Metadata.Sidecar[0] ^= 0xff
		input.Metadata.Record[0] ^= 0xff
		input.Envelope.Blob[0] ^= 0xff
		if got.Metadata.Sidecar[0] != 'K' || got.Metadata.Record[0] != '{' || got.Envelope.Blob[0] != 0x36 {
			t.Fatalf("blob %d decoder borrowed caller storage", n)
		}
	}
}

// Malformed lengths, padding and truncated prefixes fail closed while the
// adjacent canonical fixture remains accepted by the positive test above.
func TestProcess2FrameRefusesMalformedWire(t *testing.T) {
	good, err := EncodeProcess2CustodyFrame(process2FrameFixture(1))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(good); i++ {
		if _, err := DecodeProcess2CustodyFrame(good[:i]); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
	bad := [][]byte{append(bytes.Clone(good), 0), bytes.Clone(good), bytes.Clone(good), bytes.Clone(good), bytes.Clone(good), bytes.Clone(good)}
	bad[1][0] ^= 1
	bad[2][5] = 1
	binary.BigEndian.PutUint32(bad[3][6:10], ^uint32(0))
	binary.BigEndian.PutUint32(bad[4][10:14], Process2MinEnvelopeBytes-1)
	binary.BigEndian.PutUint32(bad[5][10:14], Process2MaxEnvelopeBytes+1)
	for i, value := range bad {
		if _, err := DecodeProcess2CustodyFrame(value); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	meta := process2MetadataFixture("s", "a", []byte{1}, []byte{2})
	encoded, err := EncodeProcess2Metadata(meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(v []byte) { binary.BigEndian.PutUint16(v[6:8], 0) },
		func(v []byte) { binary.BigEndian.PutUint16(v[6:8], Process2MaxServiceBytes+1) },
		func(v []byte) { binary.BigEndian.PutUint32(v[len(v)-5:len(v)-1], 0) },
	} {
		v := bytes.Clone(encoded)
		mutate(v)
		if _, err := DecodeProcess2Metadata(v); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("metadata mutation accepted: %v", err)
		}
	}
	if _, err := DecodeProcess2Metadata(append(bytes.Clone(encoded), 0)); err != namecoinwire.ErrInvalidRequest {
		t.Fatalf("metadata trailing byte: %v", err)
	}
	for _, n := range []int{0, MaxEnvelopeBlobBytes + 1} {
		if _, err := EncodeProcess2CustodyFrame(process2FrameFixture(n)); err != namecoinwire.ErrInvalidRequest {
			t.Fatalf("encode blob %d: %v", n, err)
		}
	}
}
