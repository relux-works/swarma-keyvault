// Package namecoinprocess prepares public inputs for the finite Namecoin
// process contract. Public preparation supplies no custody or consent evidence.
package namecoinprocess

import (
	"bytes"
	"encoding/binary"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const MaxEnvelopeBlobBytes = 16384

const envelopeFixedBytes = 6 + 4 + 65 + 181 + 32

// OpaqueEnvelope contains only the existing sealed representation. The codec
// checks byte framing, not point validity, binding authenticity or provenance.
// Only the qualified native vault may source the actual fd7 payload.
type OpaqueEnvelope struct {
	Blob          []byte
	WrappingPoint [65]byte
	Ciphertext    [181]byte
	Binding       [32]byte
}

func EncodeEnvelope(e OpaqueEnvelope) ([]byte, error) {
	if len(e.Blob) < 1 || len(e.Blob) > MaxEnvelopeBlobBytes {
		return nil, namecoinwire.ErrInvalidRequest
	}
	raw := make([]byte, 0, envelopeFixedBytes+len(e.Blob))
	raw = append(raw, "KVNE1\x00"...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(e.Blob)))
	raw = append(raw, e.Blob...)
	raw = append(raw, e.WrappingPoint[:]...)
	raw = append(raw, e.Ciphertext[:]...)
	return append(raw, e.Binding[:]...), nil
}

func DecodeEnvelope(raw []byte) (OpaqueEnvelope, error) {
	var e OpaqueEnvelope
	if len(raw) < envelopeFixedBytes+1 || len(raw) > envelopeFixedBytes+MaxEnvelopeBlobBytes || !bytes.Equal(raw[:6], []byte("KVNE1\x00")) {
		return e, namecoinwire.ErrInvalidRequest
	}
	n := binary.BigEndian.Uint32(raw[6:10])
	if n < 1 || n > MaxEnvelopeBlobBytes || uint64(len(raw)) != uint64(envelopeFixedBytes)+uint64(n) {
		return e, namecoinwire.ErrInvalidRequest
	}
	e.Blob = bytes.Clone(raw[10 : 10+int(n)])
	rest := raw[10+int(n):]
	copy(e.WrappingPoint[:], rest[:65])
	copy(e.Ciphertext[:], rest[65:246])
	copy(e.Binding[:], rest[246:])
	return e, nil
}
