package namecoinprocess

import (
	"bytes"
	"encoding/binary"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const (
	Process2MinMetadataBytes        = 54
	Process2MaxMetadataBytes        = 34816
	Process2MaxServiceBytes         = 128
	Process2MaxPhysicalAccountBytes = 256
	Process2MaxSidecarBytes         = 640
	Process2MaxRecordBytes          = 32768
	Process2MinEnvelopeBytes        = envelopeFixedBytes + 1
	Process2MaxEnvelopeBytes        = envelopeFixedBytes + MaxEnvelopeBlobBytes
	Process2MaxCustodyFrameBytes    = 14 + Process2MaxMetadataBytes + Process2MaxEnvelopeBytes
)

// Process2Metadata carries only the frozen public selection and canonical
// public record bytes. Sidecar and record remain byte slices so encoding never
// normalizes or reserializes either value.
type Process2Metadata struct {
	Service          string
	PhysicalAccount  string
	AccountPinSHA256 [32]byte
	Sidecar          []byte
	Record           []byte
}

// Process2CustodyFrame is one fd5 payload. It is a codec value only; it does
// not prove pair provenance, production helper admission, or a protected call.
type Process2CustodyFrame struct {
	Metadata Process2Metadata
	Envelope OpaqueEnvelope
}

// EncodeProcess2Metadata encodes the exact KVMD1 field order and byte limits.
// Semantic record, sidecar, selection, and binding validation belongs to
// internal/keyvault before projection.
func EncodeProcess2Metadata(m Process2Metadata) ([]byte, error) {
	service := []byte(m.Service)
	account := []byte(m.PhysicalAccount)
	if len(service) < 1 || len(service) > Process2MaxServiceBytes ||
		len(account) < 1 || len(account) > Process2MaxPhysicalAccountBytes ||
		len(m.Sidecar) < 1 || len(m.Sidecar) > Process2MaxSidecarBytes ||
		len(m.Record) < 1 || len(m.Record) > Process2MaxRecordBytes {
		return nil, namecoinwire.ErrInvalidRequest
	}
	length := 6 + 2 + len(service) + 2 + len(account) + len(m.AccountPinSHA256) + 4 + len(m.Sidecar) + 4 + len(m.Record)
	if length > Process2MaxMetadataBytes {
		return nil, namecoinwire.ErrInvalidRequest
	}

	raw := make([]byte, 0, length)
	raw = append(raw, "KVMD1\x00"...)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(service)))
	raw = append(raw, service...)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(account)))
	raw = append(raw, account...)
	raw = append(raw, m.AccountPinSHA256[:]...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(m.Sidecar)))
	raw = append(raw, m.Sidecar...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(m.Record)))
	raw = append(raw, m.Record...)
	return raw, nil
}

// DecodeProcess2Metadata accepts exactly one KVMD1 value with no padding or
// trailing data. It validates lengths before converting them to int or copying.
func DecodeProcess2Metadata(raw []byte) (Process2Metadata, error) {
	var m Process2Metadata
	if len(raw) < Process2MinMetadataBytes || len(raw) > Process2MaxMetadataBytes || !bytes.Equal(raw[:6], []byte("KVMD1\x00")) {
		return m, namecoinwire.ErrInvalidRequest
	}
	d := process2Cursor{raw: raw, offset: 6}
	serviceBytes, ok := process2Field16(&d, Process2MaxServiceBytes)
	if !ok || len(serviceBytes) == 0 {
		return m, namecoinwire.ErrInvalidRequest
	}
	account, ok := d.length16(Process2MaxPhysicalAccountBytes)
	if !ok || len(account) == 0 {
		return m, namecoinwire.ErrInvalidRequest
	}
	pinHash, ok := d.take(32)
	if !ok {
		return m, namecoinwire.ErrInvalidRequest
	}
	sidecar, ok := d.length32(Process2MaxSidecarBytes)
	if !ok || len(sidecar) == 0 {
		return m, namecoinwire.ErrInvalidRequest
	}
	record, ok := d.length32(Process2MaxRecordBytes)
	if !ok || len(record) == 0 || d.offset != len(raw) {
		return m, namecoinwire.ErrInvalidRequest
	}
	copy(m.AccountPinSHA256[:], pinHash)
	m.Service = string(bytes.Clone(serviceBytes))
	m.PhysicalAccount = string(bytes.Clone(account))
	m.Sidecar = bytes.Clone(sidecar)
	m.Record = bytes.Clone(record)
	return m, nil
}

// EncodeProcess2CustodyFrame emits one KVCY1 frame containing one KVMD1
// metadata value and one existing KVNE1 envelope. EOF is a transport concern;
// this function encodes no terminator and accepts no optional extension bytes.
func EncodeProcess2CustodyFrame(frame Process2CustodyFrame) ([]byte, error) {
	metadata, err := EncodeProcess2Metadata(frame.Metadata)
	if err != nil {
		return nil, err
	}
	envelope, err := EncodeEnvelope(frame.Envelope)
	if err != nil || len(envelope) < Process2MinEnvelopeBytes || len(envelope) > Process2MaxEnvelopeBytes {
		return nil, namecoinwire.ErrInvalidRequest
	}
	length := 14 + len(metadata) + len(envelope)
	if length > Process2MaxCustodyFrameBytes {
		return nil, namecoinwire.ErrInvalidRequest
	}
	raw := make([]byte, 0, length)
	raw = append(raw, "KVCY1\x00"...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(metadata)))
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(envelope)))
	raw = append(raw, metadata...)
	raw = append(raw, envelope...)
	return raw, nil
}

// DecodeProcess2CustodyFrame checks the bounded outer lengths before slicing,
// then delegates exact KVMD1 and KVNE1 validation. Every returned byte slice is
// owned by the result and no trailing byte is tolerated.
func DecodeProcess2CustodyFrame(raw []byte) (Process2CustodyFrame, error) {
	var frame Process2CustodyFrame
	if len(raw) < 14+Process2MinMetadataBytes+Process2MinEnvelopeBytes ||
		len(raw) > Process2MaxCustodyFrameBytes || !bytes.Equal(raw[:6], []byte("KVCY1\x00")) {
		return frame, namecoinwire.ErrInvalidRequest
	}
	metadataLength := uint64(binary.BigEndian.Uint32(raw[6:10]))
	envelopeLength := uint64(binary.BigEndian.Uint32(raw[10:14]))
	if metadataLength < Process2MinMetadataBytes || metadataLength > Process2MaxMetadataBytes ||
		envelopeLength < Process2MinEnvelopeBytes || envelopeLength > Process2MaxEnvelopeBytes {
		return frame, namecoinwire.ErrInvalidRequest
	}
	want := uint64(14) + metadataLength + envelopeLength
	if want != uint64(len(raw)) {
		return frame, namecoinwire.ErrInvalidRequest
	}
	metadataEnd := 14 + int(metadataLength)
	metadata, err := DecodeProcess2Metadata(raw[14:metadataEnd])
	if err != nil {
		return frame, namecoinwire.ErrInvalidRequest
	}
	envelope, err := DecodeEnvelope(raw[metadataEnd:])
	if err != nil {
		return frame, namecoinwire.ErrInvalidRequest
	}
	frame.Metadata = metadata
	frame.Envelope = envelope
	return frame, nil
}

type process2Cursor struct {
	raw    []byte
	offset int
}

func process2Field16(cursor *process2Cursor, maximum int) ([]byte, bool) {
	return cursor.length16(maximum)
}

func (d *process2Cursor) take(n uint64) ([]byte, bool) {
	if d.offset < 0 || d.offset > len(d.raw) || n > uint64(len(d.raw)-d.offset) {
		return nil, false
	}
	start := d.offset
	d.offset += int(n)
	return d.raw[start:d.offset], true
}

func (d *process2Cursor) length16(max int) ([]byte, bool) {
	raw, ok := d.take(2)
	if !ok {
		return nil, false
	}
	n := uint64(binary.BigEndian.Uint16(raw))
	if n == 0 || n > uint64(max) {
		return nil, false
	}
	return d.take(n)
}

func (d *process2Cursor) length32(max int) ([]byte, bool) {
	raw, ok := d.take(4)
	if !ok {
		return nil, false
	}
	n := uint64(binary.BigEndian.Uint32(raw))
	if n == 0 || n > uint64(max) {
		return nil, false
	}
	return d.take(n)
}
