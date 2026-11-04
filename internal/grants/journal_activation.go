package grants

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const journalCertificateEnvelopeMax = 98304

var (
	errJournalActivationFormat = errors.New("invalid journal activation body")
	errJournalActivationLimit  = errors.New("journal activation body limit exceeded")
	errJournalActivationRef    = errors.New("journal activation reference mismatch")
)

type journalHistoryRef struct {
	sequence uint64
	slot     uint16
}

type journalActivationBody struct {
	observedAt   string
	audit        uint64
	envelope     []byte
	predecessors []journalHistoryRef
	heldUses     []journalHistoryRef
}

func journalEarlierInsertion(ref journalHistoryRef, sequence uint64) bool {
	// Candidate certificate/use insertions both occupy slot0, in different kinds.
	// This does not resolve a reference or establish its actual insertion kind.
	return ref.sequence != 0 && ref.sequence < sequence && ref.slot == 0
}

func validateJournalActivation(body *journalActivationBody, sequence, wantAudit uint64) error {
	if body == nil {
		return errJournalActivationFormat
	}
	if sequence == 0 || wantAudit == 0 || body.audit != wantAudit {
		return errJournalActivationRef
	}
	if len(body.envelope) == 0 || len(body.envelope) > journalCertificateEnvelopeMax ||
		len(body.predecessors) > 16 || len(body.heldUses) > 1024 {
		return errJournalActivationLimit
	}
	if _, err := parseWireTime(body.observedAt); err != nil {
		return errJournalActivationFormat
	}
	envelope, err := parseEnvelopeProjection(body.envelope, certificateEnvelopeWire)
	if err != nil {
		return errJournalActivationFormat
	}
	certificate, err := parseCertificateProjection(envelope.payload)
	if err != nil {
		return errJournalActivationFormat
	}
	if len(certificate.supersedes) != len(body.predecessors) ||
		(len(body.predecessors) == 0 && len(body.heldUses) != 0) {
		return errJournalActivationRef
	}
	seen := make(map[journalHistoryRef]bool, len(body.predecessors))
	for _, ref := range body.predecessors {
		if !journalEarlierInsertion(ref, sequence) || seen[ref] {
			return errJournalActivationRef
		}
		seen[ref] = true
	}
	for i, ref := range body.heldUses {
		if !journalEarlierInsertion(ref, sequence) {
			return errJournalActivationRef
		}
		if i > 0 && (ref.sequence < body.heldUses[i-1].sequence ||
			(ref.sequence == body.heldUses[i-1].sequence && ref.slot <= body.heldUses[i-1].slot)) {
			return errJournalActivationRef
		}
	}
	return nil
}

func appendJournalHistoryRefs(out []byte, refs []journalHistoryRef) []byte {
	for _, ref := range refs {
		out = binary.BigEndian.AppendUint64(out, ref.sequence)
		out = binary.BigEndian.AppendUint16(out, ref.slot)
	}
	return out
}

// encodeJournalActivationBody validates representation and copies exact envelope
// bytes. It verifies no signature, current authority, clock, history or complete
// RESERVED set. Expected audit/sequence arguments are references, not admission.
func encodeJournalActivationBody(body *journalActivationBody, sequence, wantAudit uint64) ([]byte, error) {
	if err := validateJournalActivation(body, sequence, wantAudit); err != nil {
		return nil, err
	}
	// All lengths were bounded before this arithmetic or allocation.
	size := 35 + len(body.envelope) + 10*len(body.predecessors) + 10*len(body.heldUses)
	out := make([]byte, 0, size)
	out = append(out, body.observedAt...)
	out = binary.BigEndian.AppendUint64(out, body.audit)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body.envelope)))
	out = append(out, body.envelope...)
	out = append(out, byte(len(body.predecessors)))
	out = appendJournalHistoryRefs(out, body.predecessors)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body.heldUses)))
	return appendJournalHistoryRefs(out, body.heldUses), nil
}

// decodeJournalActivationBody checks exact bounded layout and existing complete
// envelope/payload representation, then returns owned buffers. Predecessor order
// is retained, but its correspondence to signed IDs needs actual history. No
// state, audit counter, signature, durability or authorization is established.
func decodeJournalActivationBody(raw []byte, sequence, wantAudit uint64) (*journalActivationBody, error) {
	if sequence == 0 || wantAudit == 0 {
		return nil, errJournalActivationRef
	}
	if len(raw) < 36 || len(raw) > journalBodyLimit(journalActivation) {
		return nil, errJournalActivationLimit
	}
	e := binary.BigEndian.Uint32(raw[28:32])
	if e == 0 || e > journalCertificateEnvelopeMax || uint64(e) > uint64(len(raw)-35) {
		return nil, errJournalActivationLimit
	}
	end := 32 + int(e)
	p := int(raw[end])
	if p > 16 {
		return nil, errJournalActivationLimit
	}
	pos := end + 1
	if len(raw)-pos < 10*p+2 {
		return nil, errJournalActivationFormat
	}
	h := int(binary.BigEndian.Uint16(raw[pos+10*p : pos+10*p+2]))
	if h > 1024 {
		return nil, errJournalActivationLimit
	}
	if len(raw)-(pos+10*p+2) != 10*h {
		return nil, errJournalActivationFormat
	}
	body := &journalActivationBody{
		observedAt: string(raw[:20]), audit: binary.BigEndian.Uint64(raw[20:28]),
		envelope: raw[32:end], predecessors: make([]journalHistoryRef, p),
		heldUses: make([]journalHistoryRef, h),
	}
	for i := range body.predecessors {
		body.predecessors[i] = journalHistoryRef{binary.BigEndian.Uint64(raw[pos:]), binary.BigEndian.Uint16(raw[pos+8:])}
		pos += 10
	}
	pos += 2
	for i := range body.heldUses {
		body.heldUses[i] = journalHistoryRef{binary.BigEndian.Uint64(raw[pos:]), binary.BigEndian.Uint16(raw[pos+8:])}
		pos += 10
	}
	if err := validateJournalActivation(body, sequence, wantAudit); err != nil {
		return nil, err
	}
	body.envelope = bytes.Clone(body.envelope)
	return body, nil
}
