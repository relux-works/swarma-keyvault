package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	journalHeaderBytes  = 88
	journalTrailerBytes = sha256.Size
	journalFrameMagic   = "SWGRJNL1"
	journalFrameVersion = 1
)

type journalFrameKind uint8

const (
	journalActivation journalFrameKind = 1 + iota
	journalReservation
	journalDispatchIntent
	journalOutcome
	journalRevocation
	journalBlocked
	journalSnapshotMark
	journalSignerRevocation
)

var (
	errJournalFrameFormat     = errors.New("invalid journal frame")
	errJournalFrameLimit      = errors.New("journal frame limit exceeded")
	errJournalFrameLink       = errors.New("journal frame link mismatch")
	errJournalFrameChecksum   = errors.New("journal frame checksum mismatch")
	errJournalFrameIncomplete = errors.New("incomplete journal frame")
	errJournalFrameRead       = errors.New("journal frame read unavailable")
)

type journalFrameLink struct {
	sequence uint64
	previous [sha256.Size]byte
	epoch    [sha256.Size]byte
}

type journalFrame struct {
	kind   journalFrameKind
	link   journalFrameLink
	body   []byte
	digest [sha256.Size]byte
}

// These provisional internal allocation limits cover the proposed record layouts.
// They do not establish compatibility with an actual receiver or provider port.
func journalBodyLimit(kind journalFrameKind) int {
	switch kind {
	case journalActivation:
		return 108739
	case journalReservation:
		return 276784
	case journalDispatchIntent:
		return 1259
	case journalOutcome:
		return 270425
	case journalRevocation:
		return 18476
	case journalBlocked:
		return 71
	case journalSnapshotMark:
		return 300
	case journalSignerRevocation:
		return 18800
	default:
		return 0
	}
}

func validJournalLink(link journalFrameLink) bool {
	zero := [sha256.Size]byte{}
	return link.sequence != 0 && ((link.sequence == 1) == (link.previous == zero))
}

// encodeJournalFrame copies an opaque body into a bounded physical frame.
// It performs no typed-body, lifecycle, custody, epoch-authentication or durability check.
func encodeJournalFrame(kind journalFrameKind, link journalFrameLink, body []byte) ([]byte, error) {
	limit := journalBodyLimit(kind)
	if limit == 0 {
		return nil, errJournalFrameFormat
	}
	if !validJournalLink(link) {
		return nil, errJournalFrameLink
	}
	if len(body) == 0 || len(body) > limit {
		return nil, errJournalFrameLimit
	}
	total := journalHeaderBytes + len(body) + journalTrailerBytes
	frame := make([]byte, total)
	copy(frame[:8], journalFrameMagic)
	binary.BigEndian.PutUint16(frame[8:10], journalFrameVersion)
	frame[10] = byte(kind)
	// Flags at11 remain zero; every other value is refused by the reader.
	binary.BigEndian.PutUint32(frame[12:16], uint32(total))
	binary.BigEndian.PutUint64(frame[16:24], link.sequence)
	copy(frame[24:56], link.previous[:])
	copy(frame[56:88], link.epoch[:])
	copy(frame[journalHeaderBytes:], body)
	sum := sha256.Sum256(frame[:total-journalTrailerBytes])
	copy(frame[total-journalTrailerBytes:], sum[:])
	return frame, nil
}

// readJournalFrame reads one physical frame against explicit expected links.
// EOF means a frame boundary; incomplete input is distinct from malformed input.
// A checksum and caller-supplied epoch comparison are not authentication or permission
// to truncate a tail. Reader cancellation/time bounds belong to its actual caller.
func readJournalFrame(reader io.Reader, want journalFrameLink) (*journalFrame, error) {
	if !validJournalLink(want) {
		return nil, errJournalFrameLink
	}
	var header [journalHeaderBytes]byte
	n, err := io.ReadFull(reader, header[:])
	if err != nil {
		if n == 0 && err == io.EOF {
			return nil, io.EOF
		}
		return nil, journalReadError(err)
	}
	if string(header[:8]) != journalFrameMagic ||
		binary.BigEndian.Uint16(header[8:10]) != journalFrameVersion || header[11] != 0 {
		return nil, errJournalFrameFormat
	}
	kind := journalFrameKind(header[10])
	limit := journalBodyLimit(kind)
	if limit == 0 {
		return nil, errJournalFrameFormat
	}
	total := binary.BigEndian.Uint32(header[12:16])
	if total <= journalHeaderBytes+journalTrailerBytes ||
		total > uint32(journalHeaderBytes+journalTrailerBytes+limit) {
		return nil, errJournalFrameLimit
	}
	link := journalFrameLink{sequence: binary.BigEndian.Uint64(header[16:24])}
	copy(link.previous[:], header[24:56])
	copy(link.epoch[:], header[56:88])
	if !validJournalLink(link) || link != want {
		return nil, errJournalFrameLink
	}
	// Allocation follows every length, version, kind, flag and link check above.
	rest := make([]byte, int(total)-journalHeaderBytes)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return nil, journalReadError(err)
	}
	body := rest[:len(rest)-journalTrailerBytes]
	hash := sha256.New()
	_, _ = hash.Write(header[:])
	_, _ = hash.Write(body)
	sum := hash.Sum(nil)
	if !bytes.Equal(sum, rest[len(body):]) {
		return nil, errJournalFrameChecksum
	}
	frame := &journalFrame{kind: kind, link: link, body: body}
	copy(frame.digest[:], sum)
	return frame, nil
}

func journalReadError(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return errJournalFrameIncomplete
	}
	// Do not echo an arbitrary reader's diagnostic or input bytes.
	return errJournalFrameRead
}
