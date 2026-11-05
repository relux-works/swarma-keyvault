package grants

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	ErrLocalState                = errors.New("required-state-unavailable")
	ErrLocalUseHeld              = errors.New("use-already-reserved")
	ErrLocalRequestCollision     = errors.New("request-id-collision")
	ErrLocalCertificateCollision = errors.New("certificate-id-collision")
	ErrLocalUnknown              = errors.New("local dispatch outcome unknown; use remains held")
)

type localHeldUse struct {
	checked  *checkedLocalCreate
	sequence uint64
	intent   bool
	receipt  *localProviderReceipt
}
type localState struct {
	file, lock, directory *os.File
	link                  journalFrameLink
	uses                  map[logicalUseKey]*localHeldUse
	requests              map[string]*localHeldUse
	certificates          map[string][]byte
	reservations          map[uint64]*localHeldUse
	write                 func(*os.File, []byte) (int, error)
	sync                  func(*os.File) error
}

func privateLocalFile(file *os.File, permission os.FileMode) bool {
	st, err := file.Stat()
	if err != nil || st.Mode().Perm() != permission {
		return false
	}
	identity, ok := st.Sys().(*syscall.Stat_t)
	return ok && identity.Uid == uint32(os.Getuid())
}

func openLocalFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrLocalState
	}
	file := os.NewFile(uintptr(fd), path)
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || !privateLocalFile(file, 0600) {
		file.Close()
		return nil, ErrLocalState
	}
	return file, nil
}

// The directory must be explicitly provisioned, owned and private. This local
// lock/epoch protects cooperating callers; it is not same-UID tamper resistance.
func openLocalState(e *LocalEnrollment) (*localState, error) {
	st, err := os.Lstat(e.stateDir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, ErrLocalState
	}
	dir, err := os.Open(e.stateDir)
	if err != nil {
		return nil, ErrLocalState
	}
	if !privateLocalFile(dir, 0700) {
		dir.Close()
		return nil, ErrLocalState
	}
	s := &localState{directory: dir, link: journalFrameLink{sequence: 1, epoch: e.epoch}, uses: map[logicalUseKey]*localHeldUse{}, requests: map[string]*localHeldUse{}, certificates: map[string][]byte{}, reservations: map[uint64]*localHeldUse{}, write: func(f *os.File, p []byte) (int, error) { return f.Write(p) }, sync: func(f *os.File) error { return f.Sync() }}
	ready := false
	defer func() {
		if !ready {
			s.close()
		}
	}()
	s.lock, err = openLocalFile(filepath.Join(e.stateDir, "local.lock"))
	if err != nil {
		return nil, err
	}
	if err = lockStateFile(context.Background(), s.lock); err != nil {
		return nil, ErrLocalState
	}
	s.file, err = openLocalFile(filepath.Join(e.stateDir, "local.journal"))
	if err != nil {
		return nil, err
	}
	if err = s.file.Sync(); err != nil {
		return nil, ErrLocalState
	}
	if err = dir.Sync(); err != nil {
		return nil, ErrLocalState
	}
	info, err := s.file.Stat()
	if err != nil || info.Size() > journalScanMaxBytes {
		return nil, ErrLocalState
	}
	for {
		var frame *journalFrame
		frame, err = readJournalFrame(s.file, s.link)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return nil, ErrLocalState
		}
		if err = s.replay(e, frame); err != nil {
			return nil, ErrLocalState
		}
		s.link.sequence++
		s.link.previous = frame.digest
	}
	ready = true
	return s, nil
}

func (s *localState) close() {
	if s.file != nil {
		s.file.Close()
	}
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
	}
	if s.directory != nil {
		s.directory.Close()
	}
}

func encodeLocalReservation(c *checkedLocalCreate) []byte {
	body := []byte("LCR1")
	body = append(body, []byte(c.observedAt.Format("2006-01-02T15:04:05Z"))...)
	body = append(body, c.correlation[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(c.certificate)))
	body = append(body, c.certificate...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(c.attestation)))
	return append(body, c.attestation...)
}

func decodeLocalReservation(e *LocalEnrollment, raw []byte) (*checkedLocalCreate, error) {
	if len(raw) < 64 || string(raw[:4]) != "LCR1" {
		return nil, ErrLocalState
	}
	at, err := parseWireTime(string(raw[4:24]))
	if err != nil {
		return nil, ErrLocalState
	}
	position := 56
	read := func(limit int) ([]byte, error) {
		if len(raw)-position < 4 {
			return nil, ErrLocalState
		}
		n := binary.BigEndian.Uint32(raw[position:])
		position += 4
		if n == 0 || n > uint32(limit) || n > uint32(len(raw)-position) {
			return nil, ErrLocalState
		}
		value := raw[position : position+int(n)]
		position += int(n)
		return value, nil
	}
	certificate, err := read(98304)
	if err != nil {
		return nil, err
	}
	request, err := read(12288)
	if err != nil || position != len(raw) {
		return nil, ErrLocalState
	}
	checked, err := e.check(certificate, request, at)
	if err != nil || !bytes.Equal(checked.correlation[:], raw[24:56]) {
		return nil, ErrLocalState
	}
	return checked, nil
}

func (s *localState) replay(e *LocalEnrollment, f *journalFrame) error {
	switch f.kind {
	case journalReservation:
		if len(s.uses) >= 256 {
			return ErrLocalState
		}
		c, err := decodeLocalReservation(e, f.body)
		if err != nil {
			return err
		}
		if s.uses[c.request.logicalUseKey()] != nil || s.requests[c.request.requestID] != nil {
			return ErrLocalState
		}
		if prior, ok := s.certificates[c.certificateID]; ok && !bytes.Equal(prior, c.certificate) {
			return ErrLocalState
		}
		held := &localHeldUse{checked: c, sequence: f.link.sequence}
		s.uses[c.request.logicalUseKey()] = held
		s.requests[c.request.requestID] = held
		s.certificates[c.certificateID] = c.certificate
		s.reservations[f.link.sequence] = held
	case journalDispatchIntent:
		if len(f.body) != 12 || string(f.body[:4]) != "LCI1" {
			return ErrLocalState
		}
		held := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if held == nil || held.intent || held.receipt != nil {
			return ErrLocalState
		}
		held.intent = true
	case journalOutcome:
		if len(f.body) < 16 || string(f.body[:4]) != "LCO1" {
			return ErrLocalState
		}
		held := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if held == nil || !held.intent || held.receipt != nil {
			return ErrLocalState
		}
		n := binary.BigEndian.Uint32(f.body[12:])
		if n > localReceiptLimit || int(n) != len(f.body)-16 {
			return ErrLocalState
		}
		receipt, err := parseLocalProviderReceipt(f.body[16:])
		if err != nil {
			return err
		}
		held.receipt = receipt
	default:
		return ErrLocalState
	}
	return nil
}

func (s *localState) append(kind journalFrameKind, body []byte) error {
	raw, err := encodeJournalFrame(kind, s.link, body)
	if err != nil {
		return ErrLocalState
	}
	info, err := s.file.Stat()
	if err != nil || info.Size()+int64(len(raw)) > journalScanMaxBytes {
		return ErrLocalState
	}
	if n, err := s.write(s.file, raw); err != nil || n != len(raw) {
		return ErrLocalState
	}
	if err := s.sync(s.file); err != nil {
		return ErrLocalState
	}
	parsed, err := readJournalFrame(bytes.NewReader(raw), s.link)
	if err != nil {
		return ErrLocalState
	}
	s.link.previous = parsed.digest
	s.link.sequence++
	return nil
}

// Keep historical observed times in the host-clock domain, never a protected
// timestamp or rollback witness. Invalid wire years cannot enter the journal.
func localObservedTime(t time.Time) (time.Time, error) {
	t = t.UTC().Truncate(time.Second)
	if t.Year() < 1 || t.Year() > 9999 {
		return time.Time{}, ErrLocalState
	}
	return t, nil
}
