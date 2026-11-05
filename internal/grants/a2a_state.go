package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrA2AState                = errors.New("a2a-required-state-unavailable")
	ErrA2AUseHeld              = errors.New("a2a-grant-use-already-held")
	ErrA2ANonceHeld            = errors.New("a2a-request-nonce-already-held")
	ErrA2ACertificateCollision = errors.New("a2a-certificate-identity-collision")
	ErrA2AUnknown              = errors.New("a2a-dispatch-outcome-unknown-use-held")
)

// A2AStateConfig names an explicitly provisioned separate G2 journal. Its epoch
// is independently configured, not read from untrusted message/registry data.
// This local file/lock boundary does not resist same-UID rollback or tampering.
type A2AStateConfig struct {
	Directory string
	Epoch     [32]byte
}

type a2aReservation struct {
	use, nonce, certificateID, certificateHash, requestHash [32]byte
	sequence                                                uint64
	intent, complete                                        bool
}

type a2aState struct {
	directory, lock, file *os.File
	link                  journalFrameLink
	uses, nonces          map[[32]byte]*a2aReservation
	certificates          map[[32]byte][32]byte
	reservations          map[uint64]*a2aReservation
	write                 func(*os.File, []byte) (int, error)
	sync                  func(*os.File) error
}

func a2aPrivateFile(file *os.File, directory bool) bool {
	st, err := file.Stat()
	if err != nil {
		return false
	}
	id, ok := st.Sys().(*syscall.Stat_t)
	if !ok || id.Uid != uint32(os.Getuid()) {
		return false
	}
	if directory {
		return st.IsDir() && st.Mode().Perm() == 0700
	}
	return st.Mode().IsRegular() && st.Mode().Perm() == 0600 && id.Nlink == 1
}

func a2aOpenDirectory(config A2AStateConfig) (*os.File, error) {
	if config.Epoch == [32]byte{} || !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory {
		return nil, ErrA2AState
	}
	fd, err := unix.Open(config.Directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrA2AState
	}
	f := os.NewFile(uintptr(fd), config.Directory)
	if !a2aPrivateFile(f, true) {
		f.Close()
		return nil, ErrA2AState
	}
	return f, nil
}

func a2aOpenFile(directory *os.File, name string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(directory.Fd()), name, flags, 0600)
	if err != nil {
		return nil, ErrA2AState
	}
	f := os.NewFile(uintptr(fd), name)
	if !a2aPrivateFile(f, false) {
		f.Close()
		return nil, ErrA2AState
	}
	return f, nil
}

func a2aActivation(r *A2AReceiver) []byte {
	b := append([]byte("G2A1"), r.ownerHash[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.audience)))
	return append(b, r.audience...)
}

// InitializeA2AState is an explicit exclusive initialization in an already
// admitted empty private directory. It never adopts, repairs or replaces old
// files. A partial failure stays present and refuses execution until its
// custodian resolves it; this function does not unlink a failed attempt.
func InitializeA2AState(config A2AStateConfig, receiver *A2AReceiver) error {
	if receiver == nil {
		return ErrA2AState
	}
	dir, err := a2aOpenDirectory(config)
	if err != nil {
		return err
	}
	defer dir.Close()
	if entries, err := dir.ReadDir(1); len(entries) != 0 || err != io.EOF {
		return ErrA2AState
	}
	lock, err := a2aOpenFile(dir, "a2a.lock", true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockStateFile(context.Background(), lock); err != nil {
		return ErrA2AState
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	file, err := a2aOpenFile(dir, "a2a.journal", true)
	if err != nil {
		return err
	}
	defer file.Close()
	frame, err := encodeJournalFrame(journalActivation, journalFrameLink{sequence: 1, epoch: config.Epoch}, a2aActivation(receiver))
	if err != nil {
		return ErrA2AState
	}
	if n, err := file.Write(frame); err != nil || n != len(frame) {
		return ErrA2AState
	}
	if file.Sync() != nil || lock.Sync() != nil || dir.Sync() != nil {
		return ErrA2AState
	}
	return nil
}

func openA2AState(ctx context.Context, config A2AStateConfig, receiver *A2AReceiver) (*a2aState, error) {
	if receiver == nil {
		return nil, ErrA2AState
	}
	dir, err := a2aOpenDirectory(config)
	if err != nil {
		return nil, err
	}
	s := &a2aState{directory: dir, link: journalFrameLink{sequence: 1, epoch: config.Epoch}, uses: map[[32]byte]*a2aReservation{}, nonces: map[[32]byte]*a2aReservation{}, certificates: map[[32]byte][32]byte{}, reservations: map[uint64]*a2aReservation{}, write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }}
	ready := false
	defer func() {
		if !ready {
			s.close()
		}
	}()
	s.lock, err = a2aOpenFile(dir, "a2a.lock", false)
	if err != nil {
		return nil, err
	}
	if lockStateFile(ctx, s.lock) != nil {
		return nil, ErrA2AState
	}
	s.file, err = a2aOpenFile(dir, "a2a.journal", false)
	if err != nil {
		return nil, err
	}
	st, err := s.file.Stat()
	if err != nil || st.Size() == 0 || st.Size() > journalScanMaxBytes {
		return nil, ErrA2AState
	}
	for {
		frame, err := readJournalFrame(s.file, s.link)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrA2AState
		}
		if s.link.sequence == 1 {
			if frame.kind != journalActivation || !bytes.Equal(frame.body, a2aActivation(receiver)) {
				return nil, ErrA2AState
			}
		} else if err := s.replay(frame); err != nil {
			return nil, err
		}
		s.link.sequence++
		s.link.previous = frame.digest
	}
	ready = true
	return s, nil
}

func (s *a2aState) close() {
	if s.file != nil {
		s.file.Close()
	}
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		s.lock.Close()
	}
	if s.directory != nil {
		s.directory.Close()
	}
}

func a2aRecordKey(domain string, fields ...[]byte) [32]byte {
	b := append([]byte(domain), '\n')
	for _, field := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
		b = append(b, field...)
	}
	return sha256.Sum256(b)
}

func newA2AReservation(r *A2AReceiver, c *a2aCertificate, q *a2aRequest) *a2aReservation {
	return &a2aReservation{
		use:             a2aRecordKey("swarma-grants/a2a-use/1", r.ownerHash[:], []byte(c.id), []byte(c.entryID)),
		nonce:           a2aRecordKey("swarma-grants/a2a-nonce/1", c.subjectHash[:], []byte(q.nonce), []byte(r.audience)),
		certificateID:   a2aRecordKey("swarma-grants/a2a-certificate-id/1", r.ownerHash[:], []byte(c.id)),
		certificateHash: sha256.Sum256(c.raw), requestHash: sha256.Sum256(q.raw),
	}
}

func encodeA2AReservation(r *a2aReservation) []byte {
	b := []byte("G2R1")
	for _, h := range [][32]byte{r.use, r.nonce, r.certificateID, r.certificateHash, r.requestHash} {
		b = append(b, h[:]...)
	}
	return b
}

func (s *a2aState) replay(f *journalFrame) error {
	switch f.kind {
	case journalReservation:
		if len(f.body) != 164 || string(f.body[:4]) != "G2R1" || len(s.uses) >= 256 {
			return ErrA2AState
		}
		r := &a2aReservation{sequence: f.link.sequence}
		fields := []*[32]byte{&r.use, &r.nonce, &r.certificateID, &r.certificateHash, &r.requestHash}
		for i, p := range fields {
			copy(p[:], f.body[4+i*32:4+(i+1)*32])
			if *p == [32]byte{} {
				return ErrA2AState
			}
		}
		if s.uses[r.use] != nil || s.nonces[r.nonce] != nil {
			return ErrA2AState
		}
		if old, ok := s.certificates[r.certificateID]; ok && old != r.certificateHash {
			return ErrA2AState
		}
		s.uses[r.use] = r
		s.nonces[r.nonce] = r
		s.certificates[r.certificateID] = r.certificateHash
		s.reservations[r.sequence] = r
	case journalDispatchIntent:
		if len(f.body) != 12 || string(f.body[:4]) != "G2I1" {
			return ErrA2AState
		}
		r := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if r == nil || r.intent || r.complete {
			return ErrA2AState
		}
		r.intent = true
	case journalOutcome:
		if len(f.body) < 16 || string(f.body[:4]) != "G2O1" {
			return ErrA2AState
		}
		r := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if r == nil || !r.intent || r.complete || binary.BigEndian.Uint32(f.body[12:16]) != uint32(len(f.body)-16) {
			return ErrA2AState
		}
		if _, err := parseRepositoryProviderReceipt(f.body[16:], A2ARepository); err != nil {
			return ErrA2AState
		}
		r.complete = true
	default:
		return ErrA2AState
	}
	return nil
}

func (s *a2aState) append(kind journalFrameKind, body []byte) error {
	raw, err := encodeJournalFrame(kind, s.link, body)
	if err != nil {
		return ErrA2AState
	}
	st, err := s.file.Stat()
	if err != nil || st.Size()+int64(len(raw)) > journalScanMaxBytes {
		return ErrA2AState
	}
	if n, err := s.write(s.file, raw); err != nil || n != len(raw) {
		return ErrA2AState
	}
	if s.sync(s.file) != nil {
		return ErrA2AState
	}
	f, err := readJournalFrame(bytes.NewReader(raw), s.link)
	if err != nil {
		return ErrA2AState
	}
	s.link.previous = f.digest
	s.link.sequence++
	return nil
}
