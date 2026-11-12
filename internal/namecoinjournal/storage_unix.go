//go:build darwin || linux

package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"golang.org/x/sys/unix"
)

const (
	maxJournalBytes    = 64 << 20
	maxDescriptorBytes = 12 << 20
	journalHeader      = "KVJF1\x00"
)

type directoryLink struct {
	parent int
	name   string
	fd     int
}

// Storage owns the real kernel gate and fd-relative public journal/cache files.
// Load/Create acquire the gate before reading any state. Retain this handle
// until all confined material has been cleared and protected readbacks finish.
// It never stores an Anchor, integrity key/token or account material. File
// contents remain untrusted until checked against the independently loaded,
// account-rederived protected anchor. Do not copy a Storage.
type Storage struct {
	mu       sync.Mutex
	gate     *namecoinlocalgate.Guard
	ownsGate bool
	home     string
	links    []directoryLink
	uid      uint32
	pid      int
	binding  Binding
	closed   bool
	damaged  bool
	sidecar  []byte
}

// CreateStorage belongs only to the separately reviewed initialization flow.
// The selected account directory and all files are create-only. A partial
// initialization is left for explicit reconciliation, never repaired/replaced.
func CreateStorage(sidecar Sidecar) (*Storage, error) {
	home, err := loginHome()
	if err != nil {
		return nil, err
	}
	return openStorageAt(home, sidecar, true)
}

// LoadStorage never creates a missing directory, journal, sidecar or anchor.
func LoadStorage(sidecar Sidecar) (*Storage, error) {
	home, err := loginHome()
	if err != nil {
		return nil, err
	}
	return openStorageAt(home, sidecar, false)
}

func loginHome() (string, error) {
	if os.Getuid() != os.Geteuid() {
		return "", ErrInvalid
	}
	// Lookup by actual uid, never HOME/USER or a caller's selected path.
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || !filepath.IsAbs(u.HomeDir) || filepath.Clean(u.HomeDir) != u.HomeDir {
		return "", ErrInvalid
	}
	return u.HomeDir, nil
}

func openStorageAt(home string, sidecar Sidecar, create bool) (_ *Storage, result error) {
	if _, err := EncodeSidecar(sidecar); err != nil {
		return nil, err
	}
	gate, err := namecoinlocalgate.Acquire()
	if err != nil {
		return nil, err
	}
	return openStorageWithGuard(home, sidecar, create, gate, true)
}

// The guard is created only by the real kernel acquisition above or the finite
// initialization reservation. ownsGate is cleanup ownership, never admission.
func openStorageWithGuard(home string, sidecar Sidecar, create bool, gate *namecoinlocalgate.Guard, ownsGate bool) (_ *Storage, result error) {
	rawSidecar, err := EncodeSidecar(sidecar)
	if err != nil || gate == nil {
		if ownsGate && gate != nil {
			_ = gate.Close()
		}
		return nil, ErrInvalid
	}
	locator, err := Locator(sidecar.Binding)
	if err != nil {
		if ownsGate {
			_ = gate.Close()
		}
		return nil, err
	}
	s := &Storage{gate: gate, ownsGate: ownsGate, home: home, uid: uint32(os.Getuid()), pid: os.Getpid(), binding: sidecar.Binding, sidecar: bytes.Clone(rawSidecar)}
	defer func() {
		if result != nil {
			_ = s.Close()
		}
	}()
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnknown
	}
	s.links = append(s.links, directoryLink{parent: -1, name: home, fd: fd})
	if !directoryOK(fd, s.uid, false) {
		return nil, ErrUnknown
	}
	// Existing user-owned Library/Application Support may be0755 or0700.
	// Every newly dedicated directory is exactly0700, without chmod repair.
	components := []string{"Library", "Application Support", "mac-keyvault", "namecoin-journal", "v1", locator}
	for i, name := range components {
		private := i >= 2
		mustCreate := create && i == len(components)-1
		if create && private {
			err = unix.Mkdirat(fd, name, 0700)
			if err != nil && (mustCreate || err != unix.EEXIST) {
				return nil, ErrUnknown
			}
			if err == nil && unix.Fsync(fd) != nil {
				return nil, ErrUnknown
			}
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, ErrUnknown
		}
		s.links = append(s.links, directoryLink{parent: fd, name: name, fd: next})
		fd = next
		if !directoryOK(fd, s.uid, private) {
			return nil, ErrUnknown
		}
	}
	if !s.valid() {
		return nil, ErrUnknown
	}
	if create {
		if err = s.createFile("sidecar", rawSidecar); err != nil {
			return nil, err
		}
		if err = s.createFile("records", []byte(journalHeader)); err != nil {
			return nil, err
		}
	}
	actual, err := s.readFile("sidecar", 640)
	if err != nil || !bytes.Equal(actual, rawSidecar) {
		return nil, ErrUnknown
	}
	if _, err = s.records(); err != nil {
		return nil, err
	}
	return s, nil
}

func directoryOK(fd int, uid uint32, private bool) bool {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid {
		return false
	}
	if private {
		return st.Mode&07777 == 0700
	}
	return st.Mode&07022 == 0 && st.Mode&0700 == 0700
}

func sameFile(a, b *unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func (s *Storage) valid() bool {
	if s == nil || s.closed || s.pid != os.Getpid() || len(s.links) != 7 {
		return false
	}
	for i, link := range s.links {
		var held, named unix.Stat_t
		if unix.Fstat(link.fd, &held) != nil || !directoryOK(link.fd, s.uid, i >= 3) {
			return false
		}
		if link.parent < 0 {
			if unix.Lstat(link.name, &named) != nil {
				return false
			}
		} else if unix.Fstatat(link.parent, link.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return false
		}
		if named.Mode&unix.S_IFMT != unix.S_IFDIR || !sameFile(&held, &named) {
			return false
		}
	}
	return true
}
func (s *Storage) dir() int { return s.links[len(s.links)-1].fd }

func (s *Storage) checkFile(fd int, name string) bool {
	var held, named unix.Stat_t
	return unix.Fstat(fd, &held) == nil && held.Mode&unix.S_IFMT == unix.S_IFREG && held.Uid == s.uid && held.Mode&07777 == 0600 && held.Nlink == 1 && unix.Fstatat(s.dir(), name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil && sameFile(&held, &named) && named.Mode&unix.S_IFMT == unix.S_IFREG
}
func (s *Storage) openFile(name string, flags int) (*os.File, error) {
	if !s.valid() {
		return nil, ErrUnknown
	}
	fd, err := unix.Openat(s.dir(), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrUnknown
	}
	if !s.checkFile(fd, name) {
		_ = unix.Close(fd)
		return nil, ErrUnknown
	}
	return os.NewFile(uintptr(fd), "<public Namecoin journal file>"), nil
}
func (s *Storage) readFile(name string, max int) ([]byte, error) {
	f, err := s.openFile(name, unix.O_RDONLY)
	if err != nil {
		s.damaged = true
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max || !s.checkFile(int(f.Fd()), name) || !s.valid() {
		s.damaged = true
		return nil, ErrUnknown
	}
	return raw, nil
}
func (s *Storage) createFile(name string, raw []byte) (result error) {
	if s.damaged {
		return ErrUnknown
	}
	defer func() {
		if result != nil {
			s.damaged = true
		}
	}()
	f, err := s.openFile(name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := f.Write(raw)
	if err != nil || n != len(raw) || f.Sync() != nil || unix.Fsync(s.dir()) != nil {
		return ErrUnknown
	}
	if _, err = f.Seek(0, 0); err != nil {
		return ErrUnknown
	}
	readback, err := io.ReadAll(io.LimitReader(f, int64(len(raw))+1))
	if err != nil || !bytes.Equal(readback, raw) || !s.checkFile(int(f.Fd()), name) || !s.valid() {
		return ErrUnknown
	}
	return nil
}

func decodeRecords(raw []byte, b Binding) ([][]byte, error) {
	if len(raw) > maxJournalBytes || !bytes.HasPrefix(raw, []byte(journalHeader)) {
		return nil, ErrUnknown
	}
	raw = raw[len(journalHeader):]
	var records [][]byte
	head := genesis(b)
	for len(raw) > 0 {
		if len(raw) < 4 || len(records) >= 65536 {
			return nil, ErrUnknown
		}
		n := binary.BigEndian.Uint32(raw[:4])
		raw = raw[4:]
		if n > MaxBody+50 || uint64(n) > uint64(len(raw)) {
			return nil, ErrUnknown
		}
		frame := raw[:int(n)]
		raw = raw[int(n):]
		f, err := DecodeFrame(frame)
		if err != nil || f.Sequence != uint64(len(records))+1 || f.Previous != head {
			return nil, ErrUnknown
		}
		head = sha256.Sum256(frame)
		records = append(records, bytes.Clone(frame))
	}
	return records, nil
}
func (s *Storage) records() ([][]byte, error) {
	sidecar, err := s.readFile("sidecar", 640)
	if err != nil || !bytes.Equal(sidecar, s.sidecar) {
		s.damaged = true
		return nil, ErrUnknown
	}
	raw, err := s.readFile("records", maxJournalBytes)
	if err != nil {
		return nil, err
	}
	records, err := decodeRecords(raw, s.binding)
	if err != nil {
		s.damaged = true
	}
	return records, err
}

// Records provides copied physical history only, not protected provenance.
func (s *Storage) Records() ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records()
}

// Append durably writes one physically consistent complete frame, fsyncs and
// reads back the full file. It does not update the protected item. No private
// operation may occur until that separate exact protected readback succeeds.
// Any failed/partial write remains on disk; this method never truncates/repairs.
func (s *Storage) Append(frame []byte) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.damaged {
		return ErrUnknown
	}
	if _, err := s.records(); err != nil {
		return err
	}
	frame = bytes.Clone(frame)
	before, err := s.readFile("records", maxJournalBytes)
	if err != nil {
		return err
	}
	if len(frame) > MaxBody+50 || len(frame)+4 > maxJournalBytes-len(before) {
		return ErrInvalid
	}
	after := append(bytes.Clone(before), binary.BigEndian.AppendUint32(nil, uint32(len(frame)))...)
	after = append(after, frame...)
	if _, err = decodeRecords(after, s.binding); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			s.damaged = true
		}
	}()
	f, err := s.openFile("records", unix.O_RDWR|unix.O_APPEND)
	if err != nil {
		return err
	}
	defer f.Close()
	current, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil || !bytes.Equal(current, before) {
		return ErrUnknown
	}
	n, err := f.Write(after[len(before):])
	if err != nil || n != len(after)-len(before) || f.Sync() != nil {
		return ErrUnknown
	}
	if _, err = f.Seek(0, 0); err != nil {
		return ErrUnknown
	}
	readback, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil || !bytes.Equal(readback, after) || !s.checkFile(int(f.Fd()), "records") || !s.valid() {
		return ErrUnknown
	}
	return nil
}

func cacheName(kind string, id AttemptID) string { return kind + "-" + hex.EncodeToString(id[:]) }

// PutDescriptor/PutResult are public-data, create-only durability operations.
// Their hashes and typed meaning must be checked against protected history.
func (s *Storage) PutDescriptor(id AttemptID, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(raw) == 0 || len(raw) > maxDescriptorBytes {
		return ErrInvalid
	}
	if s.damaged {
		return ErrUnknown
	}
	if _, err := s.records(); err != nil {
		return err
	}
	return s.createFile(cacheName("attempt", id), bytes.Clone(raw))
}
func (s *Storage) Descriptor(id AttemptID) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readFile(cacheName("attempt", id), maxDescriptorBytes)
}
func (s *Storage) PutResult(id AttemptID, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(raw) == 0 || len(raw) > 8<<20 {
		return ErrInvalid
	}
	if s.damaged {
		return ErrUnknown
	}
	if _, err := s.records(); err != nil {
		return err
	}
	return s.createFile(cacheName("result", id), bytes.Clone(raw))
}
func (s *Storage) Result(id AttemptID) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readFile(cacheName("result", id), 8<<20)
}

func (s *Storage) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var failed bool
	for i := len(s.links) - 1; i >= 0; i-- {
		if unix.Close(s.links[i].fd) != nil {
			failed = true
		}
	}
	if s.ownsGate && s.gate != nil && s.gate.Close() != nil {
		failed = true
	}
	if failed {
		return ErrUnknown
	}
	return nil
}
