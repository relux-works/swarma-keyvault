//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var errReceiptFiles = errors.New("public qualification receipt storage refused")

const maxReceiptBytes = 1048576
const pendingName = "created-item.pending"
const createdName = "created-item.json"
const cleanupName = "cleanup.json"
const cleanupPendingName = "cleanup.pending"

type receiptLink struct {
	fd     int
	parent int
	name   string
	stat   unix.Stat_t
}

// receiptFiles is only the filesystem component. It cannot query/add/delete a
// Keychain item, validate a native projection, or grant cleanup authority.
// One operation owns it synchronously; it is not shared between goroutines.
type receiptFiles struct {
	links         []receiptLink
	uid           uint32
	pending       *os.File
	pendingStat   unix.Stat_t
	pendingBytes  []byte
	reservation   string
	closed        bool
	cleanup       *os.File
	cleanupStat   unix.Stat_t
	cleanupBytes  []byte
	syncDirectory func(int) error
}

type pendingRecord struct {
	Schema        string `json:"schema"`
	State         string `json:"state"`
	Namespace     string `json:"namespace"`
	Account       string `json:"account"`
	ReservationID string `json:"reservation_id"`
}

func ReserveCreation() (*CreationReservation, error) {
	r, err := openOwnReceiptFiles()
	if err != nil {
		return nil, err
	}
	if err := r.reservePending(); err != nil {
		_ = r.close()
		return nil, err
	}
	return &CreationReservation{files: r}, nil
}

// openOwnReceiptFiles derives the fixed sibling from the real executable and
// OS account. No CLI path, HOME override or symlink resolution is accepted.
func openOwnReceiptFiles() (*receiptFiles, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, errReceiptFiles
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return nil, errReceiptFiles
	}
	if filepath.Base(exe) != "mac-keyvault" || filepath.Base(filepath.Dir(exe)) != "artifacts" {
		return nil, errReceiptFiles
	}
	return openReceiptFiles(u.HomeDir, filepath.Dir(filepath.Dir(exe)), uint32(os.Getuid()))
}

func openReceiptFiles(home, dir string, uid uint32) (out *receiptFiles, err error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !strings.HasPrefix(dir, home+"/") {
		return nil, errReceiptFiles
	}
	r := &receiptFiles{uid: uid}
	defer func() {
		if err != nil {
			_ = r.close()
		}
	}()
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errReceiptFiles
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil {
		_ = unix.Close(fd)
		return nil, errReceiptFiles
	}
	r.links = append(r.links, receiptLink{fd: fd, parent: unix.AT_FDCWD, name: "/", stat: s})
	if !receiptDirectoryOK(s, 0, 0755) {
		return nil, errReceiptFiles
	}
	current := ""
	for _, name := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		current += "/" + name
		parent := r.links[len(r.links)-1].fd
		next, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errReceiptFiles
		}
		if unix.Fstat(next, &s) != nil {
			_ = unix.Close(next)
			return nil, errReceiptFiles
		}
		r.links = append(r.links, receiptLink{fd: next, parent: parent, name: name, stat: s})
		valid := false
		switch {
		case current == home:
			valid = receiptDirectoryOK(s, uid, 0700)
		case strings.HasPrefix(home, current+"/"):
			valid = receiptDirectoryOK(s, 0, 0755)
		case strings.HasPrefix(current, home+"/"):
			valid = receiptDirectoryOK(s, uid, 0700) || receiptDirectoryOK(s, uid, 0755)
		}
		if current == dir {
			valid = receiptDirectoryOK(s, uid, 0700)
		}
		if !valid {
			return nil, errReceiptFiles
		}
	}
	if r.check() != nil {
		return nil, errReceiptFiles
	}
	return r, nil
}

func receiptDirectoryOK(s unix.Stat_t, uid uint32, mode uint32) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Uid == uid && uint32(s.Mode)&07777 == mode
}
func sameReceiptObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}
func (r *receiptFiles) dirfd() int { return r.links[len(r.links)-1].fd }
func (r *receiptFiles) syncDir() error {
	if r.syncDirectory != nil {
		return r.syncDirectory(r.dirfd())
	}
	return unix.Fsync(r.dirfd())
}
func (r *receiptFiles) check() error {
	if r.closed || len(r.links) == 0 {
		return errReceiptFiles
	}
	for _, l := range r.links {
		var held, named unix.Stat_t
		if unix.Fstat(l.fd, &held) != nil || unix.Fstatat(l.parent, l.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameReceiptObject(l.stat, held) || !sameReceiptObject(held, named) {
			return errReceiptFiles
		}
	}
	return nil
}

func receiptRegular(s unix.Stat_t, uid uint32, max int) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&07777 == 0600 && s.Uid == uid && s.Nlink == 1 && s.Size > 0 && s.Size <= int64(max)
}
func (r *receiptFiles) absent(name string) bool {
	var s unix.Stat_t
	return unix.Fstatat(r.dirfd(), name, &s, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT
}

// reservePending is called before any possible native add. A reservation is
// never automatically erased, including on write/fsync failure or Close.
func (r *receiptFiles) reservePending() error {
	if r.check() != nil || r.pending != nil || !r.absent(createdName) || !r.absent(pendingName) {
		return errReceiptFiles
	}
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return errReceiptFiles
	}
	reservation := hex.EncodeToString(id[:])
	b, err := json.Marshal(pendingRecord{Schema, "pending", Namespace, Account, reservation})
	if err != nil {
		return errReceiptFiles
	}
	b = append(b, '\n')
	fd, err := unix.Openat(r.dirfd(), pendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errReceiptFiles
	}
	f := os.NewFile(uintptr(fd), pendingName)
	// Retain ownership even after a failure: no retry or auto-cleanup can hide
	// a pending outcome. The caller must not attempt a native add on any error.
	r.pending = f
	r.reservation = reservation
	r.pendingBytes = b
	if writeFull(f, b) != nil || f.Sync() != nil || unix.Fstat(fd, &r.pendingStat) != nil || !receiptRegular(r.pendingStat, r.uid, 1024) || r.check() != nil || r.syncDir() != nil {
		return errReceiptFiles
	}
	return r.checkPending()
}

func (r *receiptFiles) checkPending() error {
	if r.check() != nil || r.pending == nil {
		return errReceiptFiles
	}
	var held, named unix.Stat_t
	if unix.Fstat(int(r.pending.Fd()), &held) != nil || unix.Fstatat(r.dirfd(), pendingName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !receiptRegular(held, r.uid, 1024) || !sameReceiptObject(r.pendingStat, held) || !sameReceiptObject(held, named) {
		return errReceiptFiles
	}
	b, err := r.readFixed(pendingName, 1024)
	if err != nil || !bytes.Equal(b, r.pendingBytes) {
		return errReceiptFiles
	}
	return nil
}

// loadPending never accepts a truncated/rewritten/noncanonical reservation.
func (r *receiptFiles) loadPending() error {
	if r.pending != nil {
		return r.checkPending()
	}
	b, err := r.readFixed(pendingName, 1024)
	if err != nil {
		return errReceiptFiles
	}
	var p pendingRecord
	if json.Unmarshal(b, &p) != nil || p.Schema != Schema || p.State != "pending" || p.Namespace != Namespace || p.Account != Account || len(p.ReservationID) != 32 {
		return errReceiptFiles
	}
	id, err := hex.DecodeString(p.ReservationID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != p.ReservationID {
		return errReceiptFiles
	}
	want, _ := json.Marshal(p)
	want = append(want, '\n')
	if !bytes.Equal(want, b) {
		return errReceiptFiles
	}
	fd, err := unix.Openat(r.dirfd(), pendingName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errReceiptFiles
	}
	r.pending = os.NewFile(uintptr(fd), pendingName)
	r.pendingBytes = b
	r.reservation = p.ReservationID
	if unix.Fstat(fd, &r.pendingStat) != nil {
		return errReceiptFiles
	}
	return r.checkPending()
}

func (r *receiptFiles) readFixed(name string, max int) ([]byte, error) {
	if (name != pendingName && name != createdName && name != cleanupName && name != cleanupPendingName) || r.check() != nil {
		return nil, errReceiptFiles
	}
	fd, err := unix.Openat(r.dirfd(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errReceiptFiles
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !receiptRegular(before, r.uid, max) {
		return nil, errReceiptFiles
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if err != nil || len(b) > max || int64(len(b)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(r.dirfd(), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameReceiptObject(before, after) || after.Size != before.Size || !sameReceiptObject(after, named) || r.check() != nil {
		return nil, errReceiptFiles
	}
	return b, nil
}

// publish writes only a fixed receipt destination. The caller first validates
// the complete receipt codec/native/candidate binding. This layer enforces the
// independent filesystem boundary; it never interprets payload as authority.
// Any error after a possible native mutation must be classified UNKNOWN.
func (r *receiptFiles) publish(name string, b []byte) error {
	if len(b) == 0 || len(b) > maxReceiptBytes {
		return errReceiptFiles
	}
	return r.publishBuilt(name, func(FileIdentity) ([]byte, error) { return b, nil })
}

// The private builder runs after the exclusive file inode exists, allowing
// that actual inode to be committed into its own immutable public receipt.
// It supplies no native provider, caller path or item authority.
func (r *receiptFiles) publishBuilt(name string, build func(FileIdentity) ([]byte, error)) error {
	if (name != createdName && name != cleanupName) || build == nil || r.checkPending() != nil {
		return errReceiptFiles
	}
	temp := "." + name + "." + r.reservation + ".tmp"
	fd, err := unix.Openat(r.dirfd(), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errReceiptFiles
	}
	f := os.NewFile(uintptr(fd), temp)
	defer f.Close()
	var own, named unix.Stat_t
	if unix.Fstat(fd, &own) != nil || own.Mode&unix.S_IFMT != unix.S_IFREG || own.Mode&07777 != 0600 || own.Uid != r.uid || own.Nlink != 1 || own.Size != 0 {
		return errReceiptFiles
	}
	b, err := build(fileIdentityFromStat(own))
	if err != nil || len(b) == 0 || len(b) > maxReceiptBytes {
		return errReceiptFiles
	}
	if writeFull(f, b) != nil || f.Sync() != nil || unix.Fstat(fd, &own) != nil || !receiptRegular(own, r.uid, maxReceiptBytes) || r.checkPending() != nil || unix.Fstatat(r.dirfd(), temp, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameReceiptObject(own, named) {
		return errReceiptFiles
	}
	// linkat creates the destination atomically and fails if ANY target exists.
	// There is deliberately no rename, unlink-target or overwrite fallback.
	if unix.Linkat(r.dirfd(), temp, r.dirfd(), name, 0) != nil {
		return errReceiptFiles
	}
	if r.syncDir() != nil || r.checkPending() != nil || unix.Fstatat(r.dirfd(), temp, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameReceiptObject(own, named) {
		return errReceiptFiles
	}
	if unix.Unlinkat(r.dirfd(), temp, 0) != nil || r.syncDir() != nil {
		return errReceiptFiles
	}
	readback, err := r.readFixed(name, maxReceiptBytes)
	if err != nil || !bytes.Equal(readback, b) {
		return errReceiptFiles
	}
	return nil
}

// readCreatedPinned compares the independently reviewed complete file hash.
// Its caller must still decode the closed record and validate all native,
// candidate, reservation and artifact bindings before any item operation.
func (r *receiptFiles) readCreatedPinned(digest string) ([]byte, error) {
	if !validSHA256(digest) || r.loadPending() != nil {
		return nil, errReceiptFiles
	}
	b, err := r.readFixed(createdName, maxReceiptBytes)
	if err != nil {
		return nil, errReceiptFiles
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != digest {
		return nil, errReceiptFiles
	}
	return b, nil
}

func (r *receiptFiles) close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	var failed bool
	if r.pending != nil && r.pending.Close() != nil {
		failed = true
	}
	if r.cleanup != nil && r.cleanup.Close() != nil {
		failed = true
	}
	for i := len(r.links) - 1; i >= 0; i-- {
		if unix.Close(r.links[i].fd) != nil {
			failed = true
		}
	}
	r.links = nil
	if failed {
		return errReceiptFiles
	}
	return nil
}
