//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"golang.org/x/sys/unix"
)

func receiptSHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func fileIdentityFromStat(s unix.Stat_t) FileIdentity {
	return FileIdentity{Device: uint64(s.Dev), Inode: s.Ino, UID: s.Uid, GID: s.Gid}
}

func (r *receiptFiles) pendingIdentity() (PendingIdentity, error) {
	if r.checkPending() != nil {
		return PendingIdentity{}, ErrReceipt
	}
	var directory unix.Stat_t
	if unix.Fstat(r.dirfd(), &directory) != nil {
		return PendingIdentity{}, ErrReceipt
	}
	return PendingIdentity{DirectoryDevice: uint64(directory.Dev), DirectoryInode: directory.Ino, Device: uint64(r.pendingStat.Dev), Inode: r.pendingStat.Ino, UID: r.pendingStat.Uid, GID: r.pendingStat.Gid, SHA256: receiptSHA256(r.pendingBytes)}, nil
}

func (r *receiptFiles) completeCreation(candidate Candidate, native NativeCreation, utc time.Time) (Publication, error) {
	pending, err := r.pendingIdentity()
	if err != nil {
		return Publication{}, err
	}
	var published Publication
	if r.publishBuilt(createdName, func(identity FileIdentity) ([]byte, error) {
		record, err := recordFromNative(utc, candidate, r.reservation, pending, native, identity)
		if err != nil {
			return nil, err
		}
		raw, err := canonicalRecord(record)
		if err != nil {
			return nil, err
		}
		published = Publication{SHA256: receiptSHA256(raw), State: record.State}
		return raw, nil
	}) != nil {
		return Publication{}, ErrReceipt
	}
	return published, nil
}

// LoadCreatedReceipt admits only the fixed actual executable/OS-home location,
// the independently reviewed original file hash and independently observed
// current candidate. It accepts no caller-supplied path, namespace or ref.
func LoadCreatedReceipt(digest string, candidate Candidate) (*LoadedReceipt, error) {
	r, err := openOwnReceiptFiles()
	if err != nil {
		return nil, ErrReceipt
	}
	loaded, err := loadCreatedReceipt(r, digest, candidate)
	if err != nil {
		_ = r.close()
		return nil, err
	}
	return loaded, nil
}
func loadCreatedReceipt(r *receiptFiles, digest string, candidate Candidate) (*LoadedReceipt, error) {
	if candidate.Validate() != nil || !r.absent(cleanupPendingName) || !r.absent(cleanupName) {
		return nil, ErrReceipt
	}
	raw, err := r.readCreatedPinned(digest)
	if err != nil {
		return nil, ErrReceipt
	}
	record, err := decodeRecord(raw)
	if err != nil || record.State != "created" || record.Candidate != candidate || record.ReservationID != r.reservation {
		return nil, ErrReceipt
	}
	pending, err := r.pendingIdentity()
	if err != nil || pending != record.Pending {
		return nil, ErrReceipt
	}
	if r.checkOriginal(record, digest) != nil {
		return nil, ErrReceipt
	}
	return &LoadedReceipt{files: r, record: record, digest: digest}, nil
}
func (r *receiptFiles) checkOriginal(record creationRecord, digest string) error {
	if record.State != "created" || validateRecord(record) != nil || record.ReservationID != r.reservation {
		return ErrReceipt
	}
	var created unix.Stat_t
	if unix.Fstatat(r.dirfd(), createdName, &created, unix.AT_SYMLINK_NOFOLLOW) != nil || !receiptRegular(created, r.uid, maxReceiptBytes) || fileIdentityFromStat(created) != record.CreatedIdentity {
		return ErrReceipt
	}
	pending, err := r.pendingIdentity()
	if err != nil || pending != record.Pending {
		return ErrReceipt
	}
	raw, err := r.readCreatedPinned(digest)
	if err != nil {
		return ErrReceipt
	}
	want, err := canonicalRecord(record)
	if err != nil || !bytes.Equal(raw, want) {
		return ErrReceipt
	}
	return nil
}
