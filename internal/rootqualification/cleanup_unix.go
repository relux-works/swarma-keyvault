//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"encoding/json"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type cleanupPendingRecord struct {
	Schema               string `json:"schema"`
	State                string `json:"state"`
	CreatedReceiptSHA256 string `json:"created_receipt_sha256"`
	ReservationID        string `json:"reservation_id"`
}
type cleanupRecord struct {
	Schema                 string       `json:"schema"`
	State                  string       `json:"state"`
	UTC                    string       `json:"utc"`
	CreatedReceiptSHA256   string       `json:"created_receipt_sha256"`
	ReservationID          string       `json:"reservation_id"`
	Candidate              Candidate    `json:"candidate"`
	CreatedIdentity        FileIdentity `json:"created_identity"`
	CleanupPendingIdentity FileIdentity `json:"cleanup_pending_identity"`
	CleanupPendingSHA256   string       `json:"cleanup_pending_sha256"`
	CleanupIdentity        FileIdentity `json:"cleanup_identity"`
}

func (r *receiptFiles) reserveCleanup(record creationRecord, digest string) error {
	if r.cleanup != nil || r.checkOriginal(record, digest) != nil || !r.absent(cleanupName) || !r.absent(cleanupPendingName) {
		return ErrReceipt
	}
	raw, err := json.Marshal(cleanupPendingRecord{"keyvault-root-acl-qualification-cleanup-pending/1", "pending", digest, r.reservation})
	if err != nil {
		return ErrReceipt
	}
	raw = append(raw, '\n')
	fd, err := unix.Openat(r.dirfd(), cleanupPendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrReceipt
	}
	r.cleanup = os.NewFile(uintptr(fd), cleanupPendingName)
	r.cleanupBytes = raw
	if writeFull(r.cleanup, raw) != nil || r.cleanup.Sync() != nil || unix.Fstat(fd, &r.cleanupStat) != nil || !receiptRegular(r.cleanupStat, r.uid, 1024) || r.syncDir() != nil || r.checkOriginal(record, digest) != nil {
		return ErrReceipt
	}
	return r.checkCleanup()
}
func (r *receiptFiles) checkCleanup() error {
	if r.checkPending() != nil || r.cleanup == nil {
		return ErrReceipt
	}
	var held, named unix.Stat_t
	if unix.Fstat(int(r.cleanup.Fd()), &held) != nil || unix.Fstatat(r.dirfd(), cleanupPendingName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !receiptRegular(held, r.uid, 1024) || !sameReceiptObject(r.cleanupStat, held) || !sameReceiptObject(held, named) {
		return ErrReceipt
	}
	raw, err := r.readFixed(cleanupPendingName, 1024)
	if err != nil || !bytes.Equal(raw, r.cleanupBytes) {
		return ErrReceipt
	}
	return nil
}
func (r *receiptFiles) publishCleanup(created creationRecord, digest, state string) (Publication, error) {
	if (state != "deleted" && state != "refused" && state != "unknown") || r.checkOriginal(created, digest) != nil || r.checkCleanup() != nil {
		return Publication{}, ErrReceipt
	}
	var publication Publication
	err := r.publishBuilt(cleanupName, func(identity FileIdentity) ([]byte, error) {
		if r.checkCleanup() != nil {
			return nil, ErrReceipt
		}
		record := cleanupRecord{Schema: "keyvault-root-acl-qualification-cleanup/1", State: state, UTC: time.Now().UTC().Format(time.RFC3339Nano), CreatedReceiptSHA256: digest, ReservationID: r.reservation, Candidate: created.Candidate, CreatedIdentity: created.CreatedIdentity, CleanupPendingIdentity: fileIdentityFromStat(r.cleanupStat), CleanupPendingSHA256: receiptSHA256(r.cleanupBytes), CleanupIdentity: identity}
		raw, err := json.Marshal(record)
		if err != nil || len(raw) > 32767 {
			return nil, ErrReceipt
		}
		raw = append(raw, '\n')
		publication = Publication{SHA256: receiptSHA256(raw), State: state}
		return raw, nil
	})
	if err != nil || r.checkOriginal(created, digest) != nil || r.checkCleanup() != nil {
		return Publication{}, ErrReceipt
	}
	return publication, nil
}
