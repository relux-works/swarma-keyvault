package rootqualification

import "sync"

// LoadedReceipt is constructed only by the fixed OS-home receipt loader.
// Public digests/record syntax never construct native or cleanup authority.
// Every use rechecks both original files and their filesystem identities.
type LoadedReceipt struct {
	mu             sync.Mutex
	files          loadedFiles
	record         creationRecord
	digest         string
	closed         bool
	cleanupStarted bool
}
type loadedFiles interface {
	checkOriginal(creationRecord, string) error
	reserveCleanup(creationRecord, string) error
	checkCleanup() error
	publishCleanup(creationRecord, string, string) (Publication, error)
	close() error
}

func (r *LoadedReceipt) Request() (Request, error) {
	if r == nil {
		return Request{}, ErrReceipt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupStarted || r.files == nil || r.files.checkOriginal(r.record, r.digest) != nil {
		return Request{}, ErrReceipt
	}
	return requestFromRecord(r.record, r.digest)
}
func (r *LoadedReceipt) CheckProjection(p Projection) error {
	if r == nil {
		return ErrReceipt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupStarted || r.files == nil || r.files.checkOriginal(r.record, r.digest) != nil {
		return ErrReceipt
	}
	h, err := ProjectionSHA256(p)
	if err != nil || h != r.record.AfterSHA256 {
		return ErrReceipt
	}
	return nil
}
func (r *LoadedReceipt) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.files != nil {
		return r.files.close()
	}
	return nil
}

// CleanupReservation is a one-use capability for the same created test item.
// BeginCleanup is called only by the separately attended cleanup entry, after
// original receipt review; the public hash alone is not owner consent.
type CleanupReservation struct {
	mu        sync.Mutex
	receipt   *LoadedReceipt
	consumed  bool
	published bool
}

func (r *LoadedReceipt) BeginCleanup() (*CleanupReservation, error) {
	if r == nil {
		return nil, ErrReceipt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupStarted || r.files == nil || r.files.checkOriginal(r.record, r.digest) != nil {
		return nil, ErrReceipt
	}
	r.cleanupStarted = true
	if r.files.reserveCleanup(r.record, r.digest) != nil {
		return nil, ErrReceipt
	}
	return &CleanupReservation{receipt: r}, nil
}

// ConsumeForNativeDelete rechecks the original receipt immediately before the
// actual fixed-item native deletion. The native function independently checks
// marker, metadata and the complete current raw ACL frame before deleting.
func (c *CleanupReservation) ConsumeForNativeDelete() (Request, string, error) {
	if c == nil {
		return Request{}, "", ErrReceipt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.consumed || c.receipt == nil {
		return Request{}, "", ErrReceipt
	}
	c.consumed = true
	r := c.receipt
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.files == nil || r.files.checkOriginal(r.record, r.digest) != nil || r.files.checkCleanup() != nil {
		return Request{}, "", ErrReceipt
	}
	request, err := requestFromRecord(r.record, r.digest)
	if err != nil {
		return Request{}, "", err
	}
	return request, r.record.AfterSHA256, nil
}

type CleanupOutcome uint8

const (
	CleanupRefused CleanupOutcome = iota + 1
	CleanupDeleted
	CleanupUnknown
)

func (c *CleanupReservation) Publish(outcome CleanupOutcome) (Publication, error) {
	if c == nil {
		return Publication{}, ErrReceipt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.consumed || c.published || c.receipt == nil {
		return Publication{}, ErrReceipt
	}
	c.published = true
	state := ""
	switch outcome {
	case CleanupRefused:
		state = "refused"
	case CleanupDeleted:
		state = "deleted"
	case CleanupUnknown:
		state = "unknown"
	default:
		return Publication{}, ErrReceipt
	}
	r := c.receipt
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.files == nil || r.files.checkOriginal(r.record, r.digest) != nil || r.files.checkCleanup() != nil {
		return Publication{}, ErrReceipt
	}
	return r.files.publishCleanup(r.record, r.digest, state)
}
