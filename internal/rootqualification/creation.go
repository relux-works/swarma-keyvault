package rootqualification

import (
	"sync"
	"time"
)

// This interface is sealed within the package. Only the actual receipt-file
// implementation constructs production reservations; no native provider or
// caller-supplied filesystem/path is accepted by ReserveCreation.
type creationFiles interface {
	checkPending() error
	close() error
}

// CreationReservation proves an exclusive pending receipt was reserved before
// one possible add. It is not code admission, owner consent or root authority.
type CreationReservation struct {
	mu        sync.Mutex
	files     creationFiles
	consumed  bool
	closed    bool
	published bool
}

type creationPublisher interface {
	completeCreation(Candidate, NativeCreation, time.Time) (Publication, error)
}

type Publication struct {
	SHA256 string
	State  string
}

// Publish records the one consumed attempt, including a finite refused or
// unknown outcome. Publication cannot revive/add/retry an item. Only a fully
// read-back created record can subsequently be loaded for item controls.
func (r *CreationReservation) Publish(candidate Candidate, result NativeCreation) (Publication, error) {
	if r == nil {
		return Publication{}, ErrReceipt
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.consumed || r.published || r.files == nil {
		return Publication{}, ErrReceipt
	}
	r.published = true
	publisher, ok := r.files.(creationPublisher)
	if !ok {
		return Publication{}, ErrReceipt
	}
	return publisher.completeCreation(candidate, result, time.Now())
}

// ConsumeForNativeCreate latches before rechecking: a changed/failed pending
// reservation cannot be restored to revive the same native attempt.
func (r *CreationReservation) ConsumeForNativeCreate() error {
	if r == nil {
		return ErrProtocol
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.consumed || r.files == nil {
		return ErrProtocol
	}
	r.consumed = true
	if r.files.checkPending() != nil {
		return ErrProtocol
	}
	return nil
}

// Close retains pending/completed audit files. It never deletes an item,
// retries an add, removes a collision, or revives a consumed capability.
func (r *CreationReservation) Close() error {
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

type CreationOutcome uint8

const (
	CreationRefused CreationOutcome = iota + 1
	CreationReadback
	CreationUnknown
)

// NativeCreation contains only public test-item evidence. Unknown/partial
// evidence cannot authorize any later item read, child control or cleanup.
type NativeCreation struct {
	Outcome      CreationOutcome
	Reference    []byte
	Before       *Projection
	After        *Projection
	BeforeSHA256 string
	AfterSHA256  string

	// Diagnostic names the first failing native step and its Security OSStatus.
	// It is printed as one public stderr line by the caller and never changes
	// Outcome or any receipt byte.
	Diagnostic Diagnostic
}
