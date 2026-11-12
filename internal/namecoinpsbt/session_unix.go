//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// ProtectedStore is implemented only by the qualified same-process native
// journal adapter. Buffers contain SECRET integrity state: never route them to
// an outer command, file, pipe, formatter or diagnostic. Replace is update-only;
// absence never initializes. The engine separately loads exact readback bytes.
type ProtectedStore interface {
	LoadProtected() ([]byte, error)
	ReplaceProtected([]byte) error
}

// PublicResultOutput accepts only the complete result the engine has verified.
// Its native implementation owns a prevalidated explicit descriptor and returns
// success only after full write, fsync and exact readback. It is never a secret
// or general callback channel and is consumed once even after a failed write.
type PublicResultOutput interface{ WriteVerifiedResult([]byte) error }

type attemptStorage interface {
	Records() ([][]byte, error)
	Append([]byte) error
	Descriptor(namecoinjournal.AttemptID) ([]byte, error)
	Result(namecoinjournal.AttemptID) ([]byte, error)
	PutDescriptor(namecoinjournal.AttemptID, []byte) error
	PutResult(namecoinjournal.AttemptID, []byte) error
	Close() error
}

// Session retains the real account gate from before protected state is loaded
// through private clearing and final readback. No method initializes missing
// state. A session is single-use and cannot be retried after an interruption.
// CompleteReviewed is an internal same-process native entry: the native caller
// must show this immutable attempt's complete review and freshly unseal this
// account with Touch ID before lending material. There is no approval boolean,
// generic digest entry, private RPC, recovery initialization or software fallback.
type Session struct {
	mu               sync.Mutex
	attempt          PublicAttempt
	sidecar          namecoinjournal.Sidecar
	storage          attemptStorage
	consumed, closed bool
	now              func() time.Time
}

func OpenSession(attempt PublicAttempt, sidecar namecoinjournal.Sidecar) (*Session, error) {
	if _, err := attempt.ReviewDocument(); err != nil {
		return nil, err
	}
	if err := sessionBinding(attempt, sidecar); err != nil {
		return nil, err
	}
	storage, err := namecoinjournal.LoadStorage(sidecar)
	if err != nil {
		if errors.Is(err, namecoinlocalgate.ErrAccountBusy) {
			return nil, failure(namecoinwire.AccountBusy)
		}
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	return &Session{attempt: attempt, sidecar: sidecar, storage: storage, now: time.Now}, nil
}
func sessionBinding(a PublicAttempt, s namecoinjournal.Sidecar) error {
	selected := a.Selection()
	context, err := a.candidate.ReviewContext(selected)
	if err != nil || len(a.review) == 0 || s.Binding.Group != selected.Group || s.Binding.Account != selected.Account || s.Binding.PublicPin != context.AccountPinSHA256 || s.Binding.Policy != selected.Policy.Revision {
		return failure(namecoinwire.AccountMismatch)
	}
	if _, err = namecoinjournal.EncodeSidecar(s); err != nil {
		return failure(namecoinwire.AccountMismatch)
	}
	return nil
}
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.storage == nil {
		return nil
	}
	return s.storage.Close()
}

// CompleteReviewed borrows exactly account-scalar32 || chaincode32, never stores
// or returns it, and clears all owned signing/anchor/intermediate buffers before
// returning. The caller must clear its borrowed source before Close releases the
// gate. A failed native write/readback or any error after possible D persistence
// reports UNKNOWN; no truncation, reset, automatic re-sign or fallback occurs.
func (s *Session) CompleteReviewed(material []byte, native ProtectedStore, output PublicResultOutput) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.consumed || s.storage == nil || native == nil || output == nil {
		return nil, failure(namecoinwire.ReplayRefused)
	}
	s.consumed = true
	if err := s.attempt.candidate.Admit(s.attempt.selected, s.now()); err != nil {
		return nil, err
	}
	point, chain := s.attempt.candidate.AccountPublic()
	account, err := loadSigningAccount(material, point, chain)
	if err != nil {
		return nil, err
	}
	defer account.clear()
	protected, err := native.LoadProtected()
	defer clear(protected)
	if err != nil {
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	anchor, err := namecoinjournal.DecodeProtected(protected, s.sidecar.Binding)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	defer anchor.Clear()
	if anchor.VerifyAccount(material) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	records, err := s.storage.Records()
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	ledger, err := anchor.RestoreLedger(records)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	var entries []HistoryEntry
	for _, id := range s.attempt.predecessorIDs() {
		descriptor, e := s.storage.Descriptor(id)
		if e != nil {
			return nil, failure(namecoinwire.OutcomeUnknown)
		}
		result, e := s.storage.Result(id)
		if e != nil {
			return nil, failure(namecoinwire.OutcomeUnknown)
		}
		entries = append(entries, HistoryEntry{Descriptor: descriptor, Result: result})
	}
	if err = s.attempt.VerifyPredecessors(anchor, records, entries); err != nil {
		return nil, err
	}
	transition, err := ledger.DispatchBound(s.attempt.ID(), s.attempt.Outpoints(), s.attempt.Commitment())
	if err != nil {
		return nil, failure(namecoinwire.ReplayRefused)
	}
	if err = s.attempt.candidate.Admit(s.attempt.selected, s.now()); err != nil {
		return nil, err
	}
	if err = s.storage.PutDescriptor(s.attempt.ID(), s.attempt.Descriptor()); err != nil {
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	dispatched, err := anchor.Append(transition.Body)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	if s.storage.Append(dispatched) != nil || persistProtected(anchor, native) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	records = append(records, dispatched)
	seq, head, err := anchor.Head()
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	// This is the first ECDSA call. The exact D and protected readback above must
	// already be durable. An expired request cannot sign even after slow storage.
	if s.attempt.candidate.Admit(s.attempt.selected, s.now()) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	signatures, err := s.attempt.candidate.signConfined(account, s.attempt.selected)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	result, err := s.attempt.candidate.ResultBytes(signatures, s.attempt.ReviewDigest(), seq, head)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	if _, err = s.attempt.candidate.VerifyResult(result, s.attempt.ReviewDigest()); err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	if s.storage.PutResult(s.attempt.ID(), result) != nil || output.WriteVerifiedResult(bytes.Clone(result)) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	signed, err := transition.Ledger.Complete(s.attempt.ID(), result)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	completed, err := anchor.Append(signed.Body)
	if err != nil || s.storage.Append(completed) != nil || persistProtected(anchor, native) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	records = append(records, completed)
	if anchor.VerifyCompleted(s.attempt.ID(), s.attempt.Commitment(), result, seq, head, records) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	// Only this fully verified completion permits the outer public acknowledgement.
	return bytes.Clone(result), nil
}
func persistProtected(anchor *namecoinjournal.Anchor, native ProtectedStore) error {
	encoded, err := anchor.EncodeProtected()
	defer clear(encoded)
	if err != nil {
		return namecoinjournal.ErrUnknown
	}
	if native.ReplaceProtected(encoded) != nil {
		return namecoinjournal.ErrUnknown
	}
	readback, err := native.LoadProtected()
	defer clear(readback)
	if err != nil || !bytes.Equal(readback, encoded) {
		return namecoinjournal.ErrUnknown
	}
	return nil
}
func (a PublicAttempt) predecessorIDs() []namecoinjournal.AttemptID {
	r := a.candidate.snapshot.Request()
	var ids []namecoinjournal.AttemptID
	if r.Slot == "B" || r.Slot == "C" || r.Slot == "D" {
		ids = append(ids, attemptIdentity(r.ReservationPlanSHA256, "A"))
	}
	if r.Slot == "C" || r.Slot == "D" {
		ids = append(ids, attemptIdentity(r.ReservationPlanSHA256, "B"))
	}
	if r.Slot == "D" {
		ids = append(ids, attemptIdentity(r.PlanSHA256, "C"))
	}
	return ids
}

// ReconcileReviewed authenticates an existing completed result after a separate
// full native reconciliation review and fresh biometric account unseal. It
// permits expired historical requests but never signs, appends, initializes or
// promotes a result whose S was not durably anchored. A new explicit public
// output descriptor must complete readback before any acknowledgement.
func (s *Session) ReconcileReviewed(material []byte, native ProtectedStore, output PublicResultOutput) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.consumed || s.storage == nil || native == nil || output == nil {
		return nil, failure(namecoinwire.ReplayRefused)
	}
	s.consumed = true
	point, chain := s.attempt.candidate.AccountPublic()
	account, err := loadSigningAccount(material, point, chain)
	if err != nil {
		return nil, err
	}
	defer account.clear()
	protected, err := native.LoadProtected()
	defer clear(protected)
	if err != nil {
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	anchor, err := namecoinjournal.DecodeProtected(protected, s.sidecar.Binding)
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	defer anchor.Clear()
	if anchor.VerifyAccount(material) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	records, err := s.storage.Records()
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	descriptor, err := s.storage.Descriptor(s.attempt.ID())
	if err != nil || !bytes.Equal(descriptor, s.attempt.descriptor) {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	result, err := s.storage.Result(s.attempt.ID())
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	receipt, err := s.attempt.candidate.VerifyResult(result, s.attempt.ReviewDigest())
	if err != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	var head [32]byte
	if _, err = hex.Decode(head[:], []byte(receipt.JournalHeadSHA256)); err != nil || anchor.VerifyCompleted(s.attempt.ID(), s.attempt.Commitment(), result, receipt.JournalSequence, head, records) != nil {
		return nil, failure(namecoinwire.OutcomeUnknown)
	}
	if output.WriteVerifiedResult(bytes.Clone(result)) != nil {
		return nil, failure(namecoinwire.OutputUnavailable)
	}
	return bytes.Clone(result), nil
}
