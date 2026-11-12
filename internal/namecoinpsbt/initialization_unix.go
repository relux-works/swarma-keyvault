//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// ProtectedInitializer belongs only to explicit first-adoption initialization
// inside the qualified native helper. The actual adapter checks exact absence,
// uses create-only native storage, and reads back the actual same item. Secret
// buffers must stay in this process and are borrowed only for the call. There
// is no replace, reset, delete, signing or general private-output capability.
type ProtectedInitializer interface {
	RequireAbsentForExplicitInitialization() error
	CreateInitializedAnchor([]byte) error
	LoadProtected() ([]byte, error)
}

type initializationHistory interface{ Records() ([][]byte, error) }
type initializationReservation interface {
	checkAbsent() error
	create() (initializationHistory, error)
	Close() error
}
type realInitializationReservation struct {
	held *namecoinjournal.InitializationReservation
}

func (r realInitializationReservation) checkAbsent() error { return r.held.CheckPublicAbsent() }
func (r realInitializationReservation) create() (initializationHistory, error) {
	return r.held.CreatePublicState()
}
func (r realInitializationReservation) Close() error { return r.held.Close() }

// InitializationSession is distinct from ordinary sign/load/reconcile. Opening
// it retains the real gate before native protected absence/review/authentication
// and writes no state. The native caller must first show its complete separate
// initialization review and freshly unseal the selected account with Touch ID.
// Close belongs after ALL borrowed native private material has been cleared.
// Construction is not consent, code admission or a stored-success receipt.
type InitializationSession struct {
	mu               sync.Mutex
	config           NativeSelection
	account          accountPublic
	reservation      initializationReservation
	consumed, closed bool
}

func initializationAccount(config NativeSelection, pin []byte) (accountPublic, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return accountPublic{}, failure(namecoinwire.AccountMismatch)
	}
	if _, err = DecodeNativeSelection(raw); err != nil {
		return accountPublic{}, err
	}
	hash := sha256.Sum256(pin)
	if hex.EncodeToString(hash[:]) != config.Selection.AccountPinSHA256 {
		return accountPublic{}, failure(namecoinwire.AccountMismatch)
	}
	p, err := namecoinwire.DecodeAccountPin(pin)
	if err != nil || p.Group != config.Selection.Group || p.Account != config.Selection.Account {
		return accountPublic{}, failure(namecoinwire.AccountMismatch)
	}
	return parseAccount(p)
}

func OpenInitialization(config NativeSelection, pin []byte) (*InitializationSession, error) {
	account, err := initializationAccount(config, pin)
	if err != nil {
		return nil, err
	}
	held, err := namecoinjournal.ReserveInitialization(config.Sidecar)
	if err != nil {
		if errors.Is(err, namecoinlocalgate.ErrAccountBusy) {
			return nil, failure(namecoinwire.AccountBusy)
		}
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	return finishInitializationOpen(config, account, held)
}

func finishInitializationOpen(config NativeSelection, account accountPublic, held *namecoinjournal.InitializationReservation) (*InitializationSession, error) {
	transferred := false
	defer func() {
		if !transferred {
			_ = held.Close()
		}
	}()
	if held.CheckPublicAbsent() != nil {
		return nil, failure(namecoinwire.JournalUnavailable)
	}
	config.Selection.RevealValuesPin = bytes.Clone(config.Selection.RevealValuesPin)
	session := &InitializationSession{config: config, account: account, reservation: realInitializationReservation{held}}
	transferred = true
	return session, nil
}

// CheckPublicAbsent belongs before the native private account borrow. Failure
// latches this session, retains the actual gate and permits only explicit Close.
// It is public filesystem admission, never native absence/consent/code proof.
func (s *InitializationSession) CheckPublicAbsent() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.consumed || s.reservation == nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	passed := false
	defer func() {
		if !passed {
			s.consumed = true
		}
	}()
	if s.reservation.checkAbsent() != nil {
		return failure(namecoinwire.JournalUnavailable)
	}
	passed = true
	return nil
}

// CompleteReviewed performs no ECDSA. The account's actual scalar AND chaincode
// must correspond before any public create. Every error after public creation
// may leave state and is UNKNOWN; no cleanup, repair, retry or success receipt
// is synthesized. Fresh native review/Touch ID are caller obligations, never a
// Boolean argument or permission inferred from matching public data.
func (s *InitializationSession) CompleteReviewed(material []byte, native ProtectedInitializer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.consumed || s.reservation == nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	s.consumed = true
	if s.reservation.checkAbsent() != nil {
		return failure(namecoinwire.JournalUnavailable)
	}
	account, err := loadSigningAccount(material, s.account.point, s.account.chain)
	if err != nil {
		return err
	}
	defer account.clear()
	if native == nil {
		return failure(namecoinwire.JournalUnavailable)
	}
	if native.RequireAbsentForExplicitInitialization() != nil {
		return failure(namecoinwire.JournalUnavailable)
	}
	anchor, err := namecoinjournal.NewInitialization(s.config.Sidecar.Binding, material)
	if err != nil {
		return failure(namecoinwire.AccountMismatch)
	}
	defer anchor.Clear()
	encoded, err := anchor.EncodeProtected()
	if err != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	defer clear(encoded)
	storage, err := s.reservation.create()
	if err != nil || storage == nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	if native.RequireAbsentForExplicitInitialization() != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	if native.CreateInitializedAnchor(encoded) != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	readback, err := native.LoadProtected()
	defer clear(readback)
	if err != nil || !bytes.Equal(readback, encoded) {
		return failure(namecoinwire.OutcomeUnknown)
	}
	actual, err := namecoinjournal.DecodeProtected(readback, s.config.Sidecar.Binding)
	if err != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	defer actual.Clear()
	if actual.VerifyAccount(material) != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	wantSequence, wantHead, err := anchor.Head()
	sequence, head, actualErr := actual.Head()
	if err != nil || actualErr != nil || sequence != 0 || sequence != wantSequence || head != wantHead {
		return failure(namecoinwire.OutcomeUnknown)
	}
	records, err := storage.Records()
	if err != nil || len(records) != 0 {
		return failure(namecoinwire.OutcomeUnknown)
	}
	return nil
}

func (s *InitializationSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.reservation == nil {
		return nil
	}
	if s.reservation.Close() != nil {
		return failure(namecoinwire.OutcomeUnknown)
	}
	return nil
}
