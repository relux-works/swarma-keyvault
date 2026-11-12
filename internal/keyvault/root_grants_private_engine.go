package keyvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
)

// Public-only immutable inputs to one PRIVATE helper attempt. The outer vault
// MUST already retain its existing mutation guard through all attended phases
// and sole create-only commit. This engine has no store/lock/private-old-pair API.
type rootGrantsEngineInput struct {
	pairMetadata []byte
	pair         RootGrantsPairBinding
	target       RootGrantsAddress
	created      string
}

type rootGrantsEnginePhase uint8

const (
	rootGrantsEngineNew rootGrantsEnginePhase = iota
	rootGrantsEngineReading
	rootGrantsEnginePrepared
	rootGrantsEngineSealing
	rootGrantsEngineClosed
)

type rootGrantsPrivateEngine struct{ state *rootGrantsEngineState }
type rootGrantsEngineState struct {
	mu       *sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	input    rootGrantsEngineInput
	phase    rootGrantsEnginePhase
	prepared *rootGrantsPrepared
	cleared  chan struct{}
}

func (rootGrantsPrivateEngine) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<private-root-grants-engine>")
}
func (rootGrantsPrivateEngine) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}
func (rootGrantsEngineState) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<private-root-grants-engine>")
}
func (rootGrantsEngineState) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}

func newRootGrantsPrivateEngine(ctx context.Context, input rootGrantsEngineInput) (*rootGrantsPrivateEngine, error) {
	if err := rootGrantsContextError(ctx); err != nil {
		return nil, err
	}
	if validateRootGrantsPair(input.pair) != nil || rootGrantsMatchPair(input.pairMetadata, input.pair) != nil {
		return nil, recoveryRefuse("retained_record_mismatch")
	}
	if _, err := input.target.Account(); err != nil {
		return nil, recoveryRefuse("invalid_arguments")
	}
	created, err := time.Parse(time.RFC3339, input.created)
	if err != nil || len(input.created) != 20 || created.UTC().Format(time.RFC3339) != input.created {
		return nil, recoveryRefuse("invalid_arguments")
	}
	input.pairMetadata = bytes.Clone(input.pairMetadata)
	ctx, budgetCancel, budgetError := rootGrantsInputBudget(ctx)
	if budgetError != nil {
		return nil, budgetError
	}
	// A phase-local cancel inherits the SAME deadline, without canceling the
	// facade public-completion lifetime on successful sealing.
	ctx, phaseCancel := context.WithCancel(ctx)
	ctx = rootGrantsBudgetView(ctx)
	cancel := func() { phaseCancel(); budgetCancel() }
	e := &rootGrantsPrivateEngine{state: &rootGrantsEngineState{mu: &sync.Mutex{}, ctx: ctx, cancel: cancel, input: input, cleared: make(chan struct{})}}
	// Abandoned handles are invalidated and prepared material cleared at the
	// ORIGINAL whole-attempt deadline; no phase can renew that deadline.
	context.AfterFunc(ctx, e.clearPrivate)
	return e, nil
}

func (e *rootGrantsPrivateEngine) clearPrivate() {
	if e == nil || e.state == nil {
		return
	}
	s := e.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prepared.clear()
	s.prepared = nil
	if s.phase != rootGrantsEngineClosed {
		s.phase = rootGrantsEngineClosed
		close(s.cleared) // private completion witness for deadline/cancel cleanup
	}
}

func (e *rootGrantsPrivateEngine) close() {
	if e != nil && e.state != nil {
		e.state.cancel()
		e.clearPrivate()
	}
}

func (e *rootGrantsPrivateEngine) startInput() error {
	if e == nil || e.state == nil {
		return recoveryRefuse("operation_unavailable")
	}
	s := e.state
	if s.ctx.Err() == context.DeadlineExceeded {
		e.close()
		return recoveryRefuse("timeout")
	}
	s.mu.Lock()
	valid := s.phase == rootGrantsEngineNew
	if valid {
		s.phase = rootGrantsEngineReading
	}
	s.mu.Unlock()
	if !valid {
		e.close() // duplicate phase calls invalidate the entire attempt
		return recoveryRefuse("operation_unavailable")
	}
	if err := rootGrantsContextError(s.ctx); err != nil {
		e.close()
		return err
	}
	return nil
}

// prepare has no reader/fd/phrase option. Only the qualified helper may invoke
// it. Its production word source opens the controlling tty itself, never IPC.
func (e *rootGrantsPrivateEngine) prepare() (RootGrantsPreparationPublic, error) {
	if err := e.startInput(); err != nil {
		return RootGrantsPreparationPublic{}, err
	}
	phrase, err := readRootGrantsTTY(e.state.ctx)
	if err != nil {
		e.close()
		return RootGrantsPreparationPublic{}, err
	}
	return e.finishInput(phrase)
}

// finishInput is private ownership plumbing, NOT an external seed-input API.
// Only prepare passes tty-owned bytes in production. Pure test seams may call
// this after the numbered grammar; no production caller can supply an input fd.
func (e *rootGrantsPrivateEngine) finishInput(ownedPhrase []byte) (RootGrantsPreparationPublic, error) {
	defer clear(ownedPhrase)
	var empty RootGrantsPreparationPublic
	if e == nil || e.state == nil {
		return empty, recoveryRefuse("operation_unavailable")
	}
	s := e.state
	if s.ctx.Err() == context.DeadlineExceeded {
		e.close()
		return empty, recoveryRefuse("timeout")
	}
	s.mu.Lock()
	reading := s.phase == rootGrantsEngineReading
	s.mu.Unlock()
	if !reading {
		e.close()
		return empty, recoveryRefuse("operation_unavailable")
	}
	prepared, err := prepareRootGrantsAttach(s.ctx, ownedPhrase, s.input.pairMetadata, s.input.pair)
	if err != nil {
		e.close()
		return empty, err
	}
	defer func() {
		if prepared != nil {
			prepared.clear()
		}
	}()
	view, err := prepared.publicView()
	if err != nil {
		e.close()
		return empty, recoveryRefuse("private_protocol_error")
	}
	s.mu.Lock()
	if s.phase != rootGrantsEngineReading || s.ctx.Err() != nil {
		s.mu.Unlock()
		e.close()
		if err := rootGrantsContextError(s.ctx); err != nil {
			return empty, err
		}
		return empty, recoveryRefuse("operation_unavailable")
	}
	s.prepared, s.phase = prepared, rootGrantsEnginePrepared
	prepared = nil // engine now owns the private lifetime
	s.mu.Unlock()
	return view, nil
}

// Public metadata/sealed bytes ONLY. This is neither stored/enrolled nor a
// native review/presence/ACL certificate; no approval Boolean is accepted.
type rootGrantsEngineSealed struct {
	metadata []byte
	envelope RootGrantsEnvelope
}

func (e *rootGrantsPrivateEngine) seal(point, deviceBlob []byte) (rootGrantsEngineSealed, error) {
	return e.sealWithRandom(point, deviceBlob, rand.Reader)
}

func (e *rootGrantsPrivateEngine) sealWithRandom(point, deviceBlob []byte, random io.Reader) (rootGrantsEngineSealed, error) {
	var empty rootGrantsEngineSealed
	if e == nil || e.state == nil {
		return empty, recoveryRefuse("operation_unavailable")
	}
	s := e.state
	if s.ctx.Err() == context.DeadlineExceeded {
		e.close()
		return empty, recoveryRefuse("timeout")
	}
	s.mu.Lock()
	if s.phase != rootGrantsEnginePrepared || s.prepared == nil {
		s.mu.Unlock()
		e.close()
		return empty, recoveryRefuse("operation_unavailable")
	}
	s.phase = rootGrantsEngineSealing
	prepared := s.prepared
	s.mu.Unlock()
	defer e.close()
	if err := rootGrantsContextError(s.ctx); err != nil {
		return empty, err
	}
	view, err := prepared.publicView()
	if err != nil {
		return empty, recoveryRefuse("operation_unavailable")
	}
	oldPair, err := parseRecoveryRecord(s.input.pairMetadata)
	if err != nil || bytes.Equal(point, oldPair.Nostr.WrappingPoint) || bytes.Equal(point, oldPair.Namecoin.WrappingPoint) {
		return empty, recoveryRefuse("wrapping_policy_refused")
	}
	r, err := NewRootGrantsRecord(s.input.target, s.input.created, view, point)
	if err != nil {
		return empty, recoveryRefuse("invalid_envelope")
	}
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		return empty, recoveryRefuse("invalid_arguments")
	}
	envelope, err := sealRootGrantsWithRandom(s.ctx, prepared, r, deviceBlob, random)
	if err != nil {
		return empty, err
	}
	if err := rootGrantsContextError(s.ctx); err != nil {
		clear(envelope.EnclaveBlob)
		clear(envelope.Ciphertext)
		return empty, err
	}
	return rootGrantsEngineSealed{metadata: metadata, envelope: envelope}, nil
}
