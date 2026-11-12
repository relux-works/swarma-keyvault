package keyvault

import (
	"context"
	"sync"
)

// rootGrantsAttachPreflight holds the EXISTING guard across the future helper's
// tty/derivation/sealing phase. It contains public bindings only, not a private
// callback or generic approval. The caller must defer cancel immediately after
// begin; commit transfers the same guard without releasing or acquiring it again.
type rootGrantsAttachPreflight struct {
	state *rootGrantsPreflightState
}

type rootGrantsPreflightState struct {
	mu      sync.Mutex
	locked  rootGrantsLockedVault
	target  RootGrantsAddress
	pair    RootGrantsPairBinding
	closed  bool
	attempt *rootGrantsAttachment
}

func beginRootGrantsAttach(ctx context.Context, vault rootGrantsAttachVault, target RootGrantsAddress, pair RootGrantsPairBinding) (*rootGrantsAttachPreflight, error) {
	if ctx == nil || vault == nil || validateRootGrantsPair(pair) != nil {
		return nil, rootGrantsAttachFailed("invalid_arguments", "preflight", "not_applied", nil)
	}
	if _, err := target.Account(); err != nil {
		return nil, rootGrantsAttachFailed("invalid_arguments", "preflight", "not_applied", nil)
	}
	if ctx.Err() != nil {
		return nil, rootGrantsAttachFailed("canceled", "preflight", "not_applied", nil)
	}
	locked, err := vault.LockExistingRootGrants(ctx)
	if err != nil || locked == nil {
		if locked != nil {
			locked.Release()
		}
		return nil, rootGrantsAttachFailed("lock_unavailable", "lock", "not_applied", nil)
	}
	retained := false
	defer func() {
		if !retained {
			locked.Release()
		}
	}()
	raw, err := locked.RecoveryPublicMetadata(pair.Service, pair.Version)
	if err != nil || rootGrantsMatchPair(raw, pair) != nil {
		return nil, rootGrantsAttachFailed("retained_record_mismatch", "preflight", "not_applied", nil)
	}
	collision, err := locked.RootGrantsCollision(target)
	if err != nil {
		return nil, rootGrantsAttachFailed("inventory_changed", "preflight", "not_applied", nil)
	}
	if collision {
		return nil, rootGrantsAttachFailed("duplicate", "preflight", "not_applied", nil)
	}
	if ctx.Err() != nil {
		return nil, rootGrantsAttachFailed("canceled", "preflight", "not_applied", nil)
	}
	retained = true
	return &rootGrantsAttachPreflight{state: &rootGrantsPreflightState{locked: locked, target: target, pair: pair}}, nil
}

func (p *rootGrantsAttachPreflight) cancel() {
	if p == nil || p.state == nil {
		return
	}
	s := p.state
	s.mu.Lock()
	locked := s.locked
	s.locked = nil
	s.closed = true
	s.mu.Unlock()
	if locked != nil {
		locked.Release()
	}
}

// The sole transfer adapter owns no source of private data and cannot acquire a
// new guard. Unused transfer ownership is released on every early return.
type rootGrantsGuardTransfer struct{ locked rootGrantsLockedVault }

func (g *rootGrantsGuardTransfer) LockExistingRootGrants(context.Context) (rootGrantsLockedVault, error) {
	locked := g.locked
	g.locked = nil
	if locked == nil {
		return nil, rootGrantsAttachFailed("lock_unavailable", "lock", "not_applied", nil)
	}
	return locked, nil
}

func (p *rootGrantsAttachPreflight) commit(ctx context.Context, plan *rootGrantsAttachment) (RootGrantsAttachResult, error) {
	if p == nil || p.state == nil {
		return RootGrantsAttachResult{}, rootGrantsAttachFailed("invalid_arguments", "preflight", "not_applied", nil)
	}
	s := p.state
	s.mu.Lock()
	if s.closed || s.locked == nil {
		if s.attempt != nil {
			s.attempt.state.mu.Lock()
			stage := s.attempt.state.stage
			s.attempt.state.mu.Unlock()
			if stage == rootGrantsAttachPrepared || stage == rootGrantsAttachActive || stage == rootGrantsAttachUnknown {
				reference := s.attempt.state.public
				s.mu.Unlock()
				return RootGrantsAttachResult{}, rootGrantsAttachFailed("mutation_unknown", "commit", "unknown", &reference)
			}
		}
		s.mu.Unlock()
		return RootGrantsAttachResult{}, rootGrantsAttachFailed("operation_unavailable", "preflight", "not_applied", nil)
	}
	transfer := &rootGrantsGuardTransfer{locked: s.locked}
	s.locked, s.closed = nil, true
	valid := plan != nil && plan.state != nil && plan.state.item.address == s.target && plan.state.public.Pair == s.pair
	if valid {
		s.attempt = plan
	}
	s.mu.Unlock()
	defer func() {
		if transfer.locked != nil {
			transfer.locked.Release()
		}
	}()
	if !valid {
		return RootGrantsAttachResult{}, rootGrantsAttachFailed("public_pin_mismatch", "prepare", "not_applied", nil)
	}
	return plan.commit(ctx, transfer)
}
