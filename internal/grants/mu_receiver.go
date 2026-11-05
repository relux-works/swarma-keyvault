package grants

import (
	"context"
	"errors"
	"time"
)

// Receiver pipeline for multi-use owner grants on Mac (contract r3 section 8,
// seams r1 P3). Envelope, grant-chain, attestation and revocation-snapshot
// checks belong to the platform verifier behind MUVerifier; this file owns
// the registry binding, the local pause, the owner-scope executor checks and
// the durable reserve/intent/effect/outcome sequence.
var (
	ErrMUSender    = errors.New("mu-sender-not-attested")
	ErrMUPaused    = errors.New("mu-grant-locally-paused")
	ErrMUScope     = errors.New("mu-request-out-of-owner-scope")
	ErrMUAudience  = errors.New("mu-audience-mismatch")
	ErrMUWidening  = errors.New("mu-request-widens-authority")
	ErrMUExecution = errors.New("mu-effect-refused")
)

// MUEvent is one authenticated Matrix event from the a2a envelope projection.
type MUEvent struct {
	SenderMXID, RoomID, EventID string
	Envelope                    []byte
}

// MUDecision is the platform verifier's candidate decision for one request.
// It is not an effect permit until reserved here.
type MUDecision struct {
	GrantRoot, GrantID, Use      string
	Author, Audience, Nonce      string
	Action, TargetKind, TargetID string
	Arguments                    map[string]string
	Expires                      time.Time
	RequestHash                  [32]byte
}

// MUVerifier is the seam to the platform verifier (ENV v-next): it verifies the
// message envelope and the grant chain at time now and returns a decision, or
// refuses. A v0 verifier refuses P-256 authors and vocabulary-v2 actions.
type MUVerifier interface {
	Verify(event MUEvent, now time.Time) (MUDecision, error)
}

// MURegistry is the pinned registry: the MXID is an index to the key the
// owner root attested, never authority on its own; accounts resolve to owners.
type MURegistry interface {
	AttestedKey(mxid string) (string, bool)
	OwnerOf(account string) (string, bool)
}

// MUEffect performs one admitted effect and returns a bounded receipt.
type MUEffect interface {
	Execute(ctx context.Context, d MUDecision) ([]byte, error)
}

// MUReceiverConfig is the receiver's protected configuration.
type MUReceiverConfig struct {
	Binding   MUBinding
	State     MUStateConfig
	Owner     string          // e.g. "owner:alexis"
	RoomScope string          // e.g. "swarma-space"
	Modules   map[string]bool // product modules known to the product card
	Paused    map[string]bool // grant ids under a local custodian pause (X7)
}

// MUReceiver handles one request at a time per call.
type MUReceiver struct {
	config   MUReceiverConfig
	verifier MUVerifier
	registry MURegistry
	effects  map[string]MUEffect // by action; absent action refuses
	now      func() time.Time
	open     func(context.Context, MUStateConfig, MUBinding) (*muState, error)
}

// NewMUReceiver builds a receiver from its protected configuration.
func NewMUReceiver(c MUReceiverConfig, v MUVerifier, r MURegistry, effects map[string]MUEffect) *MUReceiver {
	return &MUReceiver{config: c, verifier: v, registry: r, effects: effects, now: time.Now, open: openMUState}
}

// MUOutcome reports a completed or unknown dispatch.
type MUOutcome struct {
	State   string // "succeeded" or "unknown"
	Receipt []byte
}

// grantAuthorityActions are refused under any delegated grant (X6): creating,
// widening or re-delegating a grant always needs fresh owner presence.
var grantAuthorityActions = map[string]bool{"grant.issue": true, "grant.widen": true, "grant.delegate": true, "attestation.issue": true}

func (r *MUReceiver) check(ev MUEvent, now time.Time) (MUDecision, error) {
	key, ok := r.registry.AttestedKey(ev.SenderMXID)
	if !ok {
		return MUDecision{}, ErrMUSender
	}
	d, err := r.verifier.Verify(ev, now)
	if err != nil {
		return MUDecision{}, err
	}
	if d.Author != key {
		return MUDecision{}, ErrMUSender
	}
	if d.Audience != r.config.Binding.Audience || d.GrantRoot != r.config.Binding.GrantRoot {
		return MUDecision{}, ErrMUAudience
	}
	if d.Use != "once" && d.Use != "until_expiry" {
		return MUDecision{}, ErrMUState
	}
	if !now.Before(d.Expires) {
		return MUDecision{}, ErrMUState
	}
	if r.config.Paused[d.GrantID] {
		return MUDecision{}, ErrMUPaused
	}
	if grantAuthorityActions[d.Action] {
		return MUDecision{}, ErrMUWidening
	}
	if err := r.scope(d); err != nil {
		return MUDecision{}, err
	}
	return d, nil
}

// scope applies the owner-scope executor checks (Meta Q-M3) before any effect.
func (r *MUReceiver) scope(d MUDecision) error {
	switch d.TargetKind {
	case "product":
		if !r.config.Modules[d.Arguments["module"]] {
			return ErrMUScope
		}
	case "account-scope":
		if d.TargetID != r.config.Owner {
			return ErrMUScope
		}
		if owner, ok := r.registry.OwnerOf(d.Arguments["account"]); !ok || owner != r.config.Owner {
			return ErrMUScope
		}
	case "room-scope":
		if d.TargetID != r.config.RoomScope || d.Arguments["room"] == "" {
			return ErrMUScope
		}
		if owner, ok := r.registry.OwnerOf(d.Arguments["account"]); !ok || owner != r.config.Owner {
			return ErrMUScope
		}
	default:
		return ErrMUScope
	}
	return nil
}

// Handle checks, durably reserves, dispatches once and records the outcome.
// Every refusal before reservation leaves no journal entry and no effect. After
// the intent, any failure is UNKNOWN: the reservation stays held and nothing
// is retried or released.
func (r *MUReceiver) Handle(ctx context.Context, ev MUEvent) (*MUOutcome, error) {
	if r == nil || r.verifier == nil || r.registry == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrMUState
	}
	d, err := r.check(ev, r.now())
	if err != nil {
		return nil, err
	}
	effect := r.effects[d.Action]
	if effect == nil {
		return nil, ErrMUExecution
	}
	s, err := r.open(ctx, r.config.State, r.config.Binding)
	if err != nil {
		return nil, ErrMUState
	}
	defer s.close()
	// Recheck under the lock: time, pause and scope may have changed meanwhile.
	again, err := r.check(ev, r.now())
	if err != nil {
		return nil, err
	}
	if again.GrantID != d.GrantID || again.RequestHash != d.RequestHash || again.Nonce != d.Nonce {
		return nil, ErrMUState
	}
	seq, err := s.reserve(MUUse{Once: d.Use == "once", GrantRoot: d.GrantRoot, GrantID: d.GrantID, Action: d.Action, TargetKind: d.TargetKind, TargetID: d.TargetID,
		Requester: d.Author, Nonce: d.Nonce, Audience: d.Audience, RequestHash: d.RequestHash})
	if err != nil {
		return nil, err
	}
	if err := s.markIntent(seq); err != nil {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	receipt, err := effect.Execute(ctx, d)
	if err != nil || len(receipt) == 0 || len(receipt) > 8192 {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	if err := s.recordOutcome(seq, receipt); err != nil {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	return &MUOutcome{State: "succeeded", Receipt: receipt}, nil
}
