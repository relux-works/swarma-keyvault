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
	ErrMURevoked   = errors.New("mu-grant-revoked")
	ErrMURollback  = errors.New("mu-revocation-snapshot-rollback")
	ErrMUText      = errors.New("mu-request-text-refused")
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
	AuthorAttestation            string
	// PublisherKey is the grant revocation publisher whose snapshot the
	// verifier used (empty when the grant root signed it); Revocations are
	// that snapshot's complete verified entries.
	PublisherKey string
	// SnapshotMarks is the issued_at of each revocation snapshot this
	// decision used, by signer key (the publisher, and the agent revocation
	// root for a Linux author). issued_at is the per-signer sequence.
	SnapshotMarks map[string]time.Time
	// AgentRevocationKey and AgentRevocations are the agent revocation
	// root's verified snapshot for a Linux author (empty for a Mac author).
	AgentRevocationKey string
	AgentRevocations   []MURevocation
	Revocations        []MURevocation
	Expires            time.Time
	RequestHash        [32]byte
}

// MUSnapshot is one revocation snapshot whose signature by Signer has been
// verified; its age is not judged here.
type MUSnapshot struct {
	Signer   string
	IssuedAt time.Time
	Entries  []MURevocation
}

// MUSnapshotSource is implemented by a verifier that can hand the receiver
// every verified snapshot it would use for an event, before and whatever the
// outcome of verification, so a snapshot that refuses a request is still
// remembered (interop contract §2.4).
type MUSnapshotSource interface {
	VerifiedSnapshots(ev MUEvent) ([]MUSnapshot, error)
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
	// RootRevocations returns revocations signed by the owner grant root,
	// verified by the adapter and honoured at any age (r5 constraint 3).
	RootRevocations func() ([]MURevocation, error)
	// Signers pins the snapshot signers this receiver accepts: its revocation
	// publisher and, with a Linux registry, the agent revocation root. A
	// journal holding a union or mark from any other signer (the owner root
	// aside) was written under another publisher: pinning a different
	// publisher needs a new state epoch (contract, publisher profiles). Nil
	// disables the check; the service always sets it.
	Signers map[string]bool
}

// foreignSigner reports whether the journal or the decision names a snapshot
// signer this receiver does not pin.
func (r *MUReceiver) foreignSigner(s *muState, keys ...string) bool {
	if r.config.Signers == nil {
		return false
	}
	for _, k := range keys {
		if k != "" && !r.config.Signers[k] {
			return true
		}
	}
	for signer := range s.unions {
		if signer != MUOwnerRootSigner && !r.config.Signers[signer] {
			return true
		}
	}
	for signer := range s.highWater {
		if !r.config.Signers[signer] {
			return true
		}
	}
	return false
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
	r.absorbSnapshots(ctx, ev)
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
	if err := r.revocations(s, again); err != nil {
		return nil, err
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

// absorbSnapshots records the entries and issued_at of every verified
// snapshot for this event before verification, so that a snapshot which
// refuses the request is not forgotten. Errors are left to the checks that
// follow, which fail closed.
func (r *MUReceiver) absorbSnapshots(ctx context.Context, ev MUEvent) {
	src, ok := r.verifier.(MUSnapshotSource)
	if !ok {
		return
	}
	snaps, err := src.VerifiedSnapshots(ev)
	if err != nil || len(snaps) == 0 {
		return
	}
	s, err := r.open(ctx, r.config.State, r.config.Binding)
	if err != nil {
		return
	}
	defer s.close()
	if r.foreignSigner(s) {
		return
	}
	// One key signing two of the snapshots (publisher and agent revocation
	// root) would merge two signers; the decision refuses that pair, so
	// nothing is recorded for it either.
	seen := map[string]bool{}
	for _, sn := range snaps {
		if seen[sn.Signer] {
			return
		}
		seen[sn.Signer] = true
	}
	now := r.now()
	for _, sn := range snaps {
		if sn.Signer == MUOwnerRootSigner || r.foreignSigner(s, sn.Signer) || s.absorbSigned(sn.Signer, sn.Entries) != nil {
			return
		}
		// Entries always join the union, but only a snapshot that is not
		// dated in the future by the trusted clock may raise the mark;
		// otherwise one future-dated snapshot would lock out every later
		// correct one (the verifier applies the same test).
		if sn.IssuedAt.After(now) {
			continue
		}
		if s.markSnapshots(map[string]time.Time{sn.Signer: sn.IssuedAt}) != nil {
			return
		}
	}
}

// revocations applies the consumer obligations of r5 option A under the lock:
// owner-root revocations join the union at any age and always win; a revoked
// publisher fails closed; a snapshot that drops anything in the union is a
// rollback; the snapshot's own entries then join the union. The union only
// grows and survives restarts.
func (r *MUReceiver) revocations(s *muState, d MUDecision) error {
	// Each signer keeps its own union and mark; one key in both roles would
	// merge them. The platform verifier refuses that pair too.
	if d.PublisherKey != "" && d.PublisherKey == d.AgentRevocationKey {
		return ErrMUState
	}
	if r.foreignSigner(s, d.PublisherKey, d.AgentRevocationKey) {
		return ErrMUState
	}
	var root []MURevocation
	if r.config.RootRevocations != nil {
		var err error
		if root, err = r.config.RootRevocations(); err != nil {
			return ErrMUState
		}
	}
	// Owner-root entries form their own set: they revoke, but a publisher
	// that does not mirror them is not a rollback (contract §2.4).
	if err := s.absorbSigned(MUOwnerRootSigner, root); err != nil {
		return ErrMUState
	}
	for _, e := range []MURevocation{{"record", d.GrantID}, {"key", d.Author}, {"record", d.AuthorAttestation}} {
		if e.ID != "" && s.revoked[e] {
			return ErrMURevoked
		}
	}
	if d.PublisherKey != "" && s.revoked[MURevocation{"key", d.PublisherKey}] {
		return ErrMURevoked
	}
	// A snapshot older than one already accepted from the same signer is a
	// rollback even when its entries look complete (contract §2.4).
	for k, at := range d.SnapshotMarks {
		if hw, ok := s.highWater[k]; ok && at.Before(hw) {
			return ErrMURollback
		}
	}
	// Rollback is judged per signer: each snapshot must still list every
	// entry its own signer published before.
	signed := map[string][]MURevocation{}
	if d.PublisherKey != "" {
		signed[d.PublisherKey] = d.Revocations
	}
	if d.AgentRevocationKey != "" {
		signed[d.AgentRevocationKey] = d.AgentRevocations
	}
	for signer, entries := range signed {
		present := map[MURevocation]bool{}
		for _, e := range entries {
			present[e] = true
		}
		for e := range s.unions[signer] {
			if !present[e] {
				return ErrMURollback
			}
		}
	}
	for signer, entries := range signed {
		if err := s.absorbSigned(signer, entries); err != nil {
			return err
		}
	}
	return s.markSnapshots(d.SnapshotMarks)
}
