package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"
)

// LinuxProjectedVerifier is the receiver admission boundary. It must use
// protected roots and exact current author attestation/generation. Snapshot
// metadata MUST describe the very snapshots authenticated by this invocation;
// a second independent source read is not an acceptable implementation.
// The receiver supplies durable continuity; a decision alone permits no effect.
//
// Snapshots MUST hold at most 64 snapshots, at most one per signer, with every
// signer in the receiver's pinned Signers. Each signer is a nonempty token of
// at most 255 printable ASCII bytes (0x21..0x7e). Each snapshot's IssuedAt MUST
// have a positive Unix second and no fractional second; Entries MUST contain
// at most 64 distinct (Kind, ID) pairs. Kind is "record" or "key"; ID is nonempty
// and at most 255 bytes. Invalid metadata refuses the entire snapshot batch
// with ErrMUState before any of its snapshots are appended, even its valid
// subset. A corrected adapter's retry is admitted normally.
//
// Successful admission also requires a nonempty batch, fresh nonfuture
// snapshots and publisher entries matching the decision. Observation on a
// verifier refusal retains valid old/future evidence without advancing future
// marks. Observation refuses a new signer when 64 signer unions already exist;
// that capacity check is per snapshot, not a transaction over earlier appends.
// Earlier owner-root observations and storage failures have separate semantics.
type LinuxProjectedVerifier interface {
	VerifyAdmission(MUEnvelopeEvent, time.Time) (LinuxAdmission, error)
}

type LinuxReceiverConfig struct {
	MUReceiverConfig
	RoomID, ReceiverMXID              string
	PublisherKey, AgentRevocationRoot string          // explicit protected signer roles; distinct, fixed per epoch
	AllowedRooms                      map[string]bool // actual room IDs for room.membership
	PausedModules                     map[string]bool
}

// LinuxReceiver executes with the landed MU journal; it adds no wire format,
// runtime account activation, provider implementation or implicit trust.
type LinuxReceiver struct {
	config   LinuxReceiverConfig
	verifier LinuxProjectedVerifier
	registry MURegistry // protected sender-key mapping and account-owner lookup
	effects  map[string]MUEffect
	clock    func() (time.Time, error) // protected trusted clock, never event time
	open     func(context.Context, MUStateConfig, MUBinding) (*muState, error)
}

func NewLinuxReceiver(c LinuxReceiverConfig, v LinuxProjectedVerifier, registry MURegistry, effects map[string]MUEffect, clock func() (time.Time, error)) *LinuxReceiver {
	// Copy mutable protected policy so callers cannot race configuration edits.
	c.Signers = linuxBoolMap(c.Signers)
	c.Modules, c.Paused = linuxBoolMap(c.Modules), linuxBoolMap(c.Paused)
	c.AllowedRooms, c.PausedModules = linuxBoolMap(c.AllowedRooms), linuxBoolMap(c.PausedModules)
	fx := map[string]MUEffect{}
	for a, e := range effects {
		fx[a] = e
	}
	return &LinuxReceiver{config: c, verifier: v, registry: registry, effects: fx, clock: clock, open: openMUState}
}

func linuxBoolMap(in map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func linuxCloneEvent(e MUEnvelopeEvent) MUEnvelopeEvent {
	e.Envelope, e.Text = bytes.Clone(e.Envelope), bytes.Clone(e.Text)
	return e
}

// HandleProjection consumes one authenticated a2a read result. Its requested
// identity is independently bound to protected configuration by Handle.
func (r *LinuxReceiver) HandleProjection(ctx context.Context, raw []byte, room, eventID string) (*MUOutcome, error) {
	e, err := ParseLinuxProjection(raw, room, eventID)
	if err != nil {
		return nil, err
	}
	return r.Handle(ctx, e)
}

// check verifies the request and records its snapshots. Storage, trust and
// binding failures return as err at once. A step-9 refusal (a known
// revocation or a continuity rollback) returns as revocation instead, after
// the evidence is recorded, so the caller can apply the step-8 receiver
// checks first (contract section 3).
func (r *LinuxReceiver) check(e MUEnvelopeEvent, s *muState, snapshots *linuxRevocationState) (d MUDecision, revocation error, err error) {
	now, err := r.clock()
	if err != nil || now.IsZero() || now.Nanosecond() != 0 {
		return MUDecision{}, nil, ErrMUState
	}
	admission, err := r.verifier.VerifyAdmission(linuxCloneEvent(e), now)
	for _, snapshot := range admission.Snapshots {
		if !r.config.Signers[snapshot.Signer] {
			return MUDecision{}, nil, ErrMUState
		}
	}
	if err == nil && (admission.Decision.PublisherKey != r.config.PublisherKey ||
		(admission.Decision.AgentRevocationKey != "" && admission.Decision.AgentRevocationKey != r.config.AgentRevocationRoot)) {
		err = ErrMUState
	}
	if err != nil {
		// A request refusal cannot erase independently verified evidence.
		if persistErr := snapshots.observe(s, admission.Snapshots, now); persistErr != nil {
			return MUDecision{}, nil, persistErr
		}
		return MUDecision{}, nil, err
	}
	d = admission.Decision
	if known := linuxKnownRevocation(s, d); known != nil {
		if persistErr := snapshots.observe(s, admission.Snapshots, now); persistErr != nil {
			return MUDecision{}, nil, persistErr
		}
		revocation = known
	} else if admitErr := snapshots.admit(s, admission.Snapshots, d, now); admitErr != nil {
		if !errors.Is(admitErr, ErrMURollback) {
			return MUDecision{}, nil, admitErr
		}
		revocation = admitErr
	}
	// Enforce the adapter's exact-event boundary even for a stale/miswired
	// implementation. Signatures and authorization remain its responsibility.
	b, err := muMessageBody(e.Envelope)
	if err != nil {
		return MUDecision{}, nil, err
	}
	target, _ := b["target"].(map[string]any)
	args, _ := b["arguments"].(map[string]any)
	textHash := sha256.Sum256(e.Text)
	if d.RequestHash != sha256.Sum256(e.Envelope) || b["author"] != d.Author || b["author_attestation"] != d.AuthorAttestation ||
		b["aud"] != d.Audience || b["nonce"] != d.Nonce || b["action"] != d.Action || target["kind"] != d.TargetKind || target["id"] != d.TargetID ||
		b["room"] != e.Room || b["to"] != e.Receiver || b["body_sha256"] != hex.EncodeToString(textHash[:]) || len(args) != len(d.Arguments) {
		return MUDecision{}, nil, ErrMUState
	}
	for k, v := range args {
		value, exists := d.Arguments[k]
		if s, ok := v.(string); !ok || !exists || value != s {
			return MUDecision{}, nil, ErrMUState
		}
	}
	exp, err := time.Parse("2006-01-02T15:04:05Z", strOr(b["exp"]))
	if err != nil || !d.Expires.Equal(exp) || !now.Before(d.Expires) {
		return MUDecision{}, nil, ErrMUState
	}
	if d.GrantRoot != r.config.Binding.GrantRoot || d.Audience != r.config.Binding.Audience {
		return MUDecision{}, nil, ErrMUAudience
	}
	if d.Use != "once" && d.Use != "until_expiry" {
		return MUDecision{}, nil, ErrMUState
	}
	if d.GrantID == "" || d.AuthorAttestation == "" || d.PublisherKey == "" {
		return MUDecision{}, nil, ErrMUState
	}
	return d, revocation, nil
}

// policy applies the step-8 local checks in the contract's order: pause,
// widening, then owner scope. The action-target check sits between widening
// and scope, so a grant-authority action keeps its own refusal code.
func (r *LinuxReceiver) policy(d MUDecision) error {
	if r.config.Paused[d.GrantID] || r.config.PausedModules[d.Arguments["module"]] {
		return ErrMUPaused
	}
	// Defense in depth: no delegated grant may create, widen or re-delegate
	// authority.
	if grantAuthorityActions[d.Action] {
		return ErrMUWidening
	}
	if !linuxActionTarget(d.Action, d.TargetKind) {
		return ErrMUState
	}
	if d.TargetKind == "room-scope" && !r.config.AllowedRooms[d.Arguments["room"]] {
		return ErrMUScope
	}
	p := MUReceiver{config: r.config.MUReceiverConfig, registry: r.registry}
	return p.scope(d)
}

// Handle preserves reserve -> intent -> effect -> outcome. Reopening an
// unknown reservation never releases it or repeats its effect. The journal
// lock spans the final verification and the entire dispatch.
func (r *LinuxReceiver) Handle(ctx context.Context, input MUEnvelopeEvent) (*MUOutcome, error) {
	if err := ValidateLinuxRequestText(input.Text); err != nil {
		return nil, err
	}
	if r == nil || ctx == nil || ctx.Err() != nil || r.verifier == nil || r.registry == nil || r.clock == nil ||
		!a2aContextText(r.config.RoomID, '!') || !linuxMXID(r.config.ReceiverMXID) || input.Room != r.config.RoomID || input.Receiver != r.config.ReceiverMXID ||
		!linuxMXID(input.Sender) || !a2aContextText(input.EventID, '$') {
		return nil, ErrMUProjection
	}
	e := linuxCloneEvent(input)
	s, err := r.open(ctx, r.config.State, r.config.Binding)
	if err != nil {
		return nil, ErrMUState
	}
	defer s.close()
	snapshots, err := openLinuxRevocationState(s)
	if err != nil {
		return nil, ErrMUState
	}
	defer snapshots.close()
	if !r.validPins() || (&MUReceiver{config: r.config.MUReceiverConfig}).foreignSigner(s) {
		return nil, ErrMUState
	}
	// Owner-root revocations are authenticated by the injected protected
	// adapter and join the durable union at any age, even on a later refusal.
	if r.config.RootRevocations == nil {
		return nil, ErrMUState
	}
	root, err := r.config.RootRevocations()
	if err != nil {
		return nil, ErrMUState
	}
	if err := s.absorbSigned(MUOwnerRootSigner, root); err != nil {
		return nil, err
	}
	body, err := muMessageBody(e.Envelope)
	if err != nil {
		return nil, err
	}
	registered, exists := r.registry.AttestedKey(e.Sender)
	if !exists || registered != strOr(body["author"]) {
		return nil, ErrMUSender
	}
	d, revocation, err := r.check(e, s, snapshots)
	if err != nil {
		return nil, err
	}
	// Step-8 receiver checks take precedence over step-9 revocation refusals;
	// the evidence is already recorded either way.
	if err := r.policy(d); err != nil {
		return nil, err
	}
	if revocation != nil {
		return nil, revocation
	}
	if err := linuxAbsorbDecision(s, d); err != nil {
		return nil, err
	}
	// Reapply a freshly sampled protected root configuration at final admission.
	root, err = r.config.RootRevocations()
	if err != nil {
		return nil, ErrMUState
	}
	if err := s.absorbSigned(MUOwnerRootSigner, root); err != nil {
		return nil, err
	}
	again, revocation, err := r.check(e, s, snapshots)
	if err != nil {
		return nil, err
	}
	// Snapshot supersets may advance between protected-source samples; the request
	// decision and effect arguments must remain identical.
	before, after := d, again
	before.Revocations, after.Revocations = nil, nil
	before.SnapshotMarks, after.SnapshotMarks = nil, nil
	before.AgentRevocations, after.AgentRevocations = nil, nil
	if !reflect.DeepEqual(before, after) {
		return nil, ErrMUState
	}
	if err := r.policy(again); err != nil {
		return nil, err
	}
	if revocation != nil {
		return nil, revocation
	}
	if err := linuxAbsorbDecision(s, again); err != nil {
		return nil, err
	}
	effect := r.effects[again.Action]
	if effect == nil {
		return nil, ErrMUExecution
	}
	if ctx.Err() != nil {
		return nil, ErrMUState
	}
	seq, err := s.reserve(MUUse{Once: again.Use == "once", GrantRoot: again.GrantRoot, GrantID: again.GrantID, Action: again.Action, TargetKind: again.TargetKind, TargetID: again.TargetID,
		Requester: again.Author, Nonce: again.Nonce, Audience: again.Audience, RequestHash: again.RequestHash})
	if err != nil {
		return nil, err
	}
	if err := s.markIntent(seq); err != nil {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	receipt, err := effect.Execute(ctx, again)
	if err != nil || len(receipt) == 0 || len(receipt) > 8192 {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	if err := s.recordOutcome(seq, receipt); err != nil {
		return &MUOutcome{State: "unknown"}, ErrMUUnknown
	}
	return &MUOutcome{State: "succeeded", Receipt: bytes.Clone(receipt)}, nil
}

func linuxKnownRevocation(s *muState, d MUDecision) error {
	for _, rev := range []MURevocation{{"record", d.GrantID}, {"key", d.Author}, {"record", d.AuthorAttestation}, {"key", d.PublisherKey}} {
		if s.revoked[rev] {
			return ErrMURevoked
		}
	}
	return nil
}
func linuxAbsorbDecision(s *muState, d MUDecision) error {
	// The landed MUDecision/MUV1 journal retain identities, not entry.from.
	// Thus a listed identity is conservatively held immediately. Exact timed
	// revocation interoperability needs a shared contract/journal extension;
	// this candidate must not be represented as qualifying that behavior.
	for _, rev := range d.Revocations {
		if !validMURevocation(rev) {
			return ErrMUState
		}
	}
	// Root revocations always win, including a publisher revoked at any age.
	blocked := []MURevocation{{"record", d.GrantID}, {"key", d.Author}, {"record", d.AuthorAttestation}, {"key", d.PublisherKey}}
	for _, rev := range blocked {
		if s.revoked[rev] {
			return ErrMURevoked
		}
	}
	return nil
}

// validPins closes the shared receiver's optional-allowlist escape for Linux.
func (r *LinuxReceiver) validPins() bool {
	c := r.config
	return c.PublisherKey != "" && c.AgentRevocationRoot != "" && c.PublisherKey != c.AgentRevocationRoot &&
		c.PublisherKey != MUOwnerRootSigner && c.AgentRevocationRoot != MUOwnerRootSigner &&
		c.PublisherKey != c.Binding.GrantRoot && c.AgentRevocationRoot != c.Binding.GrantRoot &&
		len(c.Signers) == 2 && c.Signers[c.PublisherKey] && c.Signers[c.AgentRevocationRoot]
}
