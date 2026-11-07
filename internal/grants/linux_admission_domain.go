package grants

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
)

// LinuxProviderInput is a complete, original local observation. The custodian
// must exclude mutations while passing it to NewLinuxAdmissionDomain/Replace.
// These APIs copy it; they neither fetch evidence nor admit protected reads.
type LinuxProviderInput = linuxProviderInput

// LinuxDomainPrerequisites are obligations of the installing custodian, not
// capabilities established by this package or by a successful laboratory test.
// StorageReturnBound is a bound on the cumulative blocking work of ALL
// synchronous open/lock/replay/write/sync calls in one final admission;
// the existing filesystem API cannot enforce it. Zero values refuse effects.
// Continuity includes an independent restore floor and old-instance exclusion.
// Clock means the original Now/ObservedAt pairing has a qualified source.
type LinuxDomainPrerequisites struct {
	Clock, Continuity  bool
	StorageReturnBound time.Duration
}

// LinuxAdmissionUpdate supplies every mutable admission input as one revision.
// No callback or caller-owned registry is consulted while admitting an effect.
// RootRevocations must already be authenticated by the root custodian; they
// accumulate for this domain's lifetime, including across failed use attempts.
// Receiver.RootRevocations must be nil: use the owned slice instead.
type LinuxAdmissionUpdate struct {
	Provider                  LinuxProviderInput
	Receiver                  LinuxReceiverConfig
	SenderKeys, AccountOwners map[string]string
	RootRevocations           []MURevocation
	Prerequisites             LinuxDomainPrerequisites
}

type linuxDomainRegistry struct{ keys, owners map[string]string }

func (r linuxDomainRegistry) AttestedKey(k string) (string, bool) { v, ok := r.keys[k]; return v, ok }
func (r linuxDomainRegistry) OwnerOf(k string) (string, bool)     { v, ok := r.owners[k]; return v, ok }

type linuxDomainState struct {
	view                     *linuxProviderView
	receiver                 LinuxReceiverConfig
	registry                 linuxDomainRegistry
	roots                    []MURevocation
	observations             []LinuxVerifiedSnapshot
	advisory                 LinuxAdmission
	advisoryErr              error
	prerequisites            LinuxDomainPrerequisites
	extraBytes, extraRecords int
}

// LinuxAdmissionDomain is the single in-process update/execution exclusion
// domain. All registry, generation, policy, revocation, time/history-source,
// qualification and shutdown changes MUST use Replace or Invalidate. Do not
// install a second domain for the same authority or update its backing sources
// outside this custody. The MU journal separately excludes other journal users.
// Effects run synchronously under this gate through their outcome write; they
// must not recursively call this domain. This is not cross-process continuity.
type LinuxAdmissionDomain struct {
	clock    linuxAdmissionClock
	gate     chan struct{}
	state    linuxDomainState
	revision uint64
	disabled bool
	effects  map[string]MUEffect
}

func NewLinuxAdmissionDomain(u LinuxAdmissionUpdate, effects map[string]MUEffect) (*LinuxAdmissionDomain, error) {
	return newLinuxAdmissionDomainWithClock(u, effects, linuxRealClock{})
}
func newLinuxAdmissionDomainWithClock(u LinuxAdmissionUpdate, effects map[string]MUEffect, clock linuxAdmissionClock) (*LinuxAdmissionDomain, error) {
	clock = linuxClock(clock)
	s, err := linuxOwnDomainUpdate(u, nil, clock)
	if err != nil {
		return nil, err
	}
	d := &LinuxAdmissionDomain{clock: clock, gate: make(chan struct{}, 1), state: s, revision: 1, effects: map[string]MUEffect{}}
	d.gate <- struct{}{}
	for k, e := range effects {
		d.effects[k] = e
	}
	return d, nil
}

func linuxOwnDomainUpdate(u LinuxAdmissionUpdate, prior []MURevocation, clock linuxAdmissionClock) (linuxDomainState, error) {
	var s linuxDomainState
	// Bound the additional protected policy/index projection before copying it.
	// Charge it against the SAME 1 MiB view, not an additional allowance.
	if u.Receiver.RootRevocations != nil {
		return s, ErrMUState
	}
	n := len(u.SenderKeys) + len(u.AccountOwners) + len(u.RootRevocations) + len(prior)
	extra := 1024
	for _, m := range []map[string]string{u.SenderKeys, u.AccountOwners} {
		for k, v := range m {
			if len(k) > 4096 || len(v) > 4096 {
				return s, ErrMUState
			}
			extra += 32 + len(k) + len(v)
		}
	}
	for _, m := range []map[string]bool{u.Receiver.Signers, u.Receiver.Modules, u.Receiver.Paused, u.Receiver.AllowedRooms, u.Receiver.PausedModules} {
		n += len(m)
		for k := range m {
			if len(k) > 4096 {
				return s, ErrMUState
			}
			extra += 32 + len(k)
		}
	}
	for _, entries := range [][]MURevocation{prior, u.RootRevocations} {
		for _, r := range entries {
			if !validMURevocation(r) {
				return s, ErrMUState
			}
			extra += 32 + len(r.Kind) + len(r.ID)
		}
	}
	if n > linuxProviderMaxRecords || extra > linuxVerificationMaxViewBytes {
		return s, ErrMUState
	}
	for _, value := range []string{u.Receiver.State.Directory, u.Receiver.Owner, u.Receiver.RoomScope, u.Receiver.Binding.Audience, u.Receiver.Binding.GrantRoot, u.Receiver.RoomID, u.Receiver.ReceiverMXID, u.Receiver.PublisherKey, u.Receiver.AgentRevocationRoot} {
		if len(value) > 4096 {
			return s, ErrMUState
		}
		extra += 16 + len(value)
	}
	if !linuxProviderInputFitsBudget(u.Provider, extra, n) {
		return s, ErrMUState
	}
	pc, rc := u.Provider.Config, u.Receiver
	if pc.GrantRoot != rc.Binding.GrantRoot || pc.Audience != rc.Binding.Audience || pc.RoomID != rc.RoomID || pc.ReceiverMXID != rc.ReceiverMXID || pc.PublisherKey != rc.PublisherKey || pc.AgentRevocationRoot != rc.AgentRevocationRoot {
		return s, ErrMUState
	}
	v, err := newLinuxProviderViewWithClock(u.Provider, clock)
	if err != nil {
		return s, err
	}
	r := NewLinuxReceiver(u.Receiver, nil, nil, nil, nil)
	s = linuxDomainState{view: v, receiver: r.config, registry: linuxDomainRegistry{map[string]string{}, map[string]string{}}, prerequisites: u.Prerequisites, extraBytes: extra, extraRecords: n}
	for k, v := range u.SenderKeys {
		s.registry.keys[k] = v
	}
	for k, v := range u.AccountOwners {
		s.registry.owners[k] = v
	}
	seen := map[MURevocation]bool{}
	for _, entries := range [][]MURevocation{prior, u.RootRevocations} {
		for _, e := range entries {
			if !seen[e] {
				seen[e] = true
				s.roots = append(s.roots, e)
			}
		}
	}
	if len(s.roots) > linuxProviderMaxRecords {
		return linuxDomainState{}, ErrMUState
	}
	// Stage a real verifier advisory before final admission. The receiver still
	// repeats the complete real verification under the final lease before reserve.
	s.advisory, s.advisoryErr = v.advisory()
	if clock.now().Sub(v.input.ObservedAt) >= linuxProviderStageLimit {
		return linuxDomainState{}, ErrMUState
	}
	// Retain only independently authenticated snapshot observations. An invalid
	// source replacement still refuses at final verification; it cannot erase holds.
	for signer, raw := range v.input.Snapshots {
		if sn, err := linuxVerifiedSnapshot(raw.Wire, signer); err == nil {
			s.observations = append(s.observations, sn)
		}
	}
	if !s.observationsFit() {
		return linuxDomainState{}, ErrMUState
	}
	return s, nil
}

// Keep each authenticated observation's original time semantics. In
// particular, a future-only snapshot adds holds without raising a time mark.
// Synthesizing one latest timestamp for their union would lose that distinction.
func linuxDomainObservations(old, next []LinuxVerifiedSnapshot) ([]LinuxVerifiedSnapshot, error) {
	out := []LinuxVerifiedSnapshot{}
	for _, all := range [][]LinuxVerifiedSnapshot{old, next} {
		for _, sn := range all {
			duplicate := false
			for _, prior := range out {
				if reflect.DeepEqual(prior, sn) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if len(out) >= linuxProviderMaxRecords {
				return nil, ErrMUState
			}
			sn.Entries = append([]MURevocation(nil), sn.Entries...)
			out = append(out, sn)
		}
	}
	return out, nil
}

func (s *linuxDomainState) observationsFit() bool {
	extra := s.extraBytes
	bindings := 0
	for _, sn := range s.observations {
		extra += 64 + len(sn.Signer)
		for _, e := range sn.Entries {
			extra += 32 + len(e.Kind) + len(e.ID)
			bindings++
		}
	}
	if bindings > linuxVerificationMaxIDBindings {
		return false
	}
	candidate := s.view.input
	if candidate.State.Assurance.IsAvailable() {
		candidate.Assurance = map[string]any{"level": "A1", "presence": false}
	}
	candidate.State.Assurance = verifier.Evidence{}
	return linuxProviderInputFitsBudget(candidate, extra, s.extraRecords+len(s.observations))
}

func (d *LinuxAdmissionDomain) lock(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrMUState
	}
	select {
	case <-ctx.Done():
		return ErrMUState
	case <-d.gate:
	}
	if ctx.Err() != nil {
		d.unlock()
		return ErrMUState
	}
	return nil
}
func (d *LinuxAdmissionDomain) unlock() { d.gate <- struct{}{} }

// Replace uses compare-and-swap revision custody. A stale updater cannot replace
// newer evidence. Epoch, authority pins and journal location are immutable;
// restore/reprovision requires disabling the old instance and separate custody.
func (d *LinuxAdmissionDomain) Replace(ctx context.Context, expected uint64, u LinuxAdmissionUpdate) (uint64, error) {
	if err := d.lock(ctx); err != nil {
		return 0, err
	}
	defer d.unlock()
	if d.disabled || expected != d.revision || d.revision == ^uint64(0) {
		return d.revision, ErrMUState
	}
	a, b := d.state.receiver, u.Receiver
	old, next := d.state.view.input.Config, u.Provider.Config
	if old.GrantRoot != next.GrantRoot || old.ServiceRoot != next.ServiceRoot || old.AgentRevocationRoot != next.AgentRevocationRoot || old.PublisherKey != next.PublisherKey {
		return d.revision, ErrMUState
	}
	if a.State != b.State || a.Binding != b.Binding || a.PublisherKey != b.PublisherKey || a.AgentRevocationRoot != b.AgentRevocationRoot ||
		a.RoomID != b.RoomID || a.ReceiverMXID != b.ReceiverMXID || !reflect.DeepEqual(a.Signers, b.Signers) {
		return d.revision, ErrMUState
	}
	// Compose the source replacement with the domain's existing MU projection.
	// A concurrent completed effect never forces an updater to discard history.
	if !linuxProviderInputFits(u.Provider) {
		return d.revision, ErrMUState
	}
	merged := map[string][]byte{}
	for id, wire := range d.state.view.input.State.IDJournal {
		merged[id] = wire
	}
	for id, wire := range u.Provider.State.IDJournal {
		if prior, ok := merged[id]; ok && !bytes.Equal(prior, wire) {
			return d.revision, ErrMUState
		}
		merged[id] = wire
	}
	if len(merged) > linuxVerificationMaxIDBindings {
		return d.revision, ErrMUState
	}
	u.Provider.State.IDJournal = merged
	s, err := linuxOwnDomainUpdate(u, d.state.roots, d.clock)
	if err != nil {
		return d.revision, err
	}
	if s.view.input.ObservedAt.Before(d.state.view.input.ObservedAt) || (s.view.input.ObservedAt != d.state.view.input.ObservedAt && !s.view.input.State.Now.After(d.state.view.input.State.Now)) {
		return d.revision, ErrMUState
	}
	if s.view.input.State.Now.Before(d.state.view.input.State.Now) || s.view.input.State.Watermark.Before(d.state.view.input.State.Watermark) {
		return d.revision, ErrMUState
	}
	for id, wire := range d.state.view.input.State.IDJournal {
		if next, ok := s.view.input.State.IDJournal[id]; !ok || !bytes.Equal(wire, next) {
			return d.revision, ErrMUState
		}
	}
	// Replacing evidence observed at the same qualified instant cannot extend
	// its original earliest local expiry, even if a caller enlarges authority.
	if s.view.input.ObservedAt.Equal(d.state.view.input.ObservedAt) && d.state.view.deadline.Before(s.view.deadline) {
		s.view.deadline = d.state.view.deadline
	}
	s.observations, err = linuxDomainObservations(d.state.observations, s.observations)
	if err != nil || !s.observationsFit() {
		return d.revision, ErrMUState
	}
	d.state = s
	d.revision++
	return d.revision, nil
}

// Invalidate is irreversible for this instance and waits for any admitted effect
// to finish. No cancellation path leaves a lock or permits a late updater.
func (d *LinuxAdmissionDomain) Invalidate(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	d.disabled = true
	return nil
}

func (d *LinuxAdmissionDomain) Handle(ctx context.Context, e MUEnvelopeEvent) (*MUOutcome, error) {
	if d == nil || ctx == nil {
		return nil, ErrMUState
	}
	// Start once, BEFORE contention or journal opening. No boundary renews this.
	final, cancel := linuxClock(d.clock).withDeadline(ctx, linuxClock(d.clock).now().Add(linuxProviderFinalLimit))
	defer cancel()
	if err := d.lock(final); err != nil {
		return nil, err
	}
	defer d.unlock()
	s := d.state
	p := s.prerequisites
	if d.disabled || !p.Clock || !p.Continuity || p.StorageReturnBound <= 0 || p.StorageReturnBound > linuxProviderFinalLimit || !s.view.usable() {
		return nil, linuxVerifierRefuse("time_unavailable")
	}
	deadline, _ := final.Deadline()
	if s.view.deadline.Before(deadline) {
		deadline = s.view.deadline
	}
	extra := s.extraBytes
	for _, sn := range s.observations {
		extra += 64 + len(sn.Signer)
		for _, e := range sn.Entries {
			extra += 32 + len(e.Kind) + len(e.ID)
		}
	}
	lease := &linuxFinalAdmission{view: s.view, deadline: deadline, ctx: final, extraBytes: extra, extraRecords: s.extraRecords + len(s.observations)}
	return d.receiver(s, lease).Handle(final, e)
}

// Called only while holding the domain gate through the entire Handle.
func (d *LinuxAdmissionDomain) receiver(s linuxDomainState, lease *linuxFinalAdmission) *LinuxReceiver {
	c := s.receiver
	c.RootRevocations = func() ([]MURevocation, error) { return append([]MURevocation(nil), s.roots...), nil }
	r := NewLinuxReceiver(c, lease, s.registry, d.effects, func() (time.Time, error) {
		if !lease.live() {
			return time.Time{}, ErrMUState
		}
		return s.view.input.State.Now, nil
	})
	lease.baseline = &s.advisory
	lease.baselineErr = s.advisoryErr
	r.final = lease
	r.observations = s.observations
	return r
}

type linuxFinalAdmission struct {
	view                     *linuxProviderView
	deadline                 time.Time
	ctx                      context.Context
	admission                LinuxAdmission
	baseline                 *LinuxAdmission
	baselineErr              error
	realVerified             bool
	extraBytes, extraRecords int
}

func (l *linuxFinalAdmission) live() bool {
	return l != nil && l.ctx.Err() == nil && linuxClock(l.view.clock).now().Before(l.deadline) && l.view.usable()
}
func (l *linuxFinalAdmission) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	if !l.live() || !now.Equal(l.view.input.State.Now) || !reflect.DeepEqual(e, l.view.input.Event) {
		return LinuxAdmission{}, ErrMUState
	}
	if l.baseline != nil {
		a, err := *l.baseline, l.baselineErr
		l.baseline = nil
		// This first receiver check is advisory only. reserve requires the later
		// real invocation under this same exclusive lease and absolute deadline.
		return a, err
	}
	p, err := NewLinuxVerifier(l.view.input.Config, l.view, l.view, nil)
	if err != nil {
		return LinuxAdmission{}, err
	}
	a, err := p.VerifyAdmission(e, now)
	if err == nil && !l.live() {
		err = linuxVerifierRefuse("time_unavailable")
	}
	if err == nil {
		l.admission = a
		l.realVerified = true
	}
	return a, err
}
func (l *linuxFinalAdmission) reserve(s *muState, u MUUse) (uint64, error) {
	if !l.live() || !l.realVerified {
		return 0, ErrMUState
	}
	c, err := l.view.commitCandidate(l.admission)
	if err != nil {
		return 0, err
	}
	candidate := l.view.input
	candidate.State.IDJournal = c.ids
	if candidate.State.Assurance.IsAvailable() {
		candidate.Assurance = map[string]any{"level": "A1", "presence": false}
	}
	candidate.State.Assurance = verifier.Evidence{}
	if !linuxProviderInputFitsBudget(candidate, l.extraBytes, l.extraRecords) {
		return 0, ErrMUState
	}
	seq, err := s.reserveVerifiedUntil(u, c, l.deadline)
	// Project only what the existing journal actually committed, even on a late
	// return. This is not another authority store and never releases any hold.
	if len(s.verificationIDs) > 0 {
		l.view.input.State.IDJournal = map[string][]byte{}
		for id, wire := range s.verificationIDs {
			l.view.input.State.IDJournal[id] = bytes.Clone(wire)
		}
		l.view.input.State.Watermark = s.verificationWatermark
	}
	return seq, err
}
