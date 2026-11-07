package grants

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func linuxDomainTestUpdate(g *linuxCombinedRig) LinuxAdmissionUpdate {
	in := linuxProviderTestInput(g.dock)
	c := g.config
	c.RootRevocations = nil
	return LinuxAdmissionUpdate{Provider: in, Receiver: c, SenderKeys: map[string]string{g.dock.event.Sender: g.dock.agentID}, AccountOwners: map[string]string{},
		// Laboratory premises only: no deployment storage, clock or continuity is qualified.
		Prerequisites: LinuxDomainPrerequisites{Clock: true, Continuity: true, StorageReturnBound: time.Millisecond}}
}
func linuxDomainTestRig(t *testing.T) (*linuxCombinedRig, *LinuxAdmissionDomain, LinuxAdmissionUpdate) {
	t.Helper()
	g := newLinuxCombinedRig(t)
	linuxContractScope(g.dock, "once")
	u := linuxDomainTestUpdate(g)
	d, err := newLinuxTestAdmissionDomain(u, map[string]MUEffect{"work.assign": g.effect})
	if err != nil {
		t.Fatal(err)
	}
	return g, d, u
}

func TestLinuxDomainRealVerifierReceiverAtomicEffect(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	out, err := d.Handle(context.Background(), g.dock.event)
	if err != nil || out == nil || out.State != "succeeded" || g.calls != 1 {
		t.Fatal("real verifier/receiver control", err, out, g.calls)
	}
	s := muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	if len(s.verificationIDs) != 2 || len(s.allowances) != 1 || len(s.nonces) != 1 || len(s.highWater) != 2 || len(s.reservations) != 1 {
		t.Fatal("incomplete atomic effect custody")
	}
	for _, r := range s.reservations {
		if !r.complete || !r.intent {
			t.Fatal("effect ordering lost")
		}
	}
}

func TestLinuxDomainUpdateRefusalPairs(t *testing.T) {
	for _, mode := range []string{"generation", "revocation", "currentness", "time", "history", "clock", "continuity", "storage", "pause", "sender", "root-hold"} {
		t.Run(mode, func(t *testing.T) {
			g, d, u := linuxDomainTestRig(t)
			// Establish the paired positive control with the actual platform verifier;
			// it consumes no nonce/use and is not a mocked admission result.
			if _, err := d.state.view.advisory(); err != nil {
				t.Fatal("paired actual verifier", err)
			}
			switch mode {
			case "generation":
				a := u.Provider.Agents[g.dock.agentID]
				a.Generation = "changed"
				u.Provider.Agents[g.dock.agentID] = a
			case "revocation":
				g.dock.snapshot(g.dock.pub.id, g.dock.now, []any{map[string]any{"kind": "key", "id": g.dock.agentID, "from": g.dock.now.Add(-time.Second).Format(time.RFC3339)}})
			case "currentness":
				a := u.Provider.Agents[g.dock.agentID]
				a.Active = false
				u.Provider.Agents[g.dock.agentID] = a
			case "time":
				u.Provider.State.Trusted = false
			case "history":
				u.Provider.State.IDJournalAvailable = false
			case "clock":
				u.Prerequisites.Clock = false
			case "continuity":
				u.Prerequisites.Continuity = false
			case "storage":
				u.Prerequisites.StorageReturnBound = 0
			case "pause":
				u.Receiver.PausedModules = map[string]bool{"swarma-keyvault": true}
			case "sender":
				u.SenderKeys[g.dock.event.Sender] = "different"
			case "root-hold":
				u.RootRevocations = []MURevocation{{Kind: "key", ID: g.dock.agentID}}
			}
			if _, err := d.Replace(context.Background(), 1, u); err != nil {
				t.Fatal("update", err)
			}
			if _, err := d.Handle(context.Background(), g.dock.event); err == nil || g.calls != 0 {
				t.Fatal("updated authority admitted effect", err, g.calls)
			}
			linuxContractNoUse(t, g)
			// Refusal releases the exclusion gate even if verifier/storage work failed.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := d.Invalidate(ctx); err != nil {
				t.Fatal("refusal leaked gate", err)
			}
		})
	}
}

func TestLinuxDomainUpdatesBlockedThroughActualEffect(t *testing.T) {
	for _, mode := range []string{"generation", "revocation", "clock", "policy", "invalidation"} {
		t.Run(mode, func(t *testing.T) {
			g, d, u := linuxDomainTestRig(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			d.effects["work.assign"] = linuxEffectFunc(func(ctx context.Context, x MUDecision) ([]byte, error) {
				// The actual existing receiver has persisted reservation AND intent first.
				// The effect itself causally observes the exclusion token absent.
				select {
				case <-d.gate:
					t.Error("effect ran outside exclusion")
					d.unlock()
				default:
				}
				calls.Add(1)
				close(entered)
				<-release
				return []byte("actual synchronous fixture effect"), nil
			})
			handled := make(chan error, 1)
			go func() { _, err := d.Handle(context.Background(), g.dock.event); handled <- err }()
			select {
			case <-entered:
			case err := <-handled:
				t.Fatal("no actual effect", err)
			case <-time.After(time.Second):
				t.Fatal("effect never entered")
			}
			switch mode {
			case "generation":
				a := u.Provider.Agents[g.dock.agentID]
				a.Generation = "after-effect"
				u.Provider.Agents[g.dock.agentID] = a
			case "revocation":
				u.RootRevocations = []MURevocation{{Kind: "key", ID: g.dock.agentID}}
			case "clock":
				u.Prerequisites.Clock = false
			case "policy":
				u.Receiver.PausedModules = map[string]bool{"swarma-keyvault": true}
			}
			attempted, updated := make(chan struct{}), make(chan error, 1)
			go func() {
				close(attempted)
				if mode == "invalidation" {
					updated <- d.Invalidate(context.Background())
				} else {
					_, err := d.Replace(context.Background(), 1, u)
					updated <- err
				}
			}()
			<-attempted
			select {
			case err := <-updated:
				t.Fatal("update crossed running effect", err)
			case <-time.After(5 * time.Millisecond):
			}
			close(release)
			if err := <-handled; err != nil {
				t.Fatal("valid effect", err)
			}
			if err := <-updated; err != nil {
				t.Fatal("serialized update", err)
			}
			if calls.Load() != 1 {
				t.Fatal("effect count")
			}
			if _, err := d.Handle(context.Background(), g.dock.event); err == nil || calls.Load() != 1 {
				t.Fatal("updated domain reused old authority", err)
			}
		})
	}
}

func TestLinuxDomainCancellationAndAbsoluteBudget(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	// Occupy the actual admission domain, then cancel a waiter. It must not
	// retain/release someone else's lock or obtain a late lease.
	if err := d.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := d.Handle(ctx, g.dock.event); done <- err }()
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled waiter admitted")
	}
	d.unlock()
	// A wait consumes the SAME 100ms final budget. Hold beyond that budget;
	// no new 100ms reservation allowance may appear after acquisition.
	if err := d.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := d.clock.(*linuxTestClock)
	// Drain the first cancelled wait's deadline registration.
	<-c.started
	go func() { _, err := d.Handle(context.Background(), g.dock.event); done <- err }()
	<-c.started
	c.advance(linuxProviderFinalLimit)
	if err := <-done; err == nil {
		t.Fatal("budget renewed after waiting")
	}
	d.unlock()
	if g.calls != 0 {
		t.Fatal("timed out operation continued")
	}
	// Cleanup is independent of CPU scheduling: require a fresh lock operation
	// to complete after cancellation/refusal. Positive effects have their own test.
	clean, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := d.Invalidate(clean); err != nil {
		t.Fatal("cancel/timeout leaked gate", err)
	}

}

func TestLinuxDomainSharedBudgetThroughRealVerifierAndJournal(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	v := d.state.view
	ctx, cancel := d.clock.withDeadline(context.Background(), d.clock.now().Add(linuxProviderFinalLimit))
	defer cancel()
	deadline, _ := ctx.Deadline()
	lease := &linuxFinalAdmission{view: v, deadline: deadline, ctx: ctx, extraBytes: d.state.extraBytes, extraRecords: d.state.extraRecords}
	// The real platform verifier completes inside this one admission lease.
	a, err := lease.VerifyAdmission(v.input.Event, v.input.State.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	// Force the actual journal sync past the ORIGINAL deadline. An implementation
	// that restarts 100ms in reserveVerified would incorrectly return success.
	s.sync = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		d.clock.(*linuxTestClock).advance(deadline.Sub(d.clock.now()) + time.Millisecond)
		return nil
	}
	x := a.Decision
	u := MUUse{Once: true, GrantRoot: x.GrantRoot, GrantID: x.GrantID, Action: x.Action, TargetKind: x.TargetKind, TargetID: x.TargetID, Requester: x.Author, Nonce: x.Nonce, Audience: x.Audience, RequestHash: x.RequestHash}
	if _, err := lease.reserve(s, u); !errors.Is(err, ErrMUState) {
		t.Fatal("late reservation admitted", err)
	}
	if len(s.allowances) != 1 || len(s.verificationIDs) != 2 || g.calls != 0 {
		t.Fatal("late result refunded or effected")
	}
}

func TestLinuxDomainExpiryAndCustodyCannotRefresh(t *testing.T) {
	g, d, u := linuxDomainTestRig(t)
	// Same qualified instant with a new observation would refresh the original
	// monotonic expiry. Replace refuses rather than laundering a stale view.
	u.Provider.ObservedAt = time.Now()
	if _, err := d.Replace(context.Background(), 1, u); err == nil {
		t.Fatal("restaging refreshed time")
	}
	u.Provider.ObservedAt = d.state.view.input.ObservedAt
	u.Receiver.State.Epoch[0] ^= 1
	if _, err := d.Replace(context.Background(), 1, u); err == nil {
		t.Fatal("restore changed pinned epoch")
	}
	d.state.view.deadline = d.clock.now().Add(-time.Nanosecond)
	if _, err := d.Handle(context.Background(), g.dock.event); err == nil || g.calls != 0 {
		t.Fatal("expired authority effected")
	}
}

func TestLinuxDomainDefaultUnavailableAndRootUnion(t *testing.T) {
	g, d, u := linuxDomainTestRig(t)
	u.Prerequisites = LinuxDomainPrerequisites{}
	if _, err := d.Replace(context.Background(), 1, u); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Handle(context.Background(), g.dock.event); linuxVerifierCode(err) != "time_unavailable" || g.calls != 0 {
		t.Fatal("default pretended qualification", err)
	}
	u.Prerequisites = LinuxDomainPrerequisites{Clock: true, Continuity: true, StorageReturnBound: time.Millisecond}
	u.RootRevocations = []MURevocation{{Kind: "key", ID: g.dock.agentID}}
	if _, err := d.Replace(context.Background(), 2, u); err != nil {
		t.Fatal(err)
	}
	u.RootRevocations = nil
	if _, err := d.Replace(context.Background(), 3, u); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Handle(context.Background(), g.dock.event); !errors.Is(err, ErrMURevoked) || g.calls != 0 {
		t.Fatal("root union erased", err)
	}
}

func TestLinuxDomainReceiverLateIntentAndCancelledReservation(t *testing.T) {
	for _, mode := range []string{"late-intent", "cancel-after-reservation", "unknown-sync"} {
		t.Run(mode, func(t *testing.T) {
			g, d, _ := linuxDomainTestRig(t)
			if err := d.lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer d.unlock()
			ctx, cancel := d.clock.withDeadline(context.Background(), d.clock.now().Add(linuxProviderFinalLimit))
			defer cancel()
			deadline, _ := ctx.Deadline()
			l := &linuxFinalAdmission{view: d.state.view, deadline: deadline, ctx: ctx, extraBytes: d.state.extraBytes, extraRecords: d.state.extraRecords}
			r := d.receiver(d.state, l)
			var intent, reservation bool
			r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, c, b)
				if err != nil {
					return nil, err
				}
				kind := journalFrameKind(0)
				s.write = func(f *os.File, raw []byte) (int, error) { kind = journalFrameKind(raw[10]); return f.Write(raw) }
				s.sync = func(f *os.File) error {
					if err := f.Sync(); err != nil {
						return err
					}
					if kind == journalReservation {
						reservation = true
						if mode == "cancel-after-reservation" {
							cancel()
						}
						if mode == "unknown-sync" {
							return errors.New("synthetic lost acknowledgement")
						}
					}
					if kind == journalDispatchIntent {
						intent = true
						if mode == "late-intent" {
							d.clock.(*linuxTestClock).advance(deadline.Sub(d.clock.now()) + time.Millisecond)
						}
					}
					return nil
				}
				return s, nil
			}
			out, err := r.Handle(ctx, g.dock.event)
			if err == nil || g.calls != 0 || !reservation {
				t.Fatal("late/cancelled persistence effected", err, g.calls, reservation)
			}
			if mode == "late-intent" && (!intent || out == nil || out.State != "unknown") {
				t.Fatal("late intent refunded", err, out)
			}
			s := muOpen(t, g.config.State, g.config.Binding)
			defer s.close()
			if len(s.allowances) != 1 || len(s.verificationIDs) != 2 {
				t.Fatal("reservation not retained across refusal")
			}
		})
	}
}

func TestLinuxDomainSnapshotUpdatesRetainHoldsAndFutureMarks(t *testing.T) {
	g, d, u := linuxDomainTestRig(t)
	oldMark := g.dock.now
	// A future signed revocation must survive another source replacement even
	// if it was never used by an admitted request. Its timestamp is not a clock.
	g.dock.snapshot(g.dock.pub.id, oldMark.Add(time.Second), []any{map[string]any{"kind": "key", "id": g.dock.agentID, "from": oldMark.Format(time.RFC3339)}})
	if _, err := d.Replace(context.Background(), 1, u); err != nil {
		t.Fatal(err)
	}
	g.dock.snapshot(g.dock.pub.id, oldMark, nil)
	if _, err := d.Replace(context.Background(), 2, u); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Handle(context.Background(), g.dock.event); err == nil || g.calls != 0 {
		t.Fatal("unadmitted update lost revocation", err)
	}
	s := muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	if !s.revoked[MURevocation{Kind: "key", ID: g.dock.agentID}] || !s.highWater[g.dock.pub.id].Equal(oldMark) {
		t.Fatal("future union/mark semantics changed")
	}
}

func TestLinuxDomainOwnedCopiesAndConcurrentReplace(t *testing.T) {
	g, d, u := linuxDomainTestRig(t)
	// Mutate every caller-owned index/policy after construction, concurrently
	// with the actual verifier over domain-owned copies. This is a detachment
	// race test, not a timed final-admission qualification under instrumentation.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 0; n < 20; n++ {
			u.SenderKeys[g.dock.event.Sender] = "outside-domain"
			u.AccountOwners["account"] = "changed"
			u.Receiver.Modules["outside-module"] = true
			a := u.Provider.Agents[g.dock.agentID]
			a.Generation = "outside-generation"
			u.Provider.Agents[g.dock.agentID] = a
			u.Provider.Config.Grants[0][0] ^= 1
			u.Provider.Snapshots[g.dock.pub.id] = LinuxSnapshot{}
		}
	}()
	p, err := NewLinuxVerifier(d.state.view.input.Config, d.state.view, d.state.view, nil)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if _, err := p.VerifyAdmission(d.state.view.input.Event, g.dock.now); err != nil {
			t.Error("caller mutation changed domain", err)
		}
	}
	<-done
	if d.state.registry.keys[g.dock.event.Sender] != g.dock.agentID || len(d.state.registry.owners) != 0 || d.state.receiver.Modules["outside-module"] {
		t.Fatal("mutable policy escaped custody")
	}
	// A cancelled update waiter must neither change revision nor release another
	// holder's lock. Stale expected revisions are also refused atomically.
	if err := d.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Replace(ctx, 1, u); err == nil {
		t.Fatal("cancelled replacement")
	}
	d.unlock()
	fresh := linuxDomainTestUpdate(g)
	// g's source was deliberately corrupted above; stale CAS refuses before parse.
	if _, err := d.Replace(context.Background(), 0, fresh); err == nil {
		t.Fatal("stale replacement")
	}
	if d.revision != 1 {
		t.Fatal("cancelled/stale update changed state")
	}
}

func TestLinuxDomainReplacementCannotExtendOriginalExpiry(t *testing.T) {
	g := newLinuxCombinedRig(t)
	linuxContractScope(g.dock, "once")
	u := linuxDomainTestUpdate(g)
	u.Provider.State.AuthorityUntil = g.dock.now.Add(time.Second)
	d, err := newLinuxTestAdmissionDomain(u, map[string]MUEffect{"work.assign": g.effect})
	if err != nil {
		t.Fatal(err)
	}
	original := d.state.view.deadline
	u.Provider.State.AuthorityUntil = g.dock.now.Add(time.Minute)
	if _, err := d.Replace(context.Background(), 1, u); err != nil {
		t.Fatal(err)
	}
	if !d.state.view.deadline.Equal(original) {
		t.Fatal("replacement extended original expiry")
	}
}
