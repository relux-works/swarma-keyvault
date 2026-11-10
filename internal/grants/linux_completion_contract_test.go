package grants

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// Real journal writes plus a fixture-owned clock prove the exercised ordering:
// late pre-dispatch persistence refuses without an effect, both signer marks
// survive reopen, and a timely effect's late durable outcome remains truthful.
// These controls do not measure Linux latency or hardware power-loss durability.
func TestLinuxAdmissionSynchronousCompletion(t *testing.T) {
	for _, mode := range []string{"timely", "late-snapshot", "late-reserve", "late-intent", "late-outcome", "late-snapshot-error", "late-outcome-error", "cancel-after-reserve"} {
		t.Run(mode, func(t *testing.T) {
			g, d, _ := linuxDomainTestRig(t)
			if err := d.lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer d.unlock()
			clock := d.clock.(*linuxTestClock)
			parent, cancel := context.WithCancel(context.Background())
			ctx := linuxTestDeadline{parent, clock.now().Add(linuxProviderFinalLimit)}
			defer cancel()
			deadline, _ := ctx.Deadline()
			lease := &linuxFinalAdmission{view: d.state.view, deadline: deadline, ctx: ctx, extraBytes: d.state.extraBytes, extraRecords: d.state.extraRecords}
			r := d.receiver(d.state, lease)
			snapshotSyncs := 0
			dispatchedLate := false
			r.effects = map[string]MUEffect{"work.assign": linuxEffectFunc(func(c context.Context, decision MUDecision) ([]byte, error) {
				dispatchedLate = c.Err() != nil || !clock.now().Before(deadline)
				return g.effect.Execute(c, decision)
			})}
			r.open = func(c context.Context, config MUStateConfig, binding MUBinding) (*muState, error) {
				s, err := openMUState(c, config, binding)
				if err != nil {
					return nil, err
				}
				var kind journalFrameKind
				s.write = func(f *os.File, raw []byte) (int, error) {
					kind = journalFrameKind(raw[10])
					return f.Write(raw)
				}
				s.sync = func(f *os.File) error {
					if kind == journalSnapshotMark {
						snapshotSyncs++
					}
					late := (kind == journalSnapshotMark && snapshotSyncs == 1 && (mode == "late-snapshot" || mode == "late-snapshot-error")) ||
						(kind == journalReservation && mode == "late-reserve") ||
						(kind == journalDispatchIntent && mode == "late-intent") ||
						(kind == journalOutcome && (mode == "late-outcome" || mode == "late-outcome-error"))
					if late {
						clock.advance(deadline.Sub(clock.now()) + time.Millisecond)
					}
					if err := f.Sync(); err != nil {
						return err
					}
					if kind == journalReservation && mode == "cancel-after-reserve" {
						cancel()
					}
					if late && (mode == "late-snapshot-error" || mode == "late-outcome-error") {
						return os.ErrPermission // Lost/error acknowledgment, despite the actual Sync.
					}
					return nil
				}
				return s, nil
			}
			out, err := r.Handle(ctx, g.dock.event)
			success := mode == "timely" || mode == "late-outcome"
			effected := success || mode == "late-outcome-error"
			if dispatchedLate || g.calls != map[bool]int{false: 0, true: 1}[effected] {
				t.Fatal("effect count or admission fence", mode, g.calls, dispatchedLate)
			}
			if success {
				if err != nil || out == nil || out.State != "succeeded" || len(out.Receipt) == 0 {
					t.Fatal("durable success misreported", out, err)
				}
			} else {
				want := ErrMUState
				if mode == "late-intent" || mode == "late-outcome-error" || mode == "cancel-after-reserve" {
					want = ErrMUUnknown
				}
				deadlineCause := mode == "late-snapshot" || mode == "late-reserve" || mode == "late-intent"
				if !errors.Is(err, want) || errors.Is(err, errLinuxAdmissionDeadline) != deadlineCause {
					t.Fatal("terminal error/cause changed", mode, out, err)
				}
				if want == ErrMUUnknown && (out == nil || out.State != "unknown") {
					t.Fatal("unknown completion misreported", out, err)
				}
				if want == ErrMUState && out != nil {
					t.Fatal("pre-dispatch refusal invented an outcome", out)
				}
			}
			proofErr := linuxVerifierCompletionProof(g, d, out, err, g.calls, !dispatchedLate)
			if (proofErr == nil) != (success || linuxGenuineDeadlineCompletion(err)) {
				t.Fatal("completion proof accepted an unsafe refusal or rejected the paired control", mode, proofErr)
			}
			reopened := muOpen(t, g.config.State, g.config.Binding)
			defer reopened.close()
			wantMarks := 2
			if mode == "late-snapshot-error" {
				wantMarks = 1 // The second observation was never acknowledged/written.
			}
			if len(reopened.highWater) != wantMarks || snapshotSyncs != wantMarks {
				t.Fatal("signer persistence after terminal result", reopened.highWater, snapshotSyncs)
			}
			for signer, at := range reopened.highWater {
				var issued time.Time
				for _, observation := range d.state.observations {
					if observation.Signer == signer {
						issued = observation.IssuedAt
					}
				}
				if !at.Equal(issued) {
					t.Fatal("observation lifetime changed", at)
				}
			}
			reserved := mode != "late-snapshot" && mode != "late-snapshot-error"
			wantUses := map[bool]int{false: 0, true: 1}[reserved]
			if len(reopened.reservations) != wantUses || len(reopened.allowances) != wantUses || len(reopened.nonces) != wantUses {
				t.Fatal("persistent use was lost or invented", mode, len(reopened.reservations), len(reopened.allowances), len(reopened.nonces))
			}
			for _, use := range reopened.reservations {
				wantIntent := mode != "late-reserve"
				if use.intent != wantIntent || use.complete != effected {
					t.Fatal("durable intent/outcome misreported", mode, use.intent, use.complete)
				}
			}
		})
	}
}

// Expiry while an actual snapshot Sync is held cannot produce an early terminal
// result. After release, both signer marks persist and the effect remains absent.
func TestLinuxAdmissionWaitsForLateObservationDurability(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	if err := d.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.unlock()
	clock := d.clock.(*linuxTestClock)
	parent, cancel := context.WithCancel(context.Background())
	ctx := linuxTestDeadline{parent, clock.now().Add(linuxProviderFinalLimit)}
	defer cancel()
	deadline, _ := ctx.Deadline()
	lease := &linuxFinalAdmission{view: d.state.view, deadline: deadline, ctx: ctx, extraBytes: d.state.extraBytes, extraRecords: d.state.extraRecords}
	r := d.receiver(d.state, lease)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	r.open = func(c context.Context, config MUStateConfig, binding MUBinding) (*muState, error) {
		s, err := openMUState(c, config, binding)
		if err != nil {
			return nil, err
		}
		first := true
		s.sync = func(f *os.File) error {
			if first {
				first = false
				close(entered)
				<-release
			}
			return f.Sync()
		}
		return s, nil
	}
	go func() { _, err := r.Handle(ctx, g.dock.event); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("actual persistence boundary was not reached")
	}
	clock.advance(deadline.Sub(clock.now()) + time.Millisecond)
	var early error
	returnedEarly := false
	select {
	case early = <-done:
		returnedEarly = true
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if returnedEarly {
		t.Fatal("terminal result preceded durable completion", early)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrMUState) || !errors.Is(err, errLinuxAdmissionDeadline) || g.calls != 0 {
			t.Fatal("late completed observation admitted effect or lost deadline", err, g.calls)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("synchronous completion did not return")
	}
	s := muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	if len(s.highWater) != 2 || len(s.reservations) != 0 {
		t.Fatal("late refusal lost observations or consumed use", len(s.highWater), len(s.reservations))
	}
}
