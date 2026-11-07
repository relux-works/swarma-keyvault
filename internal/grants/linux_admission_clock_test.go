package grants

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Per-fixture clock; never global and never selected by a build tag or env.
// Signed authority Now stays in the original fixture and is not derived here.
type linuxTestClock struct {
	mu      sync.Mutex
	at      time.Time
	step    time.Duration
	waits   []linuxTestWait
	started chan struct{}
}
type linuxTestWait struct {
	at     time.Time
	cancel context.CancelFunc
}

func newLinuxTestClock() *linuxTestClock {
	return &linuxTestClock{at: time.Now(), started: make(chan struct{}, 16)}
}
func (c *linuxTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	at := c.at
	c.at = c.at.Add(c.step)
	return at
}
func (c *linuxTestClock) advance(by time.Duration) {
	if by < 0 {
		panic("test clock cannot reverse")
	}
	c.mu.Lock()
	c.at = c.at.Add(by)
	var due []context.CancelFunc
	for _, w := range c.waits {
		if !c.at.Before(w.at) {
			due = append(due, w.cancel)
		}
	}
	c.mu.Unlock()
	for _, cancel := range due {
		cancel()
	}
}

type linuxTestDeadline struct {
	context.Context
	at time.Time
}

func (c linuxTestDeadline) Deadline() (time.Time, bool) { return c.at, true }
func (c *linuxTestClock) withDeadline(parent context.Context, at time.Time) (context.Context, context.CancelFunc) {
	if old, ok := parent.Deadline(); ok && old.Before(at) {
		at = old
	}
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	c.waits = append(c.waits, linuxTestWait{at, cancel})
	expired := !c.at.Before(at)
	c.mu.Unlock()
	if expired {
		cancel()
	}
	c.started <- struct{}{}
	return linuxTestDeadline{ctx, at}, cancel
}
func newLinuxTestProviderView(in linuxProviderInput) (*linuxProviderView, error) {
	return newLinuxProviderViewWithClock(in, newLinuxTestClock())
}
func newLinuxTestAdmissionDomain(u LinuxAdmissionUpdate, effects map[string]MUEffect) (*LinuxAdmissionDomain, error) {
	return newLinuxAdmissionDomainWithClock(u, effects, newLinuxTestClock())
}

func TestLinuxClockFenceBoundariesAndObservations(t *testing.T) {
	for _, elapsed := range []time.Duration{linuxProviderFinalLimit - time.Nanosecond, linuxProviderFinalLimit} {
		t.Run(elapsed.String(), func(t *testing.T) {
			_, d, _ := linuxDomainTestRig(t)
			c := d.clock.(*linuxTestClock)
			ctx, cancel := c.withDeadline(context.Background(), c.now().Add(linuxProviderFinalLimit))
			defer cancel()
			deadline, _ := ctx.Deadline()
			l := &linuxFinalAdmission{view: d.state.view, ctx: ctx, deadline: deadline}
			c.advance(elapsed)
			if l.live() != (elapsed < linuxProviderFinalLimit) {
				t.Fatal("100ms boundary changed")
			}
		})
	}
	g, d, _ := linuxDomainTestRig(t)
	c := d.clock.(*linuxTestClock)
	// Actual crypto runs; stepping only local elapsed checks crosses 100ms.
	// The original signed evidence/qualified Now remain untouched.
	c.mu.Lock()
	c.step = 25 * time.Millisecond
	c.mu.Unlock()
	a, err := d.state.view.advisory()
	if linuxVerifierCode(err) != "time_unavailable" || len(a.Snapshots) != 2 {
		t.Fatal("elapsed refusal lost actual observations", err, len(a.Snapshots))
	}
	if g.calls != 0 {
		t.Fatal("synthetic elapsed time granted effect")
	}
}

func TestLinuxClockOriginalExpiryPairedControl(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	c := d.clock.(*linuxTestClock)
	if _, err := d.state.view.advisory(); err != nil {
		t.Fatal("actual verifier before expiry", err)
	}
	c.advance(d.state.view.deadline.Sub(c.now()))
	if _, err := d.Handle(context.Background(), g.dock.event); err == nil || g.calls != 0 {
		t.Fatal("original expiry admitted effect", err)
	}
	linuxContractNoUse(t, g)
}

func TestLinuxClockFinalEffectBoundary(t *testing.T) {
	for _, elapsed := range []time.Duration{linuxProviderFinalLimit - time.Nanosecond, linuxProviderFinalLimit} {
		t.Run(elapsed.String(), func(t *testing.T) {
			g, d, _ := linuxDomainTestRig(t)
			c := d.clock.(*linuxTestClock)
			ctx, cancel := c.withDeadline(context.Background(), c.now().Add(linuxProviderFinalLimit))
			defer cancel()
			deadline, _ := ctx.Deadline()
			l := &linuxFinalAdmission{view: d.state.view, ctx: ctx, deadline: deadline, extraBytes: d.state.extraBytes, extraRecords: d.state.extraRecords}
			// As Handle does, exclude authoritative updates throughout receiver work.
			if err := d.lock(ctx); err != nil {
				t.Fatal(err)
			}
			defer d.unlock()
			r := d.receiver(d.state, l)
			r.open = func(ctx context.Context, conf MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, conf, b)
				c.advance(elapsed)
				return s, err
			}
			out, err := r.Handle(ctx, g.dock.event)
			if elapsed < linuxProviderFinalLimit {
				if err != nil || out == nil || out.State != "succeeded" || g.calls != 1 {
					t.Fatal("paired authenticated effect before deadline", err, out, g.calls)
				}
			} else {
				if err == nil || g.calls != 0 {
					t.Fatal("effect entered at deadline", err, g.calls)
				}
				linuxContractNoUse(t, g)
			}
		})
	}
}
