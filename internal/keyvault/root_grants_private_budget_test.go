package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// Test-only deterministic clock. Advance fires actual production budget timer
// callbacks outside the clock lock; there is no900s wall-clock sleep or global
// hook. Context cancellation and engine clear paths remain real Go code.
type rootGrantsClock44 struct {
	mu     sync.Mutex
	now    time.Time
	timers []*rootGrantsTimer44
}
type rootGrantsTimer44 struct {
	clock  *rootGrantsClock44
	at     time.Time
	f      func()
	active bool
}

func rootGrantsNewClock44() *rootGrantsClock44 {
	// Sample only the epoch so a forbidden stdlib nested120s deadline would
	// actually shorten the observed budget instead of hiding behind a past
	// fixed date. Every elapsed interval/timer thereafter is fake and explicit.
	return &rootGrantsClock44{now: time.Now().UTC()}
}
func (c *rootGrantsClock44) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *rootGrantsClock44) AfterFunc(d time.Duration, f func()) rootGrantsTimer {
	c.mu.Lock()
	t := &rootGrantsTimer44{clock: c, at: c.now.Add(d), f: f, active: true}
	c.timers = append(c.timers, t)
	due := d <= 0
	if due {
		t.active = false
	}
	c.mu.Unlock()
	if due {
		f()
	}
	return t
}
func (t *rootGrantsTimer44) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (c *rootGrantsClock44) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, timer := range c.timers {
		if timer.active && !timer.at.After(c.now) {
			timer.active = false
			due = append(due, timer.f)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}
func (c *rootGrantsClock44) TimerCount() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.timers) }

type rootGrantsTimedLines44 struct {
	base      *rootGrantsLines28
	clock     *rootGrantsClock44
	advanceAt int
	advance   time.Duration
	deadlines []time.Time
	budgets   []*rootGrantsBudget
}

func (l *rootGrantsTimedLines44) observe(ctx context.Context) {
	d, _ := ctx.Deadline()
	l.deadlines = append(l.deadlines, d)
	b, _ := ctx.Value(rootGrantsBudgetKey{}).(*rootGrantsBudget)
	l.budgets = append(l.budgets, b)
}
func (l *rootGrantsTimedLines44) prompt(ctx context.Context, out []byte) error {
	l.observe(ctx)
	return l.base.prompt(ctx, out)
}
func (l *rootGrantsTimedLines44) readLine(ctx context.Context, max int) ([]byte, error) {
	l.observe(ctx)
	if l.base.reads+1 == l.advanceAt {
		l.clock.Advance(l.advance)
	}
	return l.base.readLine(ctx, max)
}
func rootGrantsBudgetSession44(t *testing.T, parent context.Context, clock *rootGrantsClock44) *RootGrantsPrivateSession {
	t.Helper()
	s, err := openRootGrantsPrivateWithClock(parent, rootGrantsRequest44(t, "keyvault-recovery/2"), clock)
	if err != nil {
		t.Fatal("valid public fixture budget refused")
	}
	t.Cleanup(s.Close)
	return s
}
func rootGrantsAwaitClear44(t *testing.T, e *rootGrantsPrivateEngine) {
	t.Helper()
	select {
	case <-e.state.cleared:
	case <-time.After(2 * time.Second):
		t.Fatal("actual deadline/cancel clear callback did not complete")
	}
	if rootGrantsEnginePrepared28(e) != nil {
		t.Fatal("closed engine retained preparation")
	}
}
func rootGrantsCheckBudget44(t *testing.T, s *RootGrantsPrivateSession, deadline time.Time) {
	t.Helper()
	for _, ctx := range []context.Context{s.ctx, s.engine.state.ctx} {
		d, ok := ctx.Deadline()
		if !ok || d != deadline {
			t.Fatal("engine/facade changed original absolute deadline")
		}
	}
	ctx, stop, err := rootGrantsInputBudget(s.engine.state.ctx)
	if err != nil {
		t.Fatal("terminal adapter budget refused before deadline")
	}
	defer stop()
	d, ok := ctx.Deadline()
	if !ok || d != deadline || ctx.Value(rootGrantsBudgetKey{}) != s.ctx.Value(rootGrantsBudgetKey{}) {
		t.Fatal("terminal adapter replaced budget")
	}
}

// Claim: actual constructor/adapter/numbered reader/engine/seal paths share ONE
// 900s budget. Input entered after120s is valid; full published-fixture sequence
// completes at900s-1ns, copies do not renew it, and facade refuses at900s+1ns.
// Limits: private pure adapter seam, software seal; no tty/native/C copy tests.
func TestRootGrantsBudget44FullSequence(t *testing.T) {
	clock := rootGrantsNewClock44()
	start := clock.Now()
	s := rootGrantsBudgetSession44(t, context.Background(), clock)
	deadline := start.Add(900 * time.Second)
	rootGrantsCheckBudget44(t, s, deadline)
	clock.Advance(121 * time.Second) // would fail the obsolete nested120s cap
	rootGrantsCheckBudget44(t, s, deadline)
	lines := &rootGrantsTimedLines44{base: &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}, clock: clock, advanceAt: 12, advance: 779*time.Second - time.Nanosecond}
	view, err := rootGrantsPrepare44(s, lines)
	if err != nil || clock.Now() != deadline.Add(-time.Nanosecond) {
		t.Fatal("full delayed numbered input refused before900s")
	}
	for i, d := range lines.deadlines {
		if d != deadline || lines.budgets[i] != s.ctx.Value(rootGrantsBudgetKey{}) {
			t.Fatal("reader renewed/replaced absolute budget")
		}
	}
	rootGrantsReturnedCleared28(t, lines.base)
	owned := rootGrantsEnginePrepared28(s.engine)
	for i := 0; i < 3; i++ {
		if err := s.check(); err != nil {
			t.Fatal("live public-copy check refused")
		}
		if raw, err := json.Marshal(view); err != nil || len(raw) == 0 {
			t.Fatal("public copy failed")
		}
		rootGrantsCheckBudget44(t, s, deadline)
	}
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	sealed, err := s.Seal(r.WrappingPoint, []byte{1})
	if err != nil || len(sealed.Record) == 0 || len(sealed.Envelope) == 0 {
		t.Fatal("software sequence failed just before900s")
	}
	rootGrantsPreparedCleared28(t, owned)
	if clock.TimerCount() != 1 {
		t.Fatal("phase installed another deadline timer")
	}
	clock.Advance(2 * time.Nanosecond)
	rootGrantsWantRefusal(t, s.check(), "timeout")
	if result, err := s.Seal(r.WrappingPoint, []byte{1}); err == nil || len(result.Record)+len(result.Envelope) != 0 {
		t.Fatal("post-deadline phase returned sealed data")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
}

// Claim: fake clock fires the ACTUAL timer/cancellation/clear path of an
// abandoned prepared engine at900s; all later input/engine/facade operations
// refuse timeout and owned scalar/lines are cleared. Crossing900 during input
// returns no phrase/preparation. No synthetic assertion substitutes for cleanup.
// Limits: no actual tty/native/owner operation; bounded2s cleanup scheduling only.
func TestRootGrantsBudget44ExpiryAndInput(t *testing.T) {
	clock := rootGrantsNewClock44()
	s := rootGrantsBudgetSession44(t, context.Background(), clock)
	f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}
	if _, err := rootGrantsPrepare44(s, f); err != nil {
		t.Fatal("paired valid numbered input failed")
	}
	owned := rootGrantsEnginePrepared28(s.engine)
	clock.Advance(900 * time.Second)
	rootGrantsAwaitClear44(t, s.engine)
	rootGrantsPreparedCleared28(t, owned)
	rootGrantsWantRefusal(t, s.engine.startInput(), "timeout")
	words := []byte(recoveryFixturePhrase)
	if _, err := s.engine.finishInput(words); err == nil {
		t.Fatal("expired engine accepted input")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
	if !bytes.Equal(words, make([]byte, len(words))) {
		t.Fatal("expired completion retained owned input")
	}
	random := &rootGrantsRandom28{}
	if _, err := s.engine.sealWithRandom(nil, nil, random); err == nil || random.calls != 0 {
		t.Fatal("expired engine reached random")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
	if _, err := OpenRootGrantsPrivate(s.ctx, rootGrantsRequest44(t, "keyvault-recovery/1")); err == nil {
		t.Fatal("expired caller context reopened budget")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
	if _, _, err := rootGrantsInputBudget(s.ctx); err == nil {
		t.Fatal("adapter renewed expired budget")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
	if phrase, err := readRootGrantsNumbered(s.ctx, &rootGrantsLines28{}); err == nil || len(phrase) != 0 {
		t.Fatal("expired reader returned phrase")
	} else {
		rootGrantsWantRefusal(t, err, "timeout")
	}
	clock2 := rootGrantsNewClock44()
	q := rootGrantsBudgetSession44(t, context.Background(), clock2)
	lines := &rootGrantsTimedLines44{base: &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}, clock: clock2, advanceAt: 12, advance: 900*time.Second + time.Nanosecond}
	view, err := rootGrantsPrepare44(q, lines)
	rootGrantsWantRefusal(t, err, "timeout")
	if view != (RootGrantsPreparationPublic{}) {
		t.Fatal("expired numbered reader prepared a key")
	}
	rootGrantsAwaitClear44(t, q.engine)
	rootGrantsReturnedCleared28(t, lines.base)
}

type rootGrantsEarlierParent44 struct {
	context.Context
	deadline time.Time
}

func (c rootGrantsEarlierParent44) Deadline() (time.Time, bool) { return c.deadline, true }

// Claim: earlier caller deadline is honored by the real budget timer, actual
// cancellation clears private state, and a derived cancel/signal-style context
// preserves timeout classification15 rather than14; EOF remains input_canceled20.
// Limits: no actual signal delivery, tty, C numeric mapper or native policy.
func TestRootGrantsBudget44EarlierCancelAndCodes(t *testing.T) {
	clock := rootGrantsNewClock44()
	parent := rootGrantsEarlierParent44{Context: context.Background(), deadline: clock.Now().Add(300 * time.Second)}
	s := rootGrantsBudgetSession44(t, parent, clock)
	rootGrantsCheckBudget44(t, s, parent.deadline)
	clock.Advance(300*time.Second + time.Nanosecond)
	rootGrantsAwaitClear44(t, s.engine)
	rootGrantsWantRefusal(t, s.check(), "timeout")
	clock2 := rootGrantsNewClock44()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := rootGrantsBudgetSession44(t, ctx, clock2)
	if _, err := rootGrantsPrepare44(q, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}); err != nil {
		t.Fatal("paired valid preparation failed")
	}
	owned := rootGrantsEnginePrepared28(q.engine)
	cancel()
	rootGrantsAwaitClear44(t, q.engine)
	rootGrantsPreparedCleared28(t, owned)
	rootGrantsWantRefusal(t, q.check(), "canceled")
	clock3 := rootGrantsNewClock44()
	r := rootGrantsBudgetSession44(t, context.Background(), clock3)
	derived, stop := context.WithCancel(r.ctx)
	defer stop()
	wrapped := rootGrantsBudgetView(derived)
	clock3.Advance(901 * time.Second)
	rootGrantsWantRefusal(t, rootGrantsContextError(wrapped), "timeout")
	clock4 := rootGrantsNewClock44()
	eof := rootGrantsBudgetSession44(t, context.Background(), clock4)
	_, err := rootGrantsPrepare44(eof, &rootGrantsLines28{})
	rootGrantsWantRefusal(t, rootGrantsPrivateError(err), "input_canceled")
}
