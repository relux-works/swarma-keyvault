package keyvault

import (
	"context"
	"time"
)

const rootGrantsAttemptLimit = 900 * time.Second

// Clock injection is package-private test scope, not a production option,
// global hook or secret callback. Production always uses the actual clock.
type rootGrantsTimer interface{ Stop() bool }
type rootGrantsClock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) rootGrantsTimer
}
type rootGrantsWallClock struct{}

func (rootGrantsWallClock) Now() time.Time { return time.Now() }
func (rootGrantsWallClock) AfterFunc(d time.Duration, f func()) rootGrantsTimer {
	return time.AfterFunc(d, f)
}

type rootGrantsBudgetKey struct{}
type rootGrantsBudget struct {
	clock    rootGrantsClock
	deadline time.Time
	cancel   context.CancelCauseFunc
}
type rootGrantsTimedContext struct {
	context.Context
	budget *rootGrantsBudget
}

func (c *rootGrantsTimedContext) Deadline() (time.Time, bool) {
	if earlier, ok := c.Context.Deadline(); ok && earlier.Before(c.budget.deadline) {
		return earlier, true
	}
	return c.budget.deadline, true
}
func (c *rootGrantsTimedContext) Value(key any) any {
	if _, ok := key.(rootGrantsBudgetKey); ok {
		return c.budget
	}
	return c.Context.Value(key)
}
func (c *rootGrantsTimedContext) Err() error {
	// Also enforce the boundary when a timer callback has not been scheduled
	// yet. CancelCause preserves an already earlier parent cancellation.
	if !c.budget.clock.Now().Before(c.budget.deadline) {
		c.budget.cancel(context.DeadlineExceeded)
	}
	if c.Context.Err() == nil {
		return nil
	}
	if context.Cause(c.Context) == context.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

func rootGrantsBudgetView(ctx context.Context) context.Context {
	if ctx != nil {
		if b, ok := ctx.Value(rootGrantsBudgetKey{}).(*rootGrantsBudget); ok {
			return &rootGrantsTimedContext{Context: ctx, budget: b}
		}
	}
	return ctx
}

// Sample Err once so a deadline between two reads cannot be mislabeled as
// cancellation. Existing unrelated recovery context/error contracts are intact.
func rootGrantsBudgetError(ctx context.Context) error {
	if ctx == nil {
		return recoveryRefuse("invalid_arguments")
	}
	switch ctx.Err() {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return recoveryRefuse("timeout")
	default:
		return recoveryRefuse("canceled")
	}
}

func rootGrantsNewBudget(ctx context.Context, clock rootGrantsClock) (context.Context, context.CancelFunc, error) {
	ctx = rootGrantsBudgetView(ctx)
	if err := rootGrantsBudgetError(ctx); err != nil {
		return nil, nil, err
	}
	if clock == nil {
		return nil, nil, recoveryRefuse("invalid_arguments")
	}
	if _, ok := ctx.Value(rootGrantsBudgetKey{}).(*rootGrantsBudget); ok {
		return ctx, func() {}, nil // inherit EXACT absolute budget; never renew
	}
	now := clock.Now()
	deadline := now.Add(rootGrantsAttemptLimit)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	base, cancel := context.WithCancelCause(ctx)
	b := &rootGrantsBudget{clock: clock, deadline: deadline, cancel: cancel}
	child := &rootGrantsTimedContext{Context: base, budget: b}
	timer := clock.AfterFunc(deadline.Sub(clock.Now()), func() { cancel(context.DeadlineExceeded) })
	context.AfterFunc(base, func() { timer.Stop() })
	stop := func() { cancel(context.Canceled); timer.Stop() }
	if err := rootGrantsBudgetError(child); err != nil {
		stop()
		return nil, nil, err
	}
	return child, stop, nil
}

// The actual engine, terminal adapter and numbered reader use this same seam.
// Existing marked contexts preserve the earlier caller deadline too. No tty
// must be opened to test propagation through this adapter boundary.
func rootGrantsInputBudget(ctx context.Context) (context.Context, context.CancelFunc, error) {
	return rootGrantsNewBudget(ctx, rootGrantsWallClock{})
}
