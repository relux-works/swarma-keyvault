package grants

import (
	"context"
	"time"
)

// The clock is private to the admission implementation. Public constructors
// always install linuxRealClock; only same-package tests supply another clock.
// It measures local fences, never qualified authority or signed evidence time.
type linuxAdmissionClock interface {
	now() time.Time
	withDeadline(context.Context, time.Time) (context.Context, context.CancelFunc)
}
type linuxRealClock struct{}

func (linuxRealClock) now() time.Time { return time.Now() }
func (linuxRealClock) withDeadline(ctx context.Context, at time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, at)
}
func linuxClock(c linuxAdmissionClock) linuxAdmissionClock {
	if c == nil {
		return linuxRealClock{}
	}
	return c
}
