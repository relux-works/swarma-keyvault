package grants

import (
	"context"
	"errors"
)

// A private cause augments the existing refusal without changing its text,
// sentinel chain or platform code. Only an actual deadline fence tags a cause;
// a slow return or a generic state refusal is not evidence of deadline expiry.
var errLinuxAdmissionDeadline = errors.New("linux-final-admission-deadline")

type linuxDeadlineError struct{ refusal error }

func (e *linuxDeadlineError) Error() string        { return e.refusal.Error() }
func (e *linuxDeadlineError) Unwrap() error        { return e.refusal }
func (e *linuxDeadlineError) Is(target error) bool { return target == errLinuxAdmissionDeadline }
func linuxDeadlineRefusal(refusal error) error     { return &linuxDeadlineError{refusal: refusal} }

// Preserve a tagged cause where an existing boundary maps an internal error to
// a public refusal. Untagged storage/state errors keep exactly that refusal.
func linuxAdmissionRefusal(cause, refusal error) error {
	if errors.Is(cause, errLinuxAdmissionDeadline) {
		return linuxDeadlineRefusal(refusal)
	}
	return refusal
}

// No public constructor installs an observer. Same-package tests attach one to
// their request context; production has no collector, global hook or log sink.
type linuxAdmissionObserver interface{ begin(string) func() }
type linuxAdmissionObserverKey struct{}

func linuxAdmissionPhase(ctx context.Context, name string) func() {
	if ctx != nil {
		if observer, ok := ctx.Value(linuxAdmissionObserverKey{}).(linuxAdmissionObserver); ok {
			return observer.begin(name)
		}
	}
	return func() {}
}
