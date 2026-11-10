package grants

import (
	"errors"
	"fmt"
	"time"
)

var linuxVerifierPaths = []string{"construction+advisory", "final-admission"}

type linuxVerifierAttemptResult struct {
	elapsed             time.Duration
	measured, qualified bool
	refusal, cleanupErr error
	phases              []linuxVerifierPhase
	completionVerified  bool
	completionErr       error
}

// No retry, short circuit, filtering or replacement. Each invocation owns its
// fixture and cleanup; the returned slice preserves every actual outcome.
func collectLinuxVerifierAttempts(run func(string, int) linuxVerifierAttemptResult) map[string][]linuxVerifierAttemptResult {
	results := make(map[string][]linuxVerifierAttemptResult)
	for i := 0; i < linuxVerifierSampleCount; i++ {
		for _, path := range linuxVerifierPaths {
			results[path] = append(results[path], run(path, i))
		}
	}
	return results
}

type linuxVerifierAttemptSummary struct {
	observed                                                       []time.Duration
	stats                                                          linuxVerifierTimingStats
	qualified, deadline, state, other, incomplete, cleanupFailures int
	safeDeadlines, lateCompletions, invalidCompletions             int
}

func linuxVerifierRefusalClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, errLinuxAdmissionDeadline):
		return "deadline"
	case errors.Is(err, ErrMUState):
		return "state"
	default:
		return "other"
	}
}

func summarizeLinuxVerifierAttempts(results []linuxVerifierAttemptResult) linuxVerifierAttemptSummary {
	var s linuxVerifierAttemptSummary
	for _, r := range results {
		if r.measured {
			s.observed = append(s.observed, r.elapsed)
		} else {
			s.incomplete++
		}
		if r.measured && r.qualified && r.refusal == nil && r.cleanupErr == nil {
			s.qualified++
		}
		if r.cleanupErr != nil {
			s.cleanupFailures++
		}
		switch linuxVerifierRefusalClass(r.refusal) {
		case "deadline":
			s.deadline++
		case "state":
			s.state++
		case "other":
			s.other++
		}
	}
	return s
}

func evaluateLinuxVerifierAttempts(results []linuxVerifierAttemptResult) (linuxVerifierAttemptSummary, error) {
	s := summarizeLinuxVerifierAttempts(results)
	var timingErr error
	s.stats, timingErr = classifyLinuxVerifierTiming(s.observed)
	if len(results) != linuxVerifierSampleCount || s.qualified != linuxVerifierSampleCount || timingErr != nil {
		return s, fmt.Errorf("attempts=%d qualified=%d incomplete=%d deadline=%d state=%d other=%d cleanup_failures=%d timing=%v", len(results), s.qualified, s.incomplete, s.deadline, s.state, s.other, s.cleanupFailures, timingErr)
	}
	return s, nil
}

// A deadline completion must come from an actual private fence. A joined
// storage/cancellation/phase error must never inherit acceptance from one tag.
func linuxGenuineDeadlineCompletion(err error) bool {
	for err != nil {
		if _, joined := err.(interface{ Unwrap() []error }); joined {
			return false
		}
		if d, ok := err.(*linuxDeadlineError); ok {
			if d.refusal == ErrMUState || d.refusal == ErrMUUnknown {
				return true
			}
			p, ok := d.refusal.(*ErrMUPlatform)
			return ok && p.Code == "time_unavailable"
		}
		err = errors.Unwrap(err)
	}
	return false
}

func evaluateLinuxVerifierPath(path string, results []linuxVerifierAttemptResult) (linuxVerifierAttemptSummary, error) {
	if path == "construction+advisory" {
		return evaluateLinuxVerifierAttempts(results)
	}
	if path != "final-admission" {
		return linuxVerifierAttemptSummary{}, fmt.Errorf("unknown verifier path %q", path)
	}
	// Reuse the original accounting, but final latency is descriptive only.
	s := summarizeLinuxVerifierAttempts(results)
	for _, r := range results {
		if r.measured && r.elapsed >= linuxVerifierMaxExclusive {
			s.lateCompletions++
		}
		valid := r.measured && r.cleanupErr == nil && r.completionVerified && r.completionErr == nil
		if valid && !r.qualified && linuxGenuineDeadlineCompletion(r.refusal) {
			s.safeDeadlines++
		} else if !valid || !r.qualified || r.refusal != nil {
			s.invalidCompletions++
		}
	}
	var err error
	s.stats, err = summarizeLinuxVerifierTiming(s.observed)
	if len(results) != linuxVerifierSampleCount || s.qualified < 1 || s.invalidCompletions != 0 || s.qualified+s.safeDeadlines != linuxVerifierSampleCount || err != nil {
		return s, fmt.Errorf("attempts=%d success=%d safe_deadline=%d invalid_completion=%d incomplete=%d cleanup_failures=%d statistics=%v", len(results), s.qualified, s.safeDeadlines, s.invalidCompletions, s.incomplete, s.cleanupFailures, err)
	}
	return s, nil
}

func linuxVerifierAttemptsError(results map[string][]linuxVerifierAttemptResult) error {
	var failures []error
	for _, path := range linuxVerifierPaths {
		if _, err := evaluateLinuxVerifierPath(path, results[path]); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
		}
	}
	return errors.Join(failures...)
}

// These offsets come from monotonic time subtraction, never UTC subtraction or
// the injectable authority/admission clock. Incomplete brackets remain visible.
type linuxVerifierPhase struct {
	name       string
	start, end time.Duration
	complete   bool
}
type linuxVerifierTrace struct {
	start  time.Time
	phases []*linuxVerifierPhase
}

func (s *linuxVerifierTrace) begin(name string) func() {
	p := &linuxVerifierPhase{name: name, start: time.Since(s.start)}
	s.phases = append(s.phases, p)
	return func() { p.end, p.complete = time.Since(s.start), true }
}
func (s *linuxVerifierTrace) snapshot() []linuxVerifierPhase {
	out := make([]linuxVerifierPhase, 0, len(s.phases))
	for _, p := range s.phases {
		out = append(out, *p)
	}
	return out
}

func validateLinuxVerifierPhases(phases []linuxVerifierPhase, elapsed time.Duration, success bool) error {
	seen := map[string]bool{}
	var previous time.Duration
	for _, p := range phases {
		if !p.complete || p.start < previous || p.end < p.start || p.end > elapsed {
			return fmt.Errorf("invalid monotonic phase: %+v elapsed=%s", p, elapsed)
		}
		previous, seen[p.name] = p.end, true
	}
	if success {
		for _, name := range []string{"domain-lock", "lock/open", "replay", "verify", "reserve/fsync", "intent/fsync", "outcome/fsync"} {
			if !seen[name] {
				return fmt.Errorf("missing phase %s", name)
			}
		}
	}
	return nil
}
