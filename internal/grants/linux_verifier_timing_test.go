//go:build !race

package grants

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Fixture preparation is outside timing. Every path attempt owns fresh keys,
// signed records, journal and cleanup. No warmup, retries or replacement samples.
func TestLinuxRealVerifierP95(t *testing.T) {
	t.Logf("fixture: fresh ephemeral P-256 GrantRoot/publisher, Ed25519 service/revoker/agent; signed publisher, grant, author attestation, message, two revocation snapshots; once work.assign; A1; empty journal; required_samples=%d p95_limit_ns=%d max_exclusive_ns=%d p95=nearest-rank runs=1 retries=0", linuxVerifierSampleCount, linuxVerifierP95Limit.Nanoseconds(), linuxVerifierMaxExclusive.Nanoseconds())
	results := collectLinuxVerifierAttempts(func(path string, i int) linuxVerifierAttemptResult {
		r := linuxVerifierAttemptResult{}
		var fixture string
		ok := t.Run(fmt.Sprintf("%s/%02d", path, i), func(t *testing.T) {
			// Fatal fixture setup errors are confined to this attempt. The collector
			// still invokes every remaining path/index and records it as incomplete.
			fixture = t.TempDir()
			root, err := filepath.EvalSymlinks(fixture)
			if err != nil {
				t.Fatal(err)
			}
			g := newLinuxCombinedRigAt(t, filepath.Join(root, "state"))
			linuxContractScope(g.dock, "once")
			if path == "construction+advisory" {
				in := linuxProviderTestInput(g.dock)
				start := time.Now()
				v, err := newLinuxProviderView(in)
				var a LinuxAdmission
				if err == nil {
					a, err = v.advisory()
				}
				r.elapsed, r.measured, r.refusal = time.Since(start), true, err
				if err == nil {
					_, realClock := v.clock.(linuxRealClock)
					r.qualified = realClock && len(a.Snapshots) == 2 && len(a.plan.originals) == 2
				}
			} else {
				// Production stages the domain before the final interval. Handle
				// starts its unchanged 100ms fence before contention and journal open.
				d, err := NewLinuxAdmissionDomain(linuxDomainTestUpdate(g), map[string]MUEffect{"work.assign": g.effect})
				if err != nil {
					r.refusal = err
					return
				}
				_, realClock := d.clock.(linuxRealClock)
				trace := &linuxVerifierTrace{}
				ctx := context.WithValue(context.Background(), linuxAdmissionObserverKey{}, trace)
				trace.start = time.Now()
				out, err := d.Handle(ctx, g.dock.event)
				r.elapsed, r.measured, r.refusal = time.Since(trace.start), true, err
				r.qualified = err == nil && realClock && out != nil && out.State == "succeeded" && g.calls == 1
				r.phases = trace.snapshot()
				if phaseErr := validateLinuxVerifierPhases(r.phases, r.elapsed, r.qualified); phaseErr != nil {
					r.qualified = false
					r.refusal = errors.Join(r.refusal, phaseErr)
				}
				t.Logf("outcome=%v effect_calls=%d phases=%+v", out, g.calls, r.phases)
			}
		})
		// TempDir cleanup has already run, including after fixture Fatal. Verify
		// removal separately; a cleanup/test failure cannot become qualification.
		if fixture != "" {
			if _, err := os.Lstat(fixture); !errors.Is(err, os.ErrNotExist) {
				r.cleanupErr = fmt.Errorf("fixture removal not confirmed: %v", err)
			}
		} else {
			r.cleanupErr = errors.New("fixture root unavailable; cleanup unconfirmed")
		}
		if !ok {
			r.qualified = false
			r.refusal = errors.Join(r.refusal, errors.New("fixture or cleanup failed"))
		}
		t.Logf("sample=%d path=%s measured=%t elapsed_ns=%d qualified=%t refusal_class=%s refusal=%v cleanup_error=%v phases=%+v", i, path, r.measured, r.elapsed.Nanoseconds(), r.qualified, linuxVerifierRefusalClass(r.refusal), r.refusal, r.cleanupErr, r.phases)
		return r
	})
	for _, path := range linuxVerifierPaths {
		s, err := evaluateLinuxVerifierAttempts(results[path])
		t.Logf("path=%s attempts=%d measured_samples=%d qualified_samples=%d required_samples=%d deadline_refusals=%d state_refusals=%d other_refusals=%d incomplete=%d cleanup_failures=%d observed_rank=%d observed_p95_ns=%d observed_max_ns=%d p95_limit_ns=%d max_exclusive_ns=%d observed_values_ns=%v", path, len(results[path]), len(s.observed), s.qualified, linuxVerifierSampleCount, s.deadline, s.state, s.other, s.incomplete, s.cleanupFailures, s.stats.rank, s.stats.p95.Nanoseconds(), s.stats.max.Nanoseconds(), linuxVerifierP95Limit.Nanoseconds(), linuxVerifierMaxExclusive.Nanoseconds(), durationNanoseconds(s.observed))
		if err != nil {
			t.Logf("path=%s FAIL: %v", path, err)
		}
	}
	if err := linuxVerifierAttemptsError(results); err != nil {
		t.Errorf("real verifier gate: %v (100ms product fence unchanged)", err)
	}
}

func durationNanoseconds(values []time.Duration) []int64 {
	out := make([]int64, len(values))
	for i, d := range values {
		out[i] = d.Nanoseconds()
	}
	return out
}
