//go:build !race

package grants

import (
	"context"
	"math"
	"sort"
	"testing"
	"time"
)

// Race runs check the same real cryptography and admission logic with explicit
// test time. This separate gate measures the shipping real-clock path without
// instrumentation. All samples count, including slow samples; there are no
// warmup exclusions or retries. Nearest-rank p95 is sorted[ceil(.95*N)-1].
func TestLinuxRealVerifierP95(t *testing.T) {
	const samples = 40
	const threshold = 60 * time.Millisecond // 40ms margin below the fixed 100ms fence
	advisory := make([]time.Duration, 0, samples)
	final := make([]time.Duration, 0, samples)
	t.Logf("fixture: fresh ephemeral P-256 GrantRoot/publisher, Ed25519 service/revoker/agent; signed publisher, grant, author attestation, message, two revocation snapshots; once work.assign; A1; empty journal; samples=%d threshold_ns=%d p95=nearest-rank", samples, threshold.Nanoseconds())
	for i := 0; i < samples; i++ {
		// Expensive key generation/signing and filesystem fixture creation are outside
		// timing. Provider copy, verifier construction and actual signed admission are
		// inside the advisory interval. No authorization or crypto is mocked.
		g := newLinuxCombinedRig(t)
		linuxContractScope(g.dock, "once")
		in := linuxProviderTestInput(g.dock)
		start := time.Now()
		v, err := newLinuxProviderView(in)
		if err != nil {
			t.Fatal(err)
		}
		a, verifyErr := v.advisory()
		end := time.Now()
		elapsed := end.Sub(start)
		advisory = append(advisory, elapsed)
		t.Logf("sample=%d path=construction+advisory start=%s end=%s elapsed_ns=%d", i, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano), elapsed.Nanoseconds())
		if verifyErr != nil || len(a.Snapshots) != 2 || len(a.plan.originals) != 2 {
			t.Fatal("real signed advisory", verifyErr)
		}
		if _, ok := v.clock.(linuxRealClock); !ok {
			t.Fatal("production provider clock changed")
		}
		// Stage the domain outside the final-admission interval, as production does.
		// Handle starts its real 100ms deadline before lock/open and includes the
		// actual verifier, original-history reservation, intent, effect and outcome.
		d, err := NewLinuxAdmissionDomain(linuxDomainTestUpdate(g), map[string]MUEffect{"work.assign": g.effect})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.clock.(linuxRealClock); !ok {
			t.Fatal("public constructor clock changed")
		}
		start = time.Now()
		out, handleErr := d.Handle(context.Background(), g.dock.event)
		end = time.Now()
		elapsed = end.Sub(start)
		final = append(final, elapsed)
		t.Logf("sample=%d path=final-admission start=%s end=%s elapsed_ns=%d", i, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano), elapsed.Nanoseconds())
		if handleErr != nil || out == nil || out.State != "succeeded" || g.calls != 1 {
			t.Fatal("real final admission", handleErr, out, g.calls)
		}
	}
	for _, series := range []struct {
		name   string
		values []time.Duration
	}{{"construction+advisory", advisory}, {"final-admission", final}} {
		ordered := append([]time.Duration(nil), series.values...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
		rank := int(math.Ceil(.95 * float64(len(ordered))))
		p95 := ordered[rank-1]
		t.Logf("path=%s n=%d rank=%d p95_ns=%d max_ns=%d threshold_ns=%d values_ns=%v", series.name, len(ordered), rank, p95.Nanoseconds(), ordered[len(ordered)-1].Nanoseconds(), threshold.Nanoseconds(), durationNanoseconds(series.values))
		if p95 >= threshold {
			t.Errorf("%s real verifier p95 %s must be below %s (100ms product fence unchanged)", series.name, p95, threshold)
		}
	}
}
func durationNanoseconds(values []time.Duration) []int64 {
	out := make([]int64, len(values))
	for i, d := range values {
		out[i] = d.Nanoseconds()
	}
	return out
}
