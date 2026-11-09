package grants

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

const (
	linuxVerifierSampleCount  = 40
	linuxVerifierP95Limit     = 80 * time.Millisecond
	linuxVerifierMaxExclusive = 100 * time.Millisecond
)

type linuxVerifierTimingStats struct {
	count, rank int
	p95, max    time.Duration
}

// classifyLinuxVerifierTiming consumes every raw duration once. Durations are
// integer nanoseconds: NaN and infinity cannot be represented by this API.
// Missing/extra or negative samples refuse. Unsorted input is sorted on a copy.
// Nearest-rank p95 = sorted[ceil(95*N/100)-1], exactly rank 38 for N=40.
func classifyLinuxVerifierTiming(values []time.Duration) (linuxVerifierTimingStats, error) {
	s := linuxVerifierTimingStats{count: len(values)}
	if s.count != linuxVerifierSampleCount {
		return s, fmt.Errorf("actual samples %d, require exactly %d", s.count, linuxVerifierSampleCount)
	}
	for _, v := range values {
		if v < 0 {
			return s, fmt.Errorf("negative timing sample")
		}
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	s.rank = (95*s.count + 99) / 100
	s.p95, s.max = ordered[s.rank-1], ordered[s.count-1]
	if s.p95 > linuxVerifierP95Limit || s.max >= linuxVerifierMaxExclusive {
		return s, fmt.Errorf("p95 %s must be <= %s and max %s must be < %s", s.p95, linuxVerifierP95Limit, s.max, linuxVerifierMaxExclusive)
	}
	return s, nil
}

func TestLinuxVerifierTimingCriterion(t *testing.T) {
	filled := func(n int, v time.Duration) []time.Duration {
		a := make([]time.Duration, n)
		for i := range a {
			a[i] = v
		}
		return a
	}
	cases := []struct {
		name     string
		values   []time.Duration
		pass     bool
		p95, max time.Duration
	}{
		{"80ms-inclusive", filled(40, 80*time.Millisecond), true, 80 * time.Millisecond, 80 * time.Millisecond},
		{"80ms-plus-nanosecond", filled(40, 80*time.Millisecond+1), false, 80*time.Millisecond + 1, 80*time.Millisecond + 1},
		{"zero-valid", filled(40, 0), true, 0, 0},
		{"missing", nil, false, 0, 0},
		{"39-refused", filled(39, 0), false, 0, 0},
		{"41-refused", filled(41, 0), false, 0, 0},
		{"negative-refused", filled(40, -1), false, 0, 0},
		{"largest-finite-duration", filled(40, time.Duration(1<<63-1)), false, time.Duration(1<<63 - 1), time.Duration(1<<63 - 1)},
	}
	for _, max := range []time.Duration{100*time.Millisecond - 1, 100 * time.Millisecond, 100*time.Millisecond + 1} {
		a := filled(40, 80*time.Millisecond)
		a[0] = max
		a[1] = max
		cases = append(cases, struct {
			name     string
			values   []time.Duration
			pass     bool
			p95, max time.Duration
		}{fmt.Sprintf("unsorted-max-%dns", max), a, max < 100*time.Millisecond, 80 * time.Millisecond, max})
	}
	// Three high samples move rank 38 above 80ms; two do not.
	a := filled(40, 80*time.Millisecond)
	a[0] = 81 * time.Millisecond
	a[1] = 81 * time.Millisecond
	a[2] = 81 * time.Millisecond
	cases = append(cases, struct {
		name     string
		values   []time.Duration
		pass     bool
		p95, max time.Duration
	}{"rank-38", a, false, 81 * time.Millisecond, 81 * time.Millisecond})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := append([]time.Duration(nil), c.values...)
			got, err := classifyLinuxVerifierTiming(c.values)
			if (err == nil) != c.pass {
				t.Fatalf("stats=%+v err=%v want pass=%v", got, err, c.pass)
			}
			if got.count != len(c.values) || got.p95 != c.p95 || got.max != c.max {
				t.Fatalf("stats=%+v", got)
			}
			if got.rank != 0 && got.rank != 38 {
				t.Fatalf("rank=%d", got.rank)
			}
			if !reflect.DeepEqual(before, c.values) {
				t.Fatal("input samples modified")
			}
		})
	}
}
