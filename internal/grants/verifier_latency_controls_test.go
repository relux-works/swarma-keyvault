package grants

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The same collector and evaluator drive the real gate. Counters below witness
// execution and cleanup, independently of the lengths reported by the gate.
func TestLinuxVerifierAttemptControls(t *testing.T) {
	for _, plantedPath := range []string{"", "construction+advisory", "final-admission"} {
		t.Run("early-refusal-"+plantedPath, func(t *testing.T) {
			calls, cleanups := map[string][]int{}, map[string][]int{}
			want := map[string][]linuxVerifierAttemptResult{}
			got := collectLinuxVerifierAttempts(func(path string, i int) linuxVerifierAttemptResult {
				calls[path] = append(calls[path], i)
				defer func() { cleanups[path] = append(cleanups[path], i) }()
				r := linuxVerifierAttemptResult{elapsed: time.Duration(20+i) * time.Millisecond, measured: true, qualified: true}
				if path == plantedPath && i == 1 {
					r.elapsed, r.qualified, r.refusal = 154*time.Millisecond, false, linuxDeadlineRefusal(ErrMUState)
				}
				want[path] = append(want[path], r)
				return r
			})
			if !reflect.DeepEqual(got, want) {
				t.Fatal("results discarded, replaced or changed")
			}
			for _, path := range linuxVerifierPaths {
				for i := 0; i < linuxVerifierSampleCount; i++ {
					if len(calls[path]) != 40 || len(cleanups[path]) != 40 || calls[path][i] != i || cleanups[path][i] != i {
						t.Fatalf("path=%s calls=%v cleanups=%v", path, calls[path], cleanups[path])
					}
				}
				s, err := evaluateLinuxVerifierAttempts(got[path])
				if (err == nil) != (path != plantedPath) || len(s.observed) != 40 {
					t.Fatalf("path=%s summary=%+v err=%v", path, s, err)
				}
				if path == plantedPath && (s.qualified != 39 || s.deadline != 1 || s.stats.max != 154*time.Millisecond) {
					t.Fatalf("refusal counted as success or lost: %+v", s)
				}
			}
			if (linuxVerifierAttemptsError(got) == nil) != (plantedPath == "") {
				t.Fatal("aggregate did not preserve failure")
			}
		})
	}
}

func TestLinuxVerifierRefusalAndQualificationControls(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Millisecond, 154 * time.Millisecond} {
		for _, tc := range []struct {
			name  string
			err   error
			class string
		}{
			{"deadline", linuxDeadlineRefusal(ErrMUState), "deadline"},
			{"wrapped-deadline", fmt.Errorf("wrapped: %w", linuxDeadlineRefusal(ErrMUState)), "deadline"},
			{"state", ErrMUState, "state"},
			{"platform", linuxVerifierRefuse("time_unavailable"), "other"},
			{"cancelled", context.Canceled, "other"},
		} {
			t.Run(tc.name+elapsed.String(), func(t *testing.T) {
				results := make([]linuxVerifierAttemptResult, 40)
				for i := range results {
					results[i] = linuxVerifierAttemptResult{elapsed: time.Millisecond, measured: true, qualified: true}
				}
				results[0] = linuxVerifierAttemptResult{elapsed: elapsed, measured: true, refusal: tc.err}
				s, err := evaluateLinuxVerifierAttempts(results)
				if err == nil || s.qualified != 39 || len(s.observed) != 40 || s.observed[0] != elapsed || linuxVerifierRefusalClass(tc.err) != tc.class {
					t.Fatalf("duration inferred cause or refusal qualified: %+v err=%v", s, err)
				}
				if s.deadline+s.state+s.other != 1 || (s.deadline == 1) != (tc.class == "deadline") || (s.state == 1) != (tc.class == "state") {
					t.Fatalf("summary relabelled refusal: %+v want class=%s", s, tc.class)
				}
			})
		}
	}
	for _, mode := range []string{"incomplete", "unqualified", "cleanup", "p95", "max", "negative", "missing", "extra"} {
		t.Run(mode, func(t *testing.T) {
			r := make([]linuxVerifierAttemptResult, 40)
			for i := range r {
				r[i] = linuxVerifierAttemptResult{elapsed: time.Millisecond, measured: true, qualified: true}
			}
			switch mode {
			case "incomplete":
				r[0].measured = false
			case "unqualified":
				r[0].qualified = false
			case "cleanup":
				r[0].cleanupErr = errors.New("cleanup failed")
			case "p95":
				for i := 0; i < 3; i++ {
					r[i].elapsed = 81 * time.Millisecond
				}
			case "max":
				r[0].elapsed = 100 * time.Millisecond
			case "negative":
				r[0].elapsed = -1
			case "missing":
				r = r[:39]
			case "extra":
				r = append(r, r[0])
			}
			if _, err := evaluateLinuxVerifierAttempts(r); err == nil {
				t.Fatal("invalid attempt series passed")
			}
		})
	}
}

func TestLinuxAdmissionDeadlineCompatibility(t *testing.T) {
	for _, original := range []error{ErrMUState, ErrMUUnknown, linuxVerifierRefuse("time_unavailable")} {
		err := linuxDeadlineRefusal(original)
		if err.Error() != original.Error() || !errors.Is(err, original) || !errors.Is(err, errLinuxAdmissionDeadline) {
			t.Fatalf("public refusal changed: %v", err)
		}
		var platform *ErrMUPlatform
		if errors.As(original, &platform) && linuxVerifierCode(err) != platform.Code {
			t.Fatal("platform code changed")
		}
	}
}

// Real fence branches, real journal writes and a deterministic clock distinguish
// cause from wall elapsed. A state defect is never relabelled just for being slow.
func TestLinuxAdmissionDeadlineCauseControls(t *testing.T) {
	for _, mode := range []string{"live-deadline", "live-cancel", "state", "missing-deadline", "missing-lease-deadline", "reserve-deadline", "late-sync"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			linuxContractScope(g.dock, "once")
			v, a, c, u := linuxCommitTestCandidate(t, g.dock)
			clock := c.clock.(*linuxTestClock)
			ctx, cancel := clock.withDeadline(context.Background(), c.deadline)
			defer cancel()
			lease := &linuxFinalAdmission{view: v, ctx: ctx, deadline: c.deadline}
			var err error
			s := muOpen(t, g.config.State, g.config.Binding)
			defer s.close()
			switch mode {
			case "live-deadline":
				clock.advance(c.deadline.Sub(clock.now()))
				_, err = lease.VerifyAdmission(v.input.Event, v.input.State.Now)
			case "live-cancel":
				cancel()
				_, err = lease.VerifyAdmission(v.input.Event, v.input.State.Now)
			case "state":
				c.complete = false
				_, err = s.reserveVerifiedUntil(u, c, c.deadline)
			case "missing-deadline":
				_, err = s.reserveVerifiedUntil(u, c, time.Time{})
			case "missing-lease-deadline":
				lease.deadline = time.Time{}
				_, err = lease.VerifyAdmission(v.input.Event, v.input.State.Now)
			case "reserve-deadline":
				clock.advance(c.deadline.Sub(clock.now()))
				_, err = s.reserveVerifiedUntil(u, c, c.deadline)
			case "late-sync":
				s.sync = func(f *os.File) error {
					if err := f.Sync(); err != nil {
						return err
					}
					clock.advance(c.deadline.Sub(clock.now()))
					return nil
				}
				_, err = s.reserveVerifiedUntil(u, c, c.deadline)
			}
			wantDeadline := mode == "live-deadline" || mode == "reserve-deadline" || mode == "late-sync"
			if err == nil || !errors.Is(err, ErrMUState) || errors.Is(err, errLinuxAdmissionDeadline) != wantDeadline || g.calls != 0 {
				t.Fatalf("mode=%s err=%v deadline=%v effects=%d", mode, err, errors.Is(err, errLinuxAdmissionDeadline), g.calls)
			}
			if mode == "late-sync" && (len(s.allowances) != 1 || len(s.verificationIDs) != len(a.plan.originals)) {
				t.Fatal("late reservation refunded")
			}
		})
	}
}

// Exercise the public production route with a private observer and real crypto.
// The deterministic admission clock grants no synthetic latency qualification.
func TestLinuxAdmissionPhaseEvidence(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	trace := &linuxVerifierTrace{start: time.Now()}
	ctx := context.WithValue(context.Background(), linuxAdmissionObserverKey{}, trace)
	out, err := d.Handle(ctx, g.dock.event)
	elapsed := time.Since(trace.start)
	phases := trace.snapshot()
	if err != nil || out == nil || out.State != "succeeded" || g.calls != 1 {
		t.Fatal("positive phase fixture", err, out, g.calls)
	}
	if err := validateLinuxVerifierPhases(phases, elapsed, true); err != nil {
		t.Fatal(err)
	}
	t.Logf("elapsed_ns=%d phases=%+v", elapsed.Nanoseconds(), phases)
	for _, mode := range []string{"missing", "incomplete", "reverse", "outside", "overlap"} {
		broken := append([]linuxVerifierPhase(nil), phases...)
		switch mode {
		case "missing":
			broken = broken[:len(broken)-1]
		case "incomplete":
			broken[0].complete = false
		case "reverse":
			broken[0].end = broken[0].start - 1
		case "outside":
			broken[len(broken)-1].end = elapsed + 1
		case "overlap":
			broken[1].start = broken[0].end - 1
		}
		if validateLinuxVerifierPhases(broken, elapsed, true) == nil {
			t.Fatalf("%s trace passed", mode)
		}
	}
}

func TestLinuxAdmissionLateStateIsNotDeadline(t *testing.T) {
	g, d, _ := linuxDomainTestRig(t)
	clock := d.clock.(*linuxTestClock)
	ctx, cancel := clock.withDeadline(context.Background(), clock.now().Add(linuxProviderFinalLimit))
	defer cancel()
	deadline, _ := ctx.Deadline()
	lease := &linuxFinalAdmission{view: d.state.view, deadline: deadline, ctx: ctx}
	r := d.receiver(d.state, lease)
	// A failed open is the operative refusal. Crossing a deadline during that
	// failed operation does not prove that the deadline caused the failure.
	r.open = func(context.Context, MUStateConfig, MUBinding) (*muState, error) {
		clock.advance(154 * time.Millisecond)
		return nil, ErrMUState
	}
	out, err := r.Handle(ctx, g.dock.event)
	if err != ErrMUState || errors.Is(err, errLinuxAdmissionDeadline) || out != nil || g.calls != 0 {
		t.Fatal("late state error relabelled", out, err, g.calls)
	}
	linuxContractNoUse(t, g)
}

func TestLinuxAdmissionLockCauseControls(t *testing.T) {
	g := newLinuxCombinedRig(t)
	holder := muOpen(t, g.config.State, g.config.Binding)
	defer holder.close()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	waiter, err := os.OpenFile(filepath.Join(g.config.State.Directory, "mu.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	if err := lockStateFile(expired, waiter); !errors.Is(err, errStateLockUnavailable) || !errors.Is(err, errLinuxAdmissionDeadline) {
		t.Fatal("operative lock deadline not tagged", err)
	}
	_, err = openMUState(expired, g.config.State, g.config.Binding)
	if !errors.Is(err, ErrMUState) || !errors.Is(err, errLinuxAdmissionDeadline) {
		t.Fatal("lock deadline cause lost", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = openMUState(cancelled, g.config.State, g.config.Binding)
	if !errors.Is(err, ErrMUState) || errors.Is(err, errLinuxAdmissionDeadline) {
		t.Fatal("cancellation relabelled", err)
	}
	// An actual flock failure (EBADF) remains unrelated even when the context
	// is also expired. Looking at ctx.Err after a generic lock error is unsafe.
	file, err := os.Open(g.config.State.Directory)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	err = lockStateFile(expired, file)
	mapped := linuxAdmissionRefusal(err, ErrMUState)
	if !errors.Is(mapped, ErrMUState) || errors.Is(mapped, errLinuxAdmissionDeadline) {
		t.Fatal("flock defect relabelled", mapped)
	}
}
