package main

import (
	"context"
	"syscall"
	"testing"
)

func hasObservation(r result, cause string) bool {
	for _, c := range r.ObservedCauses {
		if c == cause {
			return true
		}
	}
	return false
}

// The agreed precedence depends on the observed set, not its arrival order.
// Signal identities and later faults remain distinct from the frozen primary.
func TestObservedCausePrecedence(t *testing.T) {
	order := []string{"deadline", "canceled", "active-reap-refused", "exit", "success"}
	for i, want := range order {
		var r result
		for j := len(order) - 1; j >= i; j-- {
			r.observe(order[j])
			r.observe(order[j])
		}
		if primaryCause(r.ObservedCauses) != want || len(r.ObservedCauses) != len(order)-i {
			t.Fatal("cause precedence/uniqueness", r)
		}
	}
	s := &signalRecord{}
	ctx := context.WithValue(context.Background(), signalKey{}, s)
	s.record(syscall.SIGINT)
	r := result{Cause: "deadline"}
	r.observe("deadline")
	r.observeSignals(ctx)
	s.record(syscall.SIGTERM)
	s.record(syscall.SIGINT)
	r.observeSignals(ctx)
	if r.FirstSignal != "SIGINT" || r.Cause != "deadline" || !hasObservation(r, "SIGTERM") || !hasObservation(r, "SIGINT") || len(r.ObservedCauses) != 4 {
		t.Fatal("first/later signals lost or primary rewritten", r)
	}
}
