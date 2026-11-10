package grants

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Positive controls accept both late durable successes and proven no-effect
// deadline completions. Every planted invalid series fails the same evaluator
// used by the real measurement; construction retains its original thresholds.
func TestLinuxVerifierCompletionControls(t *testing.T) {
	for _, mode := range []string{"timely", "late-success", "late-safe-deadline", "all-refused", "untagged", "joined-storage", "cancelled", "unqualified", "missing-proof", "late-dispatch-proof", "missing-durable-proof", "cleanup", "incomplete", "negative", "missing", "extra"} {
		t.Run(mode, func(t *testing.T) {
			rows := make([]linuxVerifierAttemptResult, 40)
			for i := range rows {
				rows[i] = linuxVerifierAttemptResult{elapsed: time.Millisecond, measured: true, qualified: true, completionVerified: true}
			}
			pass := mode == "timely" || mode == "late-success" || mode == "late-safe-deadline"
			switch mode {
			case "late-success":
				for i := range rows {
					rows[i].elapsed = 154 * time.Millisecond
				}
			case "late-safe-deadline", "all-refused", "untagged", "joined-storage", "cancelled":
				count := 1
				if mode == "all-refused" {
					count = 40
				}
				for i := 0; i < count; i++ {
					rows[i].qualified = false
					rows[i].elapsed = 154 * time.Millisecond
					rows[i].refusal = fmt.Errorf("wrapped: %w", linuxDeadlineRefusal(ErrMUState))
				}
				if mode == "untagged" {
					rows[0].refusal = ErrMUState
				}
				if mode == "joined-storage" {
					rows[0].refusal = errors.Join(rows[0].refusal, errors.New("storage failure"))
				}
				if mode == "cancelled" {
					rows[0].refusal = context.Canceled
				}
			case "unqualified":
				rows[0].qualified = false
			case "missing-proof":
				rows[0].completionVerified = false
			case "late-dispatch-proof", "missing-durable-proof":
				rows[0].completionErr = errors.New(mode)
			case "cleanup":
				rows[0].cleanupErr = errors.New("cleanup")
			case "incomplete":
				rows[0].measured = false
			case "negative":
				rows[0].elapsed = -1
			case "missing":
				rows = rows[:39]
			case "extra":
				rows = append(rows, rows[0])
			}
			s, err := evaluateLinuxVerifierPath("final-admission", rows)
			if (err == nil) != pass {
				t.Fatalf("mode=%s summary=%+v err=%v", mode, s, err)
			}
			if mode == "late-safe-deadline" && (s.qualified != 39 || s.safeDeadlines != 1 || s.deadline != 1 || s.stats.max != 154*time.Millisecond || s.lateCompletions != 1) {
				t.Fatalf("refusal filtered or relabelled success: %+v", s)
			}
			if mode == "late-success" {
				if _, err := evaluateLinuxVerifierPath("construction+advisory", rows); err == nil {
					t.Fatal("construction timing threshold removed")
				}
			}
		})
	}
	if _, err := evaluateLinuxVerifierPath("unknown", nil); err == nil {
		t.Fatal("unknown path admitted")
	}
}

// Reopen a genuinely successful fixture, then plant bounded violations only in
// its replay projection. The proof checker must identify each intended defect;
// this checks the instrument, not storage power-loss behavior or live data.
func TestLinuxVerifierCompletionProofControls(t *testing.T) {
	g, _, _ := linuxDomainTestRig(t)
	g.dock.snapshot(g.dock.pub.id, g.dock.now.Add(-5*time.Second), []any{map[string]any{"kind": "record", "id": "sha256:" + strings.Repeat("0", 64), "from": g.dock.now.Add(-time.Second).Format(time.RFC3339)}})
	d, err := newLinuxTestAdmissionDomain(linuxDomainTestUpdate(g), map[string]MUEffect{"work.assign": g.effect})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Handle(context.Background(), g.dock.event)
	if err != nil {
		t.Fatal(err)
	}
	if err := linuxVerifierCompletionProof(g, d, out, nil, 1, true); err != nil {
		t.Fatal("positive replay proof", err)
	}
	if err := linuxVerifierCompletionProof(g, d, out, nil, 1, false); err == nil || !strings.Contains(err.Error(), "completion/effect evidence mismatch") {
		t.Fatal("late dispatch plant undetected", err)
	}
	for _, mode := range []string{"mark", "timestamp", "union", "original", "nonce", "intent", "outcome"} {
		t.Run(mode, func(t *testing.T) {
			s := muOpen(t, g.config.State, g.config.Binding)
			defer s.close()
			want := ""
			switch mode {
			case "mark":
				delete(s.highWater, d.state.observations[0].Signer)
				want = "missing signer observations"
			case "timestamp":
				s.highWater[d.state.observations[0].Signer] = time.Time{}
				want = "signer high-water mismatch"
			case "union":
				for signer := range s.unions {
					clear(s.unions[signer])
				}
				want = "missing durable signer union"
			case "original":
				for id := range s.verificationIDs {
					s.verificationIDs[id] = []byte("wrong")
					break
				}
				want = "verification original mismatch"
			case "nonce":
				clear(s.nonces)
				want = "reservation/nonce/once hold mismatch"
			case "intent":
				for _, use := range s.reservations {
					use.intent = false
				}
				want = "durable intent/outcome or held use mismatch"
			case "outcome":
				for _, use := range s.reservations {
					use.complete = false
				}
				want = "durable intent/outcome or held use mismatch"
			}
			err := linuxVerifierCompletionJournalProof(s, d, out, true)
			if err == nil || err.Error() != want {
				t.Fatalf("plant=%s expected=%q err=%v", mode, want, err)
			}
		})
	}
}
