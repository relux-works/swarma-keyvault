package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// A trace models adapter observations only. It does not execute a process or
// simulate native authentication as evidence of a real native implementation.
type policyTrace struct {
	t       *testing.T
	r       *Runner
	at      time.Duration
	actions []RunnerAction
	outcome Outcome
}

func trace(t *testing.T, context RunnerContext, deadline time.Duration) *policyTrace {
	t.Helper()
	r, err := NewRunner(context, deadline)
	if err != nil {
		t.Fatal(err)
	}
	return &policyTrace{t: t, r: r}
}

func (p *policyTrace) send(e RunnerEvent) []RunnerAction {
	p.t.Helper()
	e.At = p.at
	if childEvent(e.Kind) && e.Child == 0 {
		e.Child = 7
	}
	a, o := p.r.Step(e)
	p.actions = append(p.actions, a...)
	p.outcome = o
	return a
}

func (p *policyTrace) start() {
	p.t.Helper()
	for _, step := range []struct {
		event  RunnerEvent
		action RunnerActionKind
	}{
		{RunnerEvent{Kind: RunnerBegin}, RunnerStartChild},
		{RunnerEvent{Kind: RunnerStarted, Child: 7}, RunnerAdmitChild},
		{RunnerEvent{Kind: RunnerAdmitted}, RunnerReleaseInputs},
	} {
		a := p.send(step.event)
		want := 1
		if step.event.Kind == RunnerBegin {
			want = 2
		}
		if len(a) != want || a[0].Kind != step.action {
			p.t.Fatalf("start action: got %+v", a)
		}
	}
}

func (p *policyTrace) count(k RunnerActionKind) int {
	n := 0
	for _, a := range p.actions {
		if a.Kind == k {
			n++
		}
	}
	return n
}

func (p *policyTrace) completeChild(result, ack []byte) {
	p.t.Helper()
	p.send(RunnerEvent{Kind: RunnerStdout, Data: ack})
	p.send(RunnerEvent{Kind: RunnerNativeCompleted, Digest: sha256.Sum256(result)})
	p.send(RunnerEvent{Kind: RunnerEOF})
	p.send(RunnerEvent{Kind: RunnerExited, Normal: true, Exit: 0})
	a := p.send(RunnerEvent{Kind: RunnerReaped})
	if len(a) != 1 || a[0].Kind != RunnerReadResult || p.outcome.Done() {
		p.t.Fatalf("quarantine before readback: %+v", a)
	}
}

func (p *policyTrace) close(ok bool) {
	p.t.Helper()
	if p.count(RunnerCloseOwned) != 1 {
		p.t.Fatalf("close not requested exactly once: %+v", p.actions)
	}
	p.send(RunnerEvent{Kind: RunnerClosed, OK: ok})
}

// Every parent gate keeps public signatures quarantined. Only the final owned
// close releases the original ACK once; subsequent events cannot emit it again.
func TestRunnerCompletionAndOnceOnlyRelease(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	p.send(RunnerEvent{Kind: RunnerEffectStarted})
	p.completeChild(result, ack)
	a := p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
	if len(a) != 1 || a[0].Kind != RunnerCloseOwned || p.outcome.Done() || len(p.outcome.Result()) != 0 {
		t.Fatal("early result release")
	}
	p.close(true)
	if !p.outcome.Success() || !bytes.Equal(p.outcome.Line(), ack) || p.count(RunnerEmitOutcome) != 1 {
		t.Fatal("complete invocation refused")
	}
	for _, k := range []RunnerEventKind{RunnerCancel, RunnerTick, RunnerReaped, RunnerClosed, RunnerBegin, RunnerStdout} {
		if a := p.send(RunnerEvent{Kind: k}); len(a) != 0 {
			t.Fatal("action after terminal outcome", a)
		}
	}
	if p.count(RunnerStartChild) != 1 || p.count(RunnerCloseOwned) != 1 || p.count(RunnerEmitOutcome) != 1 || p.count(RunnerKillChild) != 0 {
		t.Fatal("repeated or forbidden capability")
	}
}

// Initialization has empty stdout/exit0 only, with actual native completion;
// a transaction ACK or possible-mutation failure never becomes init success.
func TestInitializationCompletionAndUncertainty(t *testing.T) {
	_, result, ack := publicContext(t, "all-four-before-release", "A")
	for _, name := range []string{"valid", "transaction-ack", "failure-line-exit-zero", "no-native-completion", "mutation-then-refusal", "cleanup-failure"} {
		t.Run(name, func(t *testing.T) {
			p := trace(t, RunnerContext{Mode: RunnerInitialize}, time.Minute)
			p.start()
			p.send(RunnerEvent{Kind: RunnerEffectStarted})
			switch name {
			case "transaction-ack":
				p.send(RunnerEvent{Kind: RunnerStdout, Data: ack})
			case "failure-line-exit-zero":
				p.send(RunnerEvent{Kind: RunnerStdout, Data: namecoinwire.NewFailure(namecoinwire.AuthRefused, false).Bytes()})
			case "mutation-then-refusal":
				line := namecoinwire.NewFailure(namecoinwire.AuthRefused, false).Bytes()
				p.send(RunnerEvent{Kind: RunnerStdout, Data: line})
				p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: line, Boundary: BeforeInitializationMutation})
			}
			if name != "no-native-completion" && name != "mutation-then-refusal" {
				p.send(RunnerEvent{Kind: RunnerNativeCompleted})
			}
			p.send(RunnerEvent{Kind: RunnerEOF})
			p.send(RunnerEvent{Kind: RunnerExited, Normal: true})
			p.send(RunnerEvent{Kind: RunnerReaped})
			if p.count(RunnerCloseOwned) == 0 {
				p.at = time.Minute
				p.send(RunnerEvent{Kind: RunnerTick})
			}
			p.close(name != "cleanup-failure")
			if name == "valid" {
				exit, done := p.outcome.Exit()
				if !done || exit != 0 || !p.outcome.Success() || len(p.outcome.Line()) != 0 || len(p.outcome.Result()) != 0 {
					t.Fatal("init completion mismatch")
				}
			} else {
				assertUnknown(t, p.outcome)
			}
			if p.count(RunnerReadResult) != 0 {
				t.Fatal("init read transaction result", len(result))
			}
		})
	}
}

// C5's exact 21 rows retain their specified statuses/exits only with an admitted
// mode-specific definite boundary and complete transport; no raw enum is proof.
func TestAdmittedRefusalTable(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, row := range refusalRows {
		t.Run(string(row.code), func(t *testing.T) {
			p := trace(t, c, time.Minute)
			p.start()
			line := publicFile(t, "namecoinwire", "errors", string(row.code)+".stdout")
			p.send(RunnerEvent{Kind: RunnerStdout, Data: line})
			p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: line, Boundary: BeforeDispatch})
			p.send(RunnerEvent{Kind: RunnerEOF})
			p.send(RunnerEvent{Kind: RunnerExited, Normal: true, Exit: row.exit})
			p.send(RunnerEvent{Kind: RunnerReaped})
			p.close(true)
			exit, done := p.outcome.Exit()
			if !done || exit != row.exit || p.outcome.Success() || !bytes.Equal(p.outcome.Line(), line) || p.count(RunnerReadResult) != 0 {
				t.Fatal("C5 refusal changed")
			}
		})
	}
}

// Every removed/failed completion condition prevents success with the same
// valid signed fixture. Unreaped children and unclosed resources stay pending.
func TestCompletionGateFailures(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	for _, name := range []string{"no-ack", "extra-stdout", "no-eof", "nonzero-exit", "abnormal-exit", "no-reap", "no-native", "bad-native-hash", "zero-native-hash", "readback-failure", "bad-result", "close-failure", "no-close", "stderr"} {
		t.Run(name, func(t *testing.T) {
			p := trace(t, c, time.Minute)
			p.start()
			if name != "no-ack" {
				p.send(RunnerEvent{Kind: RunnerStdout, Data: ack})
			}
			if name == "extra-stdout" {
				p.send(RunnerEvent{Kind: RunnerStdout, Data: []byte("extra\n")})
			}
			if name == "stderr" {
				p.send(RunnerEvent{Kind: RunnerStderr, Data: []byte("unexpected")})
			}
			if name != "no-native" {
				hash := sha256.Sum256(result)
				if name == "bad-native-hash" {
					hash[0] ^= 1
				}
				if name == "zero-native-hash" {
					hash = [32]byte{}
				}
				p.send(RunnerEvent{Kind: RunnerNativeCompleted, Digest: hash})
			}
			if name != "no-eof" {
				p.send(RunnerEvent{Kind: RunnerEOF})
			}
			exit, normal := 0, true
			if name == "nonzero-exit" {
				exit = 3
			}
			if name == "abnormal-exit" {
				normal = false
			}
			p.send(RunnerEvent{Kind: RunnerExited, Normal: normal, Exit: exit})
			if name != "no-reap" {
				p.send(RunnerEvent{Kind: RunnerReaped})
			}
			if p.count(RunnerReadResult) == 1 {
				switch name {
				case "readback-failure":
					p.send(RunnerEvent{Kind: RunnerReadbackFailed})
				case "bad-result":
					p.send(RunnerEvent{Kind: RunnerReadback, Data: []byte("bad")})
				default:
					p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
				}
			}
			p.at = time.Minute
			p.send(RunnerEvent{Kind: RunnerTick})
			if name == "no-reap" || name == "no-close" {
				if p.outcome.Done() {
					t.Fatal("terminal before reap/close")
				}
				if name == "no-reap" {
					if p.count(RunnerCloseOwned) != 0 {
						t.Fatal("output closed before reap/readback")
					}
					p.send(RunnerEvent{Kind: RunnerReaped})
				} else {
					p.close(true)
					assertUnknown(t, p.outcome)
					return
				}
			}
			p.close(name != "close-failure")
			assertUnknown(t, p.outcome)
			if p.count(RunnerStartChild) != 1 || p.count(RunnerCloseOwned) != 1 {
				t.Fatal("retry or repeated close")
			}
		})
	}
}

// Cancellation before Begin has zero child starts and closes owned resources
// once; a pending start action instead waits for an actual no-start observation.
func TestPrestartCancellationAndStartRace(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, name := range []string{"cancel", "deadline", "pending-no-start", "pending-started"} {
		t.Run(name, func(t *testing.T) {
			p := trace(t, c, time.Minute)
			if name == "pending-no-start" || name == "pending-started" {
				p.send(RunnerEvent{Kind: RunnerBegin})
			}
			if name == "deadline" {
				p.at = time.Minute
			}
			p.send(RunnerEvent{Kind: RunnerCancel})
			if name == "pending-no-start" || name == "pending-started" {
				if p.outcome.Done() || p.count(RunnerCloseOwned) != 0 {
					t.Fatal("claimed no start while start unresolved")
				}
				if name == "pending-no-start" {
					p.send(RunnerEvent{Kind: RunnerStartRefused, Code: namecoinwire.AuthRefused})
				} else {
					p.send(RunnerEvent{Kind: RunnerStarted, Child: 7})
					if p.count(RunnerTerminateChild) != 1 || p.outcome.Done() {
						t.Fatal("raced child escaped cancellation")
					}
					p.at = time.Minute
					p.send(RunnerEvent{Kind: RunnerTick})
					p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
					p.send(RunnerEvent{Kind: RunnerReaped})
					p.close(true)
					assertUnknown(t, p.outcome)
					return
				}
			}
			p.close(true)
			f, err := namecoinwire.DecodeFailure(p.outcome.Line())
			if err != nil || f.Code() != namecoinwire.AuthRefused || f.Exit() != 3 {
				t.Fatal("prestart cancel mapping", err)
			}
			if name == "cancel" || name == "deadline" {
				if p.count(RunnerStartChild) != 0 {
					t.Fatal("start after prestart cancellation")
				}
			}
		})
	}
}

// Grace is bounded by ten seconds and the remaining deadline, but only the
// hard deadline authorizes KILL. Every signal/reap targets the retained child.
func TestCancellationGraceAndExactChild(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, row := range []struct{ cancel, grace time.Duration }{{5 * time.Second, 15 * time.Second}, {50 * time.Second, time.Minute}, {55 * time.Second, time.Minute}, {time.Minute, time.Minute}} {
		p := trace(t, c, time.Minute)
		p.start()
		p.at = row.cancel
		actions := p.send(RunnerEvent{Kind: RunnerCancel})
		found := false
		for _, a := range actions {
			if a.Kind == RunnerWaitUntil {
				found = a.At == row.grace
			}
		}
		if !found || p.count(RunnerTerminateChild) != 1 {
			t.Fatalf("wrong grace: %+v", actions)
		}
		p.send(RunnerEvent{Kind: RunnerCancel})
		p.at = row.grace
		p.send(RunnerEvent{Kind: RunnerTick})
		p.send(RunnerEvent{Kind: RunnerTick})
		if row.grace < time.Minute && p.count(RunnerKillChild) != 0 {
			t.Fatal("user grace authorized early kill")
		}
		p.at = time.Minute
		p.send(RunnerEvent{Kind: RunnerTick})
		if p.count(RunnerKillChild) != 1 || p.count(RunnerReapChild) != 1 || p.outcome.Done() {
			t.Fatal("kill/reap repetition or early verdict")
		}
		p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
		p.send(RunnerEvent{Kind: RunnerReaped})
		p.close(true)
		assertUnknown(t, p.outcome)
		for _, a := range p.actions {
			if a.Kind == RunnerTerminateChild || a.Kind == RunnerKillChild || a.Kind == RunnerReapChild {
				if a.Child != 7 {
					t.Fatal("foreign child targeted")
				}
			}
		}
	}
}

// Natural authentic completion and reap during grace suppress a later kill;
// timeout/kill are never inferred to be a definite biometric refusal.
func TestNaturalCompletionDuringGrace(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	p.at = 5 * time.Second
	p.send(RunnerEvent{Kind: RunnerCancel})
	p.at = 20 * time.Second
	p.completeChild(result, ack)
	p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
	p.close(true)
	p.at = 25 * time.Second
	p.send(RunnerEvent{Kind: RunnerTick})
	if !p.outcome.Success() || p.count(RunnerKillChild) != 0 || p.count(RunnerTerminateChild) != 1 {
		t.Fatal("killed natural completion")
	}
}

// The forced-kill exception requires an exact admitted refusal already read.
// Partial/unknown lines, wrong boundaries, raw exit and later effect fail closed.
func TestForcedRefusalExceptionAndForbiddenDowngrades(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	line := namecoinwire.NewFailure(namecoinwire.AuthRefused, false).Bytes()
	for _, name := range []string{"valid", "partial", "unknown-code", "no-boundary", "wrong-boundary", "effect-first", "effect-after", "extra-output", "forged-no-effect"} {
		t.Run(name, func(t *testing.T) {
			p := trace(t, c, time.Minute)
			p.start()
			data := bytes.Clone(line)
			if name == "partial" {
				data = data[:len(data)-1]
			}
			if name == "unknown-code" {
				data = bytes.ReplaceAll(data, []byte("auth_refused"), []byte("invented_code"))
			}
			if name == "forged-no-effect" {
				data = []byte("{\"no_effect\":true}\n")
			}
			if name == "effect-first" {
				p.send(RunnerEvent{Kind: RunnerEffectStarted})
			}
			p.send(RunnerEvent{Kind: RunnerStdout, Data: data})
			boundary := BeforeDispatch
			if name == "wrong-boundary" {
				boundary = BeforeInitializationMutation
			}
			if name != "no-boundary" {
				p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: data, Boundary: boundary})
			}
			if name == "effect-after" {
				p.send(RunnerEvent{Kind: RunnerEffectStarted})
			}
			if name == "extra-output" {
				p.send(RunnerEvent{Kind: RunnerStdout, Data: []byte("x")})
			}
			p.at = 5 * time.Second
			p.send(RunnerEvent{Kind: RunnerCancel})
			p.at = time.Minute
			p.send(RunnerEvent{Kind: RunnerTick})
			p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
			p.send(RunnerEvent{Kind: RunnerReaped})
			p.close(true)
			if name == "valid" {
				if !bytes.Equal(p.outcome.Line(), line) {
					t.Fatal("complete pre-effect refusal lost")
				}
			} else {
				assertUnknown(t, p.outcome)
			}
		})
	}
}

// A historical descriptor/result remains publicly checkable after expiry, but
// fresh signing admission at that actual late time refuses. Reconcile still
// needs its own real invocation/authentication; a public cache alone times out.
func TestHistoricalReconcileNeedsNativeCompletion(t *testing.T) {
	c, result, ack := publicContext(t, "two-stage", "D")
	a, err := namecoinpsbt.DecodeAttempt(c.Attempt.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Candidate().Admit(a.Selection(), time.Unix(int64(a.Selection().Policy.ReleaseNotAfter)+1, 0)); err == nil {
		t.Fatal("fresh expired signing admitted")
	}
	c.Mode, c.Attempt = RunnerReconcile, a
	for _, native := range []bool{true, false} {
		p := trace(t, c, time.Minute)
		p.start()
		p.send(RunnerEvent{Kind: RunnerStdout, Data: ack})
		if native {
			p.send(RunnerEvent{Kind: RunnerNativeCompleted, Digest: sha256.Sum256(result)})
		}
		p.send(RunnerEvent{Kind: RunnerEOF})
		p.send(RunnerEvent{Kind: RunnerExited, Normal: true})
		p.send(RunnerEvent{Kind: RunnerReaped})
		if native {
			p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
		} else {
			if p.count(RunnerReadResult) != 0 || p.outcome.Done() {
				t.Fatal("cache manufactured native completion")
			}
			p.at = time.Minute
			p.send(RunnerEvent{Kind: RunnerTick})
		}
		p.close(true)
		if native {
			if !p.outcome.Success() {
				t.Fatal("authentic historical completion refused")
			}
		} else {
			assertUnknown(t, p.outcome)
		}
		if p.count(RunnerStartChild) != 1 {
			t.Fatal("automatic retry/reconcile")
		}
	}
}

// Kernel reap may precede pipe EOF and delivery of native completion evidence.
// Draining an already reaped child's output never permits another signal.
func TestReapBeforePipeDrain(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	p.send(RunnerEvent{Kind: RunnerExited, Normal: true})
	p.send(RunnerEvent{Kind: RunnerReaped})
	p.send(RunnerEvent{Kind: RunnerNativeCompleted, Digest: sha256.Sum256(result)})
	p.send(RunnerEvent{Kind: RunnerStdout, Data: ack})
	p.send(RunnerEvent{Kind: RunnerEOF})
	p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
	p.close(true)
	if !p.outcome.Success() || p.count(RunnerTerminateChild) != 0 || p.count(RunnerKillChild) != 0 {
		t.Fatal("late drain signalled reaped child or refused authentic completion")
	}
}

// The exception is evidence already available before forced termination;
// completing a refusal line only after SIGKILL cannot retroactively qualify it.
func TestLateRefusalCannotUndoForcedTermination(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	line := namecoinwire.NewFailure(namecoinwire.AuthRefused, false).Bytes()
	p.send(RunnerEvent{Kind: RunnerStdout, Data: line[:len(line)-1]})
	p.at = 5 * time.Second
	p.send(RunnerEvent{Kind: RunnerCancel})
	p.at = time.Minute
	p.send(RunnerEvent{Kind: RunnerTick})
	p.send(RunnerEvent{Kind: RunnerStdout, Data: line[len(line)-1:]})
	p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: line, Boundary: BeforeDispatch})
	p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
	p.send(RunnerEvent{Kind: RunnerReaped})
	p.close(true)
	assertUnknown(t, p.outcome)
}

// Foreign child handles, duplicate lifecycle events, invalid time and unproved
// admission cannot release an input or success; owned cleanup is not repeated.
func TestProtocolAndOwnershipRefusals(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, name := range []string{"foreign", "duplicate-admission", "backwards-time", "invalid-exit", "unknown-event", "early-readback", "early-close", "duplicate-start", "reconcile-mutation"} {
		t.Run(name, func(t *testing.T) {
			context := c
			if name == "reconcile-mutation" {
				context.Mode = RunnerReconcile
			}
			p := trace(t, context, time.Minute)
			p.start()
			p.at = time.Second
			p.send(RunnerEvent{Kind: RunnerTick})
			switch name {
			case "foreign":
				p.send(RunnerEvent{Kind: RunnerStdout, Child: 9, Data: []byte("x")})
			case "duplicate-admission":
				p.send(RunnerEvent{Kind: RunnerAdmitted})
			case "backwards-time":
				p.at = 0
				p.send(RunnerEvent{Kind: RunnerTick})
			case "invalid-exit":
				p.send(RunnerEvent{Kind: RunnerExited, Normal: true, Exit: 256})
			case "unknown-event":
				p.send(RunnerEvent{Kind: RunnerEventKind(255)})
			case "early-readback":
				p.send(RunnerEvent{Kind: RunnerReadback, Data: []byte("cached")})
			case "early-close":
				p.send(RunnerEvent{Kind: RunnerClosed, OK: true})
			case "duplicate-start":
				p.send(RunnerEvent{Kind: RunnerStarted, Child: 9})
			case "reconcile-mutation":
				p.send(RunnerEvent{Kind: RunnerEffectStarted})
			}
			p.at = time.Minute
			p.send(RunnerEvent{Kind: RunnerTick})
			p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
			p.send(RunnerEvent{Kind: RunnerReaped})
			p.close(true)
			assertUnknown(t, p.outcome)
			if p.count(RunnerReleaseInputs) != 1 || p.count(RunnerStartChild) != 1 || p.count(RunnerCloseOwned) != 1 {
				t.Fatal("extra capability action")
			}
			for _, a := range p.actions {
				if a.Kind != RunnerStartChild && a.Kind != RunnerEmitOutcome && !(a.Kind == RunnerWaitUntil && a.Child == 0) && a.Child != 7 {
					t.Fatal("foreign handle in action", a)
				}
			}
		})
	}
}

// Oversize is a post-execution UNKNOWN, with no emitted ACK, truncation or
// second helper. Adjacent valid transport sizes still complete successfully.
func TestRunnerPostEffectResultCap(t *testing.T) {
	c, result, _ := publicContext(t, "all-four-before-release", "A")
	for _, size := range []int{MaxProcessResultBytes - 1, MaxProcessResultBytes, MaxProcessResultBytes + 1} {
		p := trace(t, c, time.Minute)
		p.start()
		p.send(RunnerEvent{Kind: RunnerEffectStarted})
		raw := append(bytes.Repeat([]byte{' '}, size-len(result)), result...)
		ack := namecoinwire.Acknowledgement(sha256.Sum256(raw))
		p.completeChild(raw, ack)
		p.send(RunnerEvent{Kind: RunnerReadback, Data: raw})
		p.close(true)
		if size <= MaxProcessResultBytes {
			if !p.outcome.Success() || len(p.outcome.Result()) != size {
				t.Fatal("valid cap neighbor refused/truncated")
			}
		} else {
			assertUnknown(t, p.outcome)
		}
		if p.count(RunnerEmitOutcome) != 1 || p.count(RunnerStartChild) != 1 {
			t.Fatal("repeat or retry after output bound")
		}
	}
}

// A normal noncanonical/unknown start refusal remains UNKNOWN; it cannot be
// rewritten as cancellation. A genuine admission refusal keeps its C5 code.
func TestStartRefusalMapping(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, code := range []namecoinwire.Code{namecoinwire.HelperNotAdmitted, "unknown-start-error"} {
		p := trace(t, c, time.Minute)
		p.send(RunnerEvent{Kind: RunnerBegin})
		p.send(RunnerEvent{Kind: RunnerStartRefused, Code: code})
		p.close(true)
		if code == namecoinwire.HelperNotAdmitted {
			f, err := namecoinwire.DecodeFailure(p.outcome.Line())
			if err != nil || f.Code() != code {
				t.Fatal("prestart admission refusal changed", err)
			}
		} else {
			assertUnknown(t, p.outcome)
		}
	}
}

// Caller changes to context variables and descriptor copies cannot substitute
// a different plan while an invocation is running; the original still verifies.
func TestRunnerOwnsFrozenPublicContext(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	descriptor := c.Attempt.Descriptor()
	descriptor[len(descriptor)-1] ^= 255
	if _, err := namecoinpsbt.DecodeAttempt(descriptor); err == nil {
		t.Fatal("changed frozen bytes accepted")
	}
	c.Mode, c.Attempt = RunnerInitialize, namecoinpsbt.PublicAttempt{}
	p.start()
	p.completeChild(result, ack)
	p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
	p.close(true)
	if !p.outcome.Success() || !bytes.Equal(p.outcome.Line(), ack) {
		t.Fatal("caller replaced frozen context")
	}
}

// Every C5 code loses definite-refusal status at the conservative engine-run
// entry, even before descriptor persistence or DISPATCHED. The paired pre-effect table above remains the valid neighbor.
func TestAllCodesAfterPossibleEffectAreUnknown(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, row := range refusalRows {
		t.Run(string(row.code), func(t *testing.T) {
			p := trace(t, c, time.Minute)
			p.start()
			p.send(RunnerEvent{Kind: RunnerEffectStarted})
			line := publicFile(t, "namecoinwire", "errors", string(row.code)+".stdout")
			p.send(RunnerEvent{Kind: RunnerStdout, Data: line})
			p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: line, Boundary: BeforeDispatch})
			p.send(RunnerEvent{Kind: RunnerEOF})
			p.send(RunnerEvent{Kind: RunnerExited, Normal: true, Exit: row.exit})
			p.send(RunnerEvent{Kind: RunnerReaped})
			p.close(true)
			assertUnknown(t, p.outcome)
		})
	}
}

// The reducer schedules TERM at hard-10s and never KILL at an earlier user
// grace. These are elapsed-event controls, not native signal/timer witnesses.
func TestSoftDeadlineSchedule(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, mode := range []RunnerMode{RunnerSign, RunnerReconcile, RunnerInitialize} {
		t.Run(strconv.Itoa(int(mode)), func(t *testing.T) {
			context := c
			context.Mode = mode
			if mode == RunnerInitialize {
				context.Attempt = namecoinpsbt.PublicAttempt{}
			}
			p := trace(t, context, time.Minute)
			p.start()
			if p.actions[1].Kind != RunnerWaitUntil || p.actions[1].At != 50*time.Second {
				t.Fatal("soft deadline not scheduled at entry", p.actions)
			}
			p.at = 50*time.Second - time.Nanosecond
			p.send(RunnerEvent{Kind: RunnerTick})
			if p.count(RunnerTerminateChild) != 0 || p.count(RunnerKillChild) != 0 {
				t.Fatal("early signal")
			}
			p.at = 50 * time.Second
			p.send(RunnerEvent{Kind: RunnerTick})
			if p.count(RunnerTerminateChild) != 1 || p.r.grace != time.Minute {
				t.Fatal("soft deadline did not independently send TERM")
			}
			p.send(RunnerEvent{Kind: RunnerCancel})
			if p.count(RunnerTerminateChild) != 1 || p.r.grace != time.Minute {
				t.Fatal("missing/duplicate TERM or wrong remaining grace")
			}
			p.at = time.Minute - time.Nanosecond
			p.send(RunnerEvent{Kind: RunnerTick})
			if p.count(RunnerKillChild) != 0 {
				t.Fatal("KILL before hard deadline")
			}
			p.at = time.Minute
			p.send(RunnerEvent{Kind: RunnerTick})
			p.send(RunnerEvent{Kind: RunnerTick})
			if p.count(RunnerTerminateChild) != 1 || p.count(RunnerKillChild) != 1 || p.count(RunnerReapChild) != 1 || p.outcome.Done() {
				t.Fatal("wrong hard deadline ownership/actions")
			}
			p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
			p.send(RunnerEvent{Kind: RunnerReaped})
			p.close(true)
			assertUnknown(t, p.outcome)
		})
	}
}

// A known no-start at soft_T refuses. A genuinely raced late start gets one
// immediate TERM with actual remaining grace, plus KILL only if hard_T is due.
func TestLateStartAndShortTimeout(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, deadline := range []time.Duration{time.Second, 10 * time.Second, time.Minute} {
		p := trace(t, c, deadline)
		p.at = max(0, deadline-10*time.Second)
		p.send(RunnerEvent{Kind: RunnerBegin})
		if p.count(RunnerStartChild) != 0 {
			t.Fatal("planned start at/after soft deadline")
		}
		p.close(true)
		f, err := namecoinwire.DecodeFailure(p.outcome.Line())
		if err != nil || f.Code() != namecoinwire.AuthRefused || f.Exit() != 3 {
			t.Fatal("wrong no-start refusal", err)
		}
	}
	for _, at := range []time.Duration{50 * time.Second, 55 * time.Second, time.Minute, 65 * time.Second} {
		p := trace(t, c, time.Minute)
		p.send(RunnerEvent{Kind: RunnerBegin})
		p.at = at
		p.send(RunnerEvent{Kind: RunnerStarted, Child: 7})
		if p.count(RunnerTerminateChild) != 1 || p.count(RunnerReleaseInputs) != 0 || p.r.grace-at != min(10*time.Second, max(0, time.Minute-at)) {
			t.Fatal("late start extended grace or released inputs", p.actions)
		}
		if (p.count(RunnerKillChild) == 1) != (at >= time.Minute) || p.outcome.Done() {
			t.Fatal("wrong late-start hard boundary")
		}
		p.at = max(at, time.Minute)
		p.send(RunnerEvent{Kind: RunnerTick})
		p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
		p.send(RunnerEvent{Kind: RunnerReaped})
		p.close(true)
		assertUnknown(t, p.outcome)
	}
}

// An early user grace expires without a KILL, and soft_T sends no second TERM.
// Normal verified completion after that grace still releases the exact ACK.
func TestEarlyGraceThenSoftDeadlineCompletion(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	p.at = time.Second
	p.send(RunnerEvent{Kind: RunnerCancel})
	p.at = 11 * time.Second
	actions := p.send(RunnerEvent{Kind: RunnerTick})
	if len(actions) != 1 || actions[0].Kind != RunnerWaitUntil || actions[0].At != time.Minute || p.count(RunnerKillChild) != 0 {
		t.Fatal("early grace did not retain child until hard deadline", actions)
	}
	p.at = 50 * time.Second
	p.send(RunnerEvent{Kind: RunnerTick})
	p.at = 55 * time.Second
	p.completeChild(result, ack)
	p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
	p.close(true)
	if !p.outcome.Success() || p.count(RunnerTerminateChild) != 1 || p.count(RunnerKillChild) != 0 {
		t.Fatal("early cancellation destroyed normal completion")
	}
}

// A late parent interrupt after the full child ACK cannot become auth_refused.
// Independent verification still decides success versus UNKNOWN.
func TestCancelAfterCompleteACK(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	for _, badReadback := range []bool{false, true} {
		p := trace(t, c, time.Minute)
		p.start()
		p.completeChild(result, ack)
		p.send(RunnerEvent{Kind: RunnerCancel})
		if badReadback {
			p.send(RunnerEvent{Kind: RunnerReadbackFailed})
		} else {
			p.send(RunnerEvent{Kind: RunnerReadback, Data: result})
		}
		p.close(true)
		if badReadback {
			assertUnknown(t, p.outcome)
		} else if !p.outcome.Success() || !bytes.Equal(p.outcome.Line(), ack) {
			t.Fatal("late interrupt replaced completed ACK")
		}
		if p.count(RunnerTerminateChild) != 0 || p.count(RunnerKillChild) != 0 {
			t.Fatal("signalled reaped child")
		}
	}
}

// The observed run edge ends sign/init definite refusal even before the first
// write. Reconcile can still cleanly cancel without claiming no prior output.
// Actual call-edge observation and storage remnants need native qualification.
func TestModeSpecificCancellationCutovers(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	for _, mode := range []RunnerMode{RunnerSign, RunnerInitialize, RunnerReconcile} {
		for _, entered := range []bool{false, true} {
			if mode == RunnerReconcile && entered {
				continue // Reconcile has no mutating run-entry event.
			}
			for _, code := range []namecoinwire.Code{namecoinwire.AuthRefused, namecoinwire.JournalUnavailable} {
				t.Run(fmt.Sprintf("mode%d/entered%v/%s", mode, entered, code), func(t *testing.T) {
					context := c
					context.Mode = mode
					boundary := BeforeDispatch
					if mode == RunnerInitialize {
						context.Attempt = namecoinpsbt.PublicAttempt{}
						boundary = BeforeInitializationMutation
					}
					p := trace(t, context, time.Minute)
					p.start()
					if entered {
						p.send(RunnerEvent{Kind: RunnerEffectStarted})
					}
					p.at = time.Second
					p.send(RunnerEvent{Kind: RunnerCancel})
					line := namecoinwire.NewFailure(code, false).Bytes()
					p.send(RunnerEvent{Kind: RunnerStdout, Data: line})
					p.send(RunnerEvent{Kind: RunnerDefiniteRefusal, Data: line, Boundary: boundary})
					p.send(RunnerEvent{Kind: RunnerEOF})
					p.send(RunnerEvent{Kind: RunnerExited, Normal: true, Exit: namecoinwire.NewFailure(code, false).Exit()})
					p.send(RunnerEvent{Kind: RunnerReaped})
					p.close(true)
					if entered {
						assertUnknown(t, p.outcome)
					} else if !bytes.Equal(p.outcome.Line(), line) {
						t.Fatal("proven pre-run/clean reconcile refusal changed")
					}
					if p.count(RunnerStartChild) != 1 || p.count(RunnerReadResult) != 0 {
						t.Fatal("retry or released refused output")
					}
				})
			}
		}
	}
}

// A jumped elapsed observation cannot extend hard_T. This exercises the
// overdue reducer action only; it does not qualify stopped-parent scheduling.
func TestOverdueObservationDoesNotExtendDeadline(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	p := trace(t, c, time.Minute)
	p.start()
	p.send(RunnerEvent{Kind: RunnerEffectStarted})
	p.at = 70 * time.Second
	p.send(RunnerEvent{Kind: RunnerTick})
	if p.count(RunnerTerminateChild) != 1 || p.count(RunnerKillChild) != 1 || p.count(RunnerReapChild) != 1 || p.outcome.Done() {
		t.Fatal("overdue observation extended deadline or reported before reap")
	}
	p.send(RunnerEvent{Kind: RunnerExited, Normal: false})
	p.send(RunnerEvent{Kind: RunnerReaped})
	p.close(true)
	assertUnknown(t, p.outcome)
}
