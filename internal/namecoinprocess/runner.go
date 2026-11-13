package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// RunnerChild is an adapter-owned correlation handle, NOT a PID or authority.
// The adapter must retain exactly one actual, owned unreaped process handle and
// map actions to that handle. Never resolve it afresh by PID/name/process group.
// Recheck that ownership before each queued signal; discard pending signals if
// the actual child has already been reaped, even before the next Step call.
type RunnerChild uint64

type RunnerEventKind uint8

const (
	RunnerBegin RunnerEventKind = iota + 1
	RunnerStarted
	RunnerStartRefused
	RunnerAdmitted
	RunnerStdout
	RunnerStderr
	RunnerEOF
	RunnerEffectStarted
	RunnerNativeCompleted
	RunnerDefiniteRefusal
	RunnerExited
	RunnerReaped
	RunnerReadback
	RunnerReadbackFailed
	RunnerClosed
	RunnerCancel
	RunnerTick
	RunnerFault
)

type RefusalBoundary uint8

const (
	BeforeDispatch               RefusalBoundary = iota + 1 // Sign: before engine run; reconcile: clean read-only unwind.
	BeforeInitializationMutation                            // Before initialization engine run, not merely CreatePublicState.
)

// RunnerEvent carries bounded observations, not a caller-supplied no-effect
// flag or verifier callback. At is elapsed monotonic time since process entry.
// All child events carry the exact retained handle; parent events carry zero.
//
// Adapter obligations:
//   - Started reports actual start (including uncertain exec); StartRefused is
//     only an actual proven no-start result, never an unclassified spawn error.
//   - Admitted follows checks of the actual child/parent code and matched pin,
//     before ReleaseInputs. Path/hash claims alone do not establish admission.
//   - EffectStarted reports entry into the existing sign/init engine run,
//     before PutDescriptor/CreatePublicState. This is the conservative
//     uncertainty cutover, not evidence that a write or ECDSA already happened.
//     Observe the actual call edge: a DISPATCHED callback is too late. There
//     is no new ABI, hook, wire field or cancellation channel. After this edge
//     no cancellation refusal is definite; run-phase journal_unavailable is
//     UNKNOWN, including EEXIST/partial descriptor writes before D. Native
//     phase observation remains a separate qualification obligation.
//   - NativeCompleted comes only from this admitted native invocation after
//     authentic completion, native cleanup and archive close. Digest binds its
//     exact result; for initialization it is zero. Public cached JSON, matching
//     hashes, a callback or a caller's process_exit cannot supply this event.
//   - DefiniteRefusal attests the exact complete stdout line already read from
//     that admitted child, and a positively established mode-specific boundary
//     with required native cleanup. Raw codes/exits and absence of DISPATCHED
//     are insufficient. For sign/init the boundary is BEFORE the engine run,
//     never merely before D or the first protected mutation. Reconcile may
//     refuse after historical output was written, after clean read-only unwind;
//     this does not claim no historical or public-output effects. No extra wire
//     or cancellation channel is implied.
//   - Exited/Normal/Exit are actual wait observations (normal exit 0..255).
//     Reaped is the successful exact-child reap, never merely a signal result.
//   - Readback contains the entire bounded descriptor readback. Closed reports
//     one attempted close of all remaining parent-owned resources, with OK its
//     result. Track consumed ownership for every descriptor, including writers
//     closed during transfer. Do not retry a failed close on a reused number or
//     erase/truncate/reuse partial output.
//
// The adapter owns prompt/pipe scheduling and closes unneeded input writers
// during transfer/cancellation. It must deliver real observations promptly; this
// reducer cannot establish their truth or manufacture missing phase evidence.
type RunnerEvent struct {
	Kind     RunnerEventKind
	At       time.Duration
	Child    RunnerChild
	Data     []byte
	Digest   [32]byte
	Boundary RefusalBoundary
	Code     namecoinwire.Code // StartRefused only; existing closed namespace.
	Exit     int
	Normal   bool
	OK       bool // Closed only; never a no-effect assertion.
}

type RunnerActionKind uint8

const (
	RunnerStartChild RunnerActionKind = iota + 1
	RunnerAdmitChild
	RunnerReleaseInputs
	RunnerTerminateChild // One SIGTERM to the exact still-unreaped child.
	RunnerKillChild      // One SIGKILL to the same still-unreaped child.
	RunnerReapChild      // waitpid on the exact owned child; no retry/helper action.
	RunnerWaitUntil
	RunnerReadResult
	RunnerCloseOwned // Close remaining owned resources once; preserve files/state.
	RunnerEmitOutcome
)

type RunnerAction struct {
	Kind  RunnerActionKind
	Child RunnerChild
	At    time.Duration // Absolute elapsed soft, grace or hard timer boundary.
}

// Runner is a deterministic, single-invocation event/action reducer. It never
// spawns/signals/waits/closes, opens stores, retries or starts reconciliation.
// Use NewRunner and serialize Step calls; a Runner must not be copied or shared
// between goroutines. A separate invocation requires a separately admitted
// operation, new output and native authentication, not reuse of this state.
type Runner struct {
	context                                                  RunnerContext
	deadline, now, grace                                     time.Duration
	initialized, begun, startPending                         bool
	child                                                    RunnerChild
	admitted, runEntered, nativeDone                         bool
	nativeDigest                                             [32]byte
	stdout                                                   []byte
	eof, exited, normal, reaped                              bool
	exit                                                     int
	refusal                                                  *namecoinwire.Failure
	fault, stopping, expired, term, kill, reapRequested      bool
	hardWait                                                 bool
	readRequested, readDone, closeRequested, closed, closeOK bool
	verified                                                 Outcome
	outcome                                                  Outcome
	prestartFailure                                          namecoinwire.Failure
	prestartRefused                                          bool
}

func NewRunner(context RunnerContext, deadline time.Duration) (*Runner, error) {
	if !validRunnerContext(context, deadline) {
		return nil, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	return &Runner{context: context, deadline: deadline, initialized: true}, nil
}

// Step emits each capability action at most once. A terminal outcome is sticky,
// but RunnerEmitOutcome appears only on the transition, including empty-stdout
// initialization success. No terminal child verdict precedes actual reap.
func (r *Runner) Step(e RunnerEvent) ([]RunnerAction, Outcome) {
	if r.outcome.Done() {
		return nil, r.outcome
	}
	var actions []RunnerAction
	add := func(k RunnerActionKind) { actions = append(actions, RunnerAction{Kind: k, Child: r.child}) }
	if !r.initialized {
		r.outcome = refusedOutcome(namecoinwire.NewFailure(namecoinwire.InvalidRequest, false))
		add(RunnerEmitOutcome)
		return actions, r.outcome
	}
	if e.At < r.now || e.At < 0 {
		r.fail()
	} else {
		r.now = e.At
	}
	if r.now >= r.deadline {
		r.expired, r.stopping = true, true
	}
	if r.now >= r.deadline-10*time.Second {
		r.stopping = true
	}
	if (childEvent(e.Kind) && (r.child == 0 || e.Child != r.child)) ||
		(!childEvent(e.Kind) && e.Kind != RunnerStarted && e.Child != 0) {
		// A foreign/reused handle is never adopted or targeted by an action.
		r.fail()
	} else {
		switch e.Kind {
		case RunnerBegin:
			if r.begun || r.fault {
				r.fail()
			} else {
				r.begun = true
				if !r.stopping {
					r.startPending = true
					add(RunnerStartChild)
					actions = append(actions, RunnerAction{Kind: RunnerWaitUntil, At: r.deadline - 10*time.Second})
				}
			}
		case RunnerStarted:
			if !r.startPending || r.child != 0 || e.Child == 0 {
				r.fail()
			} else {
				r.child, r.startPending = e.Child, false
				if !r.stopping {
					add(RunnerAdmitChild)
				}
			}
		case RunnerStartRefused:
			if !r.startPending || r.child != 0 {
				r.fail()
			} else {
				r.startPending = false
				r.prestartFailure = namecoinwire.NewFailure(e.Code, false)
				r.prestartRefused = true
				r.stopping = true
			}
		case RunnerAdmitted:
			if r.admitted || r.reaped || r.exited || r.stopping {
				r.fail()
			} else {
				r.admitted = true
				add(RunnerReleaseInputs)
			}
		case RunnerStdout:
			if r.eof || len(e.Data) > 512-len(r.stdout) {
				r.fail()
			} else {
				r.stdout = append(r.stdout, e.Data...)
				if r.refusal != nil && !bytes.Equal(r.stdout, r.refusal.Bytes()) {
					r.fail()
				}
			}
		case RunnerStderr:
			if len(e.Data) != 0 {
				r.fail()
			}
		case RunnerEOF:
			if r.eof {
				r.fail()
			}
			r.eof = true
			if r.context.Mode == RunnerInitialize {
				if len(r.stdout) == 0 {
					break
				}
				if _, err := namecoinwire.DecodeFailure(r.stdout); err != nil {
					r.fail()
				}
				break
			}
			if _, err := namecoinwire.DecodeAcknowledgement(r.stdout); err != nil {
				if _, err := namecoinwire.DecodeFailure(r.stdout); err != nil {
					r.fail()
				}
			}
		case RunnerEffectStarted:
			if !r.admitted || r.reaped || r.nativeDone || r.context.Mode == RunnerReconcile {
				r.fail()
			}
			r.runEntered = true
		case RunnerNativeCompleted:
			if !r.admitted || r.nativeDone || r.refusal != nil || r.kill ||
				(r.context.Mode == RunnerInitialize && e.Digest != [32]byte{}) {
				r.fail()
			} else {
				r.nativeDone, r.nativeDigest = true, e.Digest
			}
		case RunnerDefiniteRefusal:
			boundary := BeforeDispatch
			if r.context.Mode == RunnerInitialize {
				boundary = BeforeInitializationMutation
			}
			f, err := namecoinwire.DecodeFailure(e.Data)
			if err != nil || !r.admitted || r.runEntered || r.nativeDone || r.kill || r.refusal != nil ||
				e.Boundary != boundary || !bytes.Equal(e.Data, r.stdout) {
				r.fail()
			} else {
				r.refusal = &f
			}
		case RunnerExited:
			if r.exited || r.reaped || (e.Normal && (e.Exit < 0 || e.Exit > 255)) {
				r.fail()
			} else {
				r.exited, r.normal, r.exit = true, e.Normal, e.Exit
			}
		case RunnerReaped:
			if !r.exited || r.reaped {
				r.fail()
			} else {
				r.reaped = true
			}
		case RunnerReadback:
			if !r.readRequested || r.readDone || len(e.Data) > MaxProcessResultBytes {
				r.fail()
				r.readDone = true
			} else {
				r.readDone = true
				verified, err := verifyProcessResult(r.context, r.stdout, e.Data)
				if err != nil || sha256.Sum256(e.Data) != r.nativeDigest {
					r.fail()
				} else {
					r.verified = verified
				}
			}
		case RunnerReadbackFailed:
			if !r.readRequested || r.readDone {
				r.fail()
			}
			r.readDone = true
			r.fail()
		case RunnerClosed:
			if !r.closeRequested || r.closed {
				r.fail()
			} else {
				r.closed, r.closeOK = true, e.OK
				if !e.OK {
					r.fail()
				}
			}
		case RunnerCancel:
			r.stopping = true
		case RunnerTick:
		case RunnerFault:
			r.fail()
		default:
			r.fail()
		}
	}

	if r.child == 0 && !r.startPending && (r.stopping || r.fault) {
		code := r.prestartFailure.Code()
		if r.now >= r.deadline-10*time.Second || (r.stopping && !r.fault && !r.prestartRefused) {
			code = namecoinwire.AuthRefused
		}
		if r.fault {
			code = namecoinwire.InvalidRequest
		}
		if !r.closeRequested {
			r.closeRequested = true
			add(RunnerCloseOwned)
		}
		if r.closed {
			if !r.closeOK {
				code = namecoinwire.OutputUnavailable
			}
			r.outcome = refusedOutcome(namecoinwire.NewFailure(code, false))
			add(RunnerEmitOutcome)
		}
		return actions, r.outcome
	}
	if r.child != 0 && !r.reaped {
		if r.stopping && !r.exited && !r.term {
			r.term = true
			r.grace = r.now + min(10*time.Second, max(0, r.deadline-r.now))
			add(RunnerTerminateChild)
			actions = append(actions, RunnerAction{Kind: RunnerWaitUntil, Child: r.child, At: r.grace})
		}
		if r.term && !r.exited && r.now >= r.grace && r.now < r.deadline && !r.hardWait {
			r.hardWait = true
			actions = append(actions, RunnerAction{Kind: RunnerWaitUntil, Child: r.child, At: r.deadline})
		}
		if r.term && !r.exited && r.now >= r.deadline && !r.kill {
			r.kill = true
			add(RunnerKillChild)
		}
		if (r.exited || r.kill) && !r.reapRequested {
			r.reapRequested = true
			add(RunnerReapChild)
		}
	}
	if r.reaped && !r.closeRequested {
		completionLineOK := r.context.Mode != RunnerInitialize || len(r.stdout) == 0
		completeSuccess := !r.fault && !r.kill && !r.expired && r.admitted && r.nativeDone && r.eof && r.normal && r.exit == 0 && completionLineOK
		if completeSuccess && r.context.Mode != RunnerInitialize && !r.readRequested {
			r.readRequested = true
			add(RunnerReadResult)
		}
		// A valid ACK without authentic completion waits only until the deadline;
		// it cannot turn a cache into native proof or release a public result.
		completeFailure := r.fault || r.kill || r.expired ||
			(r.eof && r.exited && (!r.normal || r.exit != 0 || r.refusal != nil || !completionLineOK))
		if completeFailure || (completeSuccess && (r.context.Mode == RunnerInitialize || r.readDone)) {
			r.closeRequested = true
			add(RunnerCloseOwned)
		}
	}
	if r.reaped && r.closed {
		r.outcome = refusedOutcome(namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true))
		if !r.fault && r.closeOK && r.refusal != nil && !r.runEntered &&
			((r.normal && r.exit == r.refusal.Exit() && r.eof) || r.kill) {
			r.outcome = refusedOutcome(*r.refusal)
		} else if !r.fault && r.closeOK && !r.kill && !r.expired && r.admitted && r.nativeDone && r.eof && r.normal && r.exit == 0 &&
			(r.context.Mode != RunnerInitialize || len(r.stdout) == 0) {
			if r.context.Mode == RunnerInitialize {
				r.outcome = Outcome{done: true, success: true}
			} else if r.verified.Success() {
				r.outcome = r.verified
			}
		}
		add(RunnerEmitOutcome)
	}
	return actions, r.outcome
}

func (r *Runner) fail() { r.fault, r.stopping = true, true }

func childEvent(k RunnerEventKind) bool {
	switch k {
	case RunnerAdmitted, RunnerStdout, RunnerStderr, RunnerEOF, RunnerEffectStarted,
		RunnerNativeCompleted, RunnerDefiniteRefusal, RunnerExited, RunnerReaped:
		return true
	}
	return false
}
