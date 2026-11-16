package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func completeProcess2Evidence(t *testing.T) process2Evidence {
	t.Helper()
	context, result, ack := publicContext(t, "all-four-before-release", "A")
	invocation, err := ParseProcess2Args(process2ArgsFixture())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(result)
	profile, _ := hex.DecodeString(invocation.args.ProfileSHA256)
	request, _ := hex.DecodeString(invocation.args.RequestSHA256)
	var profileHash, requestHash [32]byte
	copy(profileHash[:], profile)
	copy(requestHash[:], request)
	inputs := Process2AttemptInputs{Mode: SignPSBT, Group: invocation.args.Group, Account: invocation.args.Account,
		ProfileSHA256: profileHash, OperationInputSHA256: requestHash}
	binding := inputs.binding()
	started, err := EncodeProcess2StatusFrame(Process2StatusFrame{Event: Process2EffectStarted, AttemptBinding: binding})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := EncodeProcess2StatusFrame(Process2StatusFrame{Event: Process2NativeCompleted, AttemptBinding: binding, ResultSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	closeObservations := make([]process2CloseObservation, 11)
	for i := range closeObservations {
		closeObservations[i] = process2CloseObservation{resource: "fixture-close", attempted: true, ok: true}
	}
	return process2Evidence{context: context, invocation: invocation, binding: binding, frameBytes: 500, frameLength: 500,
		writerCloseOK: true, writerJoined: true, stdinCloseOK: true, childEndsCloseOK: true,
		readerCloseOK: true, outputCloseOK: true, status: append(started, completed...), statusEOF: true,
		stdout: bytes.Clone(ack), stdoutEOF: true, stderrEOF: true, result: bytes.Clone(result), resultReadbackOK: true,
		waitDone: true, waitExit: 0, admitted: true, closeObservations: closeObservations}
}

func cloneProcess2Evidence(e process2Evidence) process2Evidence {
	e.status = bytes.Clone(e.status)
	e.stdout = bytes.Clone(e.stdout)
	e.result = bytes.Clone(e.result)
	e.closeObservations = append([]process2CloseObservation(nil), e.closeObservations...)
	return e
}

// Claim: each isolated single-barrier mutation returns UNKNOWN while the valid
// baseline remains successful before and after every negative case. Limit:
// phase evidence is fixture-built; runner integration supplies real observations.
func TestProcess2OutcomeRequiresEveryCompletionBarrier(t *testing.T) {
	valid := completeProcess2Evidence(t)
	if outcome := process2Outcome(valid); !outcome.Success() {
		t.Fatal("complete valid result refused; late cancellation is a valid neighbor")
	}
	mutants := map[string]func(*process2Evidence){
		"admission":              func(e *process2Evidence) { e.admitted = false },
		"frame-length":           func(e *process2Evidence) { e.frameLength = Process2MaxCustodyFrameBytes + 1 },
		"zero-bytes":             func(e *process2Evidence) { e.frameBytes = 0 },
		"partial-write":          func(e *process2Evidence) { e.frameBytes-- },
		"writer-error":           func(e *process2Evidence) { e.writeErr = true },
		"writer-close":           func(e *process2Evidence) { e.writerCloseOK = false },
		"writer-join":            func(e *process2Evidence) { e.writerJoined = false },
		"stdin-close":            func(e *process2Evidence) { e.stdinCloseOK = false },
		"child-end-close":        func(e *process2Evidence) { e.childEndsCloseOK = false },
		"reader-close":           func(e *process2Evidence) { e.readerCloseOK = false },
		"output-close":           func(e *process2Evidence) { e.outputCloseOK = false },
		"status-without-eof":     func(e *process2Evidence) { e.statusEOF = false },
		"status-overflow":        func(e *process2Evidence) { e.statusOverflow = true },
		"stdout-without-eof":     func(e *process2Evidence) { e.stdoutEOF = false },
		"stdout-overflow":        func(e *process2Evidence) { e.stdoutOverflow = true },
		"stderr-not-empty":       func(e *process2Evidence) { e.stderrHadBytes = true },
		"stderr-without-eof":     func(e *process2Evidence) { e.stderrEOF = false },
		"result-readback":        func(e *process2Evidence) { e.resultReadbackOK = false },
		"wait-missing":           func(e *process2Evidence) { e.waitDone = false },
		"wait-failed":            func(e *process2Evidence) { e.waitErr = true },
		"wait-nonzero":           func(e *process2Evidence) { e.waitExit = 1 },
		"missing-close-ledger":   func(e *process2Evidence) { e.closeObservations = nil },
		"failed-close-ledger":    func(e *process2Evidence) { e.closeObservations[4].ok = false },
		"status-result-mismatch": func(e *process2Evidence) { e.status[Process2StatusFrameBytes+40] ^= 1 },
		"ack-result-mismatch":    func(e *process2Evidence) { e.stdout[0] ^= 1 },
		"bad-public-result":      func(e *process2Evidence) { e.result = []byte("not a valid public result") },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			if baseline := process2Outcome(cloneProcess2Evidence(valid)); !baseline.Success() {
				t.Fatal("valid control no longer succeeds before this negative case")
			}
			evidence := cloneProcess2Evidence(valid)
			mutate(&evidence)
			assertUnknown(t, process2Outcome(evidence))
			if baseline := process2Outcome(cloneProcess2Evidence(valid)); !baseline.Success() {
				t.Fatal("negative case poisoned the valid control for neighboring cases")
			}
		})
	}
}
