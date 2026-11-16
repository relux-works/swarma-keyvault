//go:build linux

package namecoinprocess

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Claim: an already-fired original deadline still closes an incomplete child
// response after the rendezvoused writer becomes ready, then joins/reaps it.
// Limit: Linux pipe-size and public software helper fixtures only.
func TestProcess2FiredDeadlineWithReadyWriterCleansIncompleteResponse(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "14")
	frame := process2FrameFixture(MaxEnvelopeBlobBytes)
	frame.Metadata.Service = strings.Repeat("s", Process2MaxServiceBytes)
	frame.Metadata.PhysicalAccount = options.AttemptInputs.Group
	frame.Metadata.Sidecar = bytes.Repeat([]byte{'s'}, Process2MaxSidecarBytes)
	frame.Metadata.Record = bytes.Repeat([]byte{'r'}, Process2MaxRecordBytes)
	var err error
	options.Frame, err = EncodeProcess2CustodyFrame(frame)
	if err != nil {
		t.Fatal("encode maximum bounded writer fixture", err)
	}
	if len(options.Frame) <= 4096 {
		t.Fatal("fixture frame did not exceed the deliberately bounded pipe")
	}
	options.custodyPipeCapacity = 4096
	options.Deadline = time.Now().Add(150 * time.Millisecond)
	allowWriter := make(chan struct{})
	writerReady := make(chan struct{})
	writerWasReadyBeforeNestedSelect := false
	deadlineSelected := false
	options.testHooks = &process2RunTestHooks{
		beforeWriter:   func() { <-allowWriter },
		writerComplete: func() { close(writerReady) },
		deadlineSelected: func() {
			deadlineSelected = true
			close(allowWriter)
			select {
			case <-writerReady:
				writerWasReadyBeforeNestedSelect = true
			case <-time.After(2 * time.Second):
			}
		},
	}
	started := time.Now()
	type runResult struct {
		outcome  Outcome
		evidence process2Evidence
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan runResult, 1)
	go func() {
		outcome, evidence := runProcess2(ctx, command, options)
		done <- runResult{outcome: outcome, evidence: evidence}
	}()
	var result runResult
	select {
	case result = <-done:
	case <-time.After(3 * time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("runner required cancellation fallback instead of original-deadline cleanup")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("original deadline cleanup was not bounded: %s", elapsed)
	}
	assertUnknown(t, result.outcome)
	if !deadlineSelected || !writerWasReadyBeforeNestedSelect || !result.evidence.admitted || !result.evidence.writerJoined ||
		result.evidence.frameBytes != result.evidence.frameLength || result.evidence.writeErr || !result.evidence.writerCloseOK ||
		!result.evidence.waitDone || result.evidence.waitErr || result.evidence.waitExit != 128+int(syscall.SIGKILL) ||
		!result.evidence.readerCloseOK || !allProcess2ClosesOK(result.evidence.closeObservations) {
		t.Fatalf("ready-writer deadline path missed a required cleanup witness: %+v", result.evidence)
	}
}

// Claim: cancellation selected before helper effect remains UNKNOWN when the
// writer is ready in the nested select, even if the helper completes later.
// Limit: Linux public software helper and fixture admission; no native identity proof.
func TestProcess2PreCompletionCancellationWithReadyWriterStaysUnknown(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	command, options, wantResult, _ := process2RunnerFixture(t, helper, outputPath, "18")
	options.Deadline = time.Now().Add(5 * time.Second)

	allowWriter := make(chan struct{})
	writerStarted := make(chan struct{})
	writerReady := make(chan struct{})
	contextSelected := make(chan struct{})
	writerReadyBeforeNestedSelect := make(chan struct{})
	contextWriterSelected := make(chan struct{})
	responseCollectionAllowed := make(chan struct{})
	childReaped := make(chan struct{})
	var releaseWriter sync.Once
	var releaseResponseCollection sync.Once
	var releasePartialWrite sync.Once
	var waitCount atomic.Int32
	var writerCount atomic.Int32
	var outputBefore os.FileInfo
	var helperHeldBeforeEffect bool
	var cancelSelectedBeforeDeadline bool
	options.testHooks = &process2RunTestHooks{
		beforeWriter: func() {
			outputBefore, _ = os.Stat(outputPath)
			close(writerStarted)
			<-allowWriter
		},
		writerComplete: func() {
			writerCount.Add(1)
			close(writerReady)
		},
		contextSelected: func() {
			cancelSelectedBeforeDeadline = time.Now().Before(options.Deadline)
			close(contextSelected)
			releaseWriter.Do(func() { close(allowWriter) })
			select {
			case <-writerReady:
			case <-time.After(2 * time.Second):
				close(writerReadyBeforeNestedSelect)
				return
			}
			until := time.Now().Add(2 * time.Second)
			for time.Now().Before(until) {
				if _, err := os.Stat(outputPath + ".pre-effect"); err == nil {
					helperHeldBeforeEffect = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			close(writerReadyBeforeNestedSelect)
		},
		contextWriterSelected: func() {
			close(contextWriterSelected)
			<-responseCollectionAllowed
		},
		afterWait: func() {
			waitCount.Add(1)
			close(childReaped)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type runResult struct {
		outcome  Outcome
		evidence process2Evidence
	}
	done := make(chan runResult, 1)
	var result *runResult
	resumeHelper := func() {
		file, err := os.OpenFile(outputPath+".continue", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = file.Close()
		}
	}
	resumePartialWrite := func() {
		releasePartialWrite.Do(func() {
			file, err := os.OpenFile(outputPath+".write-rest", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err == nil {
				_ = file.Close()
			}
		})
	}
	t.Cleanup(func() {
		cancel()
		releaseWriter.Do(func() { close(allowWriter) })
		resumeHelper()
		resumePartialWrite()
		releaseResponseCollection.Do(func() { close(responseCollectionAllowed) })
		if result == nil {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("runner did not resolve the child during bounded fixture cleanup")
			}
		}
	})
	started := time.Now()
	go func() {
		outcome, evidence := runProcess2(ctx, command, options)
		done <- runResult{outcome: outcome, evidence: evidence}
	}()
	select {
	case <-writerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("setup failed before the real fd5 writer reached its rendezvous")
	}
	cancel()
	select {
	case <-contextSelected:
	case <-time.After(2 * time.Second):
		t.Fatal("setup failed: parent context did not select the outer cancellation branch")
	}
	select {
	case <-writerReadyBeforeNestedSelect:
	case <-time.After(3 * time.Second):
		t.Fatal("setup failed: writer/helper rendezvous did not reach the nested ready-writer branch")
	}
	if !cancelSelectedBeforeDeadline || !helperHeldBeforeEffect {
		t.Fatal("setup failed: cancellation did not precede the unchanged deadline while the helper was held before effect")
	}
	select {
	case <-contextWriterSelected:
	case <-time.After(2 * time.Second):
		t.Fatal("setup failed: nested ready-writer receive was not witnessed")
	}
	resumeHelper()
	partialDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(partialDeadline) {
		if _, err := os.Stat(outputPath + ".partial"); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(outputPath + ".partial"); err != nil {
		t.Fatal("setup failed: helper did not reach its held partial-output state", err)
	}
	partial, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(partial, wantResult[:len(wantResult)/2]) {
		t.Fatal("cancellation cleanup truncated, replaced or changed the helper's partial public output", err)
	}
	if info, err := os.Stat(outputPath); err != nil || outputBefore == nil || !os.SameFile(outputBefore, info) {
		t.Fatal("cancellation cleanup deleted or replaced the partial public output", err)
	}
	resumePartialWrite()
	completionDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(completionDeadline) {
		if _, err := os.Stat(outputPath + ".complete"); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(outputPath + ".complete"); err != nil {
		t.Fatal("setup failed: helper did not emit authentic completion after cancellation", err)
	}
	select {
	case <-childReaped:
	case <-time.After(2 * time.Second):
		t.Fatal("setup failed: the retained child did not finish its single wait/reap")
	}
	releaseResponseCollection.Do(func() { close(responseCollectionAllowed) })
	select {
	case value := <-done:
		result = &value
	case <-time.After(3 * time.Second):
		t.Fatal("helper did not resolve within the original deadline after the cancellation witness")
	}
	if time.Since(started) >= 5*time.Second || !result.evidence.admitted ||
		result.evidence.frameBytes != result.evidence.frameLength || result.evidence.writeErr ||
		!result.evidence.writerCloseOK || !result.evidence.writerJoined || !result.evidence.stdinCloseOK ||
		!result.evidence.readerCloseOK || !result.evidence.waitDone || !result.evidence.outputCloseOK ||
		!result.evidence.contextCancelledDuringInput || writerCount.Load() != 1 || waitCount.Load() != 1 ||
		!result.evidence.statusEOF || !result.evidence.stdoutEOF || !result.evidence.stderrEOF ||
		!result.evidence.resultReadbackOK || result.evidence.waitExit != 0 ||
		!bytes.Equal(result.evidence.result, wantResult) ||
		len(result.evidence.closeObservations) != 11 || !allProcess2ClosesOK(result.evidence.closeObservations) {
		t.Fatalf("intended cancellation lifecycle did not complete its bounded cleanup witness: %+v", result.evidence)
	}
	if info, err := os.Stat(outputPath); err != nil || outputBefore == nil || !os.SameFile(outputBefore, info) {
		t.Fatal("public output path was deleted or replaced after cancellation", err)
	}
	if raw, err := os.ReadFile(outputPath); err != nil || !bytes.HasPrefix(wantResult, raw) {
		t.Fatal("public output bytes were overwritten or corrupted after cancellation", err)
	}
	if result.outcome.Success() {
		t.Fatalf("R1-C regression reproduced: pre-completion cancellation took the context-selected/nested-ready-writer path, but later helper completion released a result and final transaction; evidence=%+v", result.evidence)
	}
	if len(result.outcome.Result()) != 0 || len(result.outcome.FinalTransaction()) != 0 {
		t.Fatal("cancelled incomplete attempt released a result or final transaction")
	}
	assertUnknown(t, result.outcome)
}

// Claim: a child that exits before admission remains UNKNOWN while the actual
// same-child wait and all owned descriptors resolve. Limit: /proc zombie-state
// witness and public helper on Linux; no production identity admission.
func TestProcess2EarlyChildExitBeforeAdmissionStaysUnknown(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "17")
	exitedBeforeAdmission := false
	options.testHooks = &process2RunTestHooks{beforeAdmission: func(process *os.Process) {
		exitedBeforeAdmission = waitForLinuxZombie(process, 2*time.Second)
	}}
	options.Admit = func(context.Context, *os.Process, [32]byte) error {
		if exitedBeforeAdmission {
			return os.ErrProcessDone
		}
		return nil
	}
	outcome, evidence := runProcess2(context.Background(), command, options)
	assertUnknown(t, outcome)
	if !exitedBeforeAdmission || evidence.admitted || evidence.frameBytes != 0 || evidence.writerJoined ||
		!evidence.waitDone || evidence.waitErr || evidence.waitExit != 89 || !evidence.readerCloseOK ||
		!allProcess2ClosesOK(evidence.closeObservations) {
		t.Fatalf("early child exit was not established and resolved before admission: %+v", evidence)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() != 0 {
		t.Fatal("early-exit refusal changed the retained empty output", err)
	}
}

func waitForLinuxZombie(process *os.Process, maximum time.Duration) bool {
	deadline := time.Now().Add(maximum)
	path := filepath.Join("/proc", strconv.Itoa(process.Pid), "stat")
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			closeParen := strings.LastIndexByte(string(data), ')')
			if closeParen >= 0 {
				fields := strings.Fields(string(data[closeParen+1:]))
				if len(fields) > 0 && fields[0] == "Z" {
					return true
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// Claim: real helper EOF can precede same-child reap, and real same-child reap
// can precede reader EOF; both orderings still pass the full success barrier.
// Limit: synchronized public software subprocesses, not native admission.
func TestProcess2EOFAndWaitBothOrderings(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	t.Run("eof-before-wait", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, wantResult, wantAck := process2RunnerFixture(t, helper, outputPath, "15")
		var sequence, eofOrder, waitOrder, eofCount atomic.Int32
		eofReady := make(chan struct{})
		var eofOnce atomic.Bool
		options.testHooks = &process2RunTestHooks{
			afterReader: func(result process2ReaderResult) {
				if result.eof && eofCount.Add(1) == 3 && eofOnce.CompareAndSwap(false, true) {
					eofOrder.Store(sequence.Add(1))
					close(eofReady)
				}
			},
			afterWait: func() { waitOrder.Store(sequence.Add(1)) },
		}
		type runResult struct {
			outcome  Outcome
			evidence process2Evidence
		}
		done := make(chan runResult, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			outcome, evidence := runProcess2(ctx, command, options)
			done <- runResult{outcome: outcome, evidence: evidence}
		}()
		select {
		case <-eofReady:
		case <-time.After(5 * time.Second):
			cancel()
			_ = os.WriteFile(outputPath+".continue", []byte("continue"), 0o600)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			t.Fatal("helper did not produce reader EOF before the parent release")
		}
		if err := os.WriteFile(outputPath+".continue", []byte("continue"), 0o600); err != nil {
			t.Fatal("release helper after witnessed EOF", err)
		}
		result := <-done
		if !result.outcome.Success() || !bytes.Equal(result.outcome.Result(), wantResult) || !bytes.Equal(result.outcome.Line(), wantAck) ||
			!(eofOrder.Load() > 0 && waitOrder.Load() > eofOrder.Load()) {
			t.Fatalf("EOF-before-wait lifecycle did not retain valid success: eof=%d wait=%d evidence=%+v", eofOrder.Load(), waitOrder.Load(), result.evidence)
		}
	})

	t.Run("wait-before-eof", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, wantResult, wantAck := process2RunnerFixture(t, helper, outputPath, "16")
		var sequence, eofOrder, waitOrder atomic.Int32
		waitReady := make(chan struct{})
		var eofOnce atomic.Bool
		options.testHooks = &process2RunTestHooks{
			beforeReader: func(process2ReaderKind) { <-waitReady },
			afterReader: func(result process2ReaderResult) {
				if result.eof && eofOnce.CompareAndSwap(false, true) {
					eofOrder.Store(sequence.Add(1))
				}
			},
			afterWait: func() {
				waitOrder.Store(sequence.Add(1))
				close(waitReady)
			},
		}
		type runResult struct {
			outcome  Outcome
			evidence process2Evidence
		}
		done := make(chan runResult, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			outcome, evidence := runProcess2(ctx, command, options)
			done <- runResult{outcome: outcome, evidence: evidence}
		}()
		var result runResult
		select {
		case result = <-done:
		case <-time.After(5 * time.Second):
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			t.Fatal("wait-before-EOF control did not resolve its child and readers")
		}
		if !result.outcome.Success() || !bytes.Equal(result.outcome.Result(), wantResult) || !bytes.Equal(result.outcome.Line(), wantAck) ||
			!(waitOrder.Load() > 0 && eofOrder.Load() > waitOrder.Load()) {
			t.Fatalf("wait-before-EOF lifecycle did not retain valid success: wait=%d eof=%d evidence=%+v", waitOrder.Load(), eofOrder.Load(), result.evidence)
		}
	})
}
