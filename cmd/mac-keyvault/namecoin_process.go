//go:build darwin || linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type namecoinSigningResult struct {
	outcome      namecoinprocess.Outcome
	requestID    string
	sittingID    string
	unsignedTxID string
}

type namecoinSignRunner func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error)

type namecoinObservation struct {
	event       namecoinprocess.RunnerEvent
	beforeInput bool
}

type namecoinObservedReader struct {
	state  *namecoinProcess1
	reader io.Reader
}

func (r namecoinObservedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n != 0 || errors.Is(err, io.EOF) {
		r.state.recordChildObservation()
	}
	return n, err
}

type namecoinProcess1 struct {
	ctx        context.Context
	args       namecoinprocess.Args
	helper     string
	pin        []byte
	helperArgv []string
	status     namecoinprocess.StatusObservationSource
	expect     namecoinprocess.StatusExpectation
	prepared   namecoinprocess.Prepared
	runner     *namecoinprocess.Runner

	cmd         *exec.Cmd
	output      *namecoinfiles.Output
	command     func(string, ...string) *exec.Cmd
	verifyChild func(int, []byte) error

	stdinRead, stdinWrite   *os.File
	statusRead, statusWrite *os.File
	stdoutRead, stdoutWrite *os.File
	stderrRead, stderrWrite *os.File

	child            namecoinprocess.RunnerChild
	events           chan namecoinObservation
	started          time.Time
	waitGate         chan struct{}
	waitGateOnce     sync.Once
	workerWG         sync.WaitGroup
	workersDone      chan struct{}
	statusReaderDone chan struct{}

	gateMu            sync.Mutex
	inputReleased     bool
	earlyObservation  bool
	resourcesClosed   bool
	transferErr       bool
	closeErr          bool
	waitDone          atomic.Bool
	waitUnconfirmed   atomic.Bool
	statusEOFObserved atomic.Bool
	statusReadFailed  atomic.Bool
	protocolEarly     atomic.Bool
	hardDeadline      atomic.Bool
	timer             *time.Timer
	timerC            <-chan time.Time
}

func runNamecoinSign(ctx context.Context, args namecoinprocess.Args, status namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
	if ctx == nil || status == nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	if ctx.Err() != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.AuthRefused, false)
	}
	helper, pin, err := keyvault.NamecoinProcessHelper()
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
	}
	prepared, err := namecoinprocess.PrepareSigningFiles(args, time.Now())
	if err != nil {
		return namecoinSigningResult{}, namecoinFailure(err, false)
	}
	expectation, err := prepared.StatusExpectation()
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	helperArgv, err := namecoinprocess.HelperArgs(args)
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	state, err := newNamecoinProcess1(ctx, args, helper, pin, helperArgv, status, expectation, prepared)
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.OutputUnavailable, false)
	}
	runner, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: prepared.Attempt()}, args.Timeout)
	if err != nil {
		_ = state.closeOwned()
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	state.runner = runner
	outcome, err := state.run()
	if err != nil {
		return namecoinSigningResult{}, err
	}
	request, err := namecoinwire.Decode(prepared.InputBytes())
	if err != nil || !outcome.Success() {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
	}
	return namecoinSigningResult{outcome: outcome, requestID: request.Request().RequestID,
		sittingID: request.Request().SittingID, unsignedTxID: prepared.Attempt().Candidate().View().UnsignedTxID}, nil
}

func namecoinFailure(err error, effectPossible bool) error {
	var failure namecoinwire.Failure
	if errors.As(err, &failure) {
		return namecoinwire.NewFailure(failure.Code(), effectPossible)
	}
	return namecoinwire.NewFailure(namecoinwire.InvalidRequest, effectPossible)
}

func newNamecoinProcess1(ctx context.Context, args namecoinprocess.Args, helper string, pin []byte, helperArgv []string, status namecoinprocess.StatusObservationSource, expectation namecoinprocess.StatusExpectation, prepared namecoinprocess.Prepared) (*namecoinProcess1, error) {
	if ctx == nil || args.Mode != namecoinprocess.SignPSBT || helper == "" || len(pin) == 0 || len(helperArgv) < 4 || status == nil || expectation.Mode != namecoinprocess.RunnerSign || prepared.Mode() != namecoinprocess.SignPSBT {
		return nil, namecoinwire.ErrInvalidRequest
	}
	s := &namecoinProcess1{ctx: ctx, args: args, helper: helper, pin: append([]byte(nil), pin...), helperArgv: append([]string(nil), helperArgv...),
		status: status, expect: expectation, prepared: prepared, child: 1, events: make(chan namecoinObservation, 32),
		command: exec.Command, verifyChild: keyvault.VerifyNamecoinProcessHelper,
		waitGate: make(chan struct{}), workersDone: make(chan struct{}), statusReaderDone: make(chan struct{})}
	var err error
	if s.stdinRead, s.stdinWrite, err = os.Pipe(); err != nil {
		return nil, err
	}
	if s.statusRead, s.statusWrite, err = os.Pipe(); err != nil {
		_ = s.closeOwned()
		return nil, err
	}
	if s.stdoutRead, s.stdoutWrite, err = os.Pipe(); err != nil {
		_ = s.closeOwned()
		return nil, err
	}
	if s.stderrRead, s.stderrWrite, err = os.Pipe(); err != nil {
		_ = s.closeOwned()
		return nil, err
	}
	if s.output, err = namecoinfiles.CreateOutput(args.OutputPath); err != nil {
		_ = s.closeOwned()
		return nil, err
	}
	return s, nil
}

func (s *namecoinProcess1) run() (namecoinprocess.Outcome, error) {
	s.started = time.Now()
	defer s.stopTimer()
	if s.ctx.Err() != nil {
		_ = s.closeOwned()
		return namecoinprocess.Outcome{}, namecoinwire.NewFailure(namecoinwire.AuthRefused, false)
	}
	actions, outcome := s.runner.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerBegin})
	s.apply(actions)
	if outcome.Done() {
		return s.finish(outcome)
	}
	ctxDone := s.ctx.Done()
	workersDone := s.workersDone
	workersFinished := false
	for {
		select {
		case observation := <-s.events:
			if observation.beforeInput {
				s.protocolEarly.Store(true)
				actions, outcome = s.runner.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault, At: s.elapsed()})
			} else {
				observation.event.At = s.elapsed()
				actions, outcome = s.runner.Step(observation.event)
			}
			s.apply(actions)
			if outcome.Done() {
				return s.finish(outcome)
			}
			if workersFinished && len(s.events) == 0 {
				return s.finishUnknown()
			}
			if s.waitDone.Load() && (s.statusReadFailed.Load() || s.protocolEarly.Load()) {
				select {
				case <-s.statusReaderDone:
					if !s.statusEOFObserved.Load() || s.protocolEarly.Load() {
						return s.finishUnknown()
					}
				default:
				}
			}
		case <-ctxDone:
			ctxDone = nil
			actions, outcome = s.runner.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerCancel, At: s.elapsed()})
			s.apply(actions)
			if outcome.Done() {
				return s.finish(outcome)
			}
		case <-s.timerC:
			s.timerC = nil
			at := s.elapsed()
			if at >= s.args.Timeout {
				s.hardDeadline.Store(true)
			}
			actions, outcome = s.runner.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerTick, At: at})
			s.apply(actions)
			if outcome.Done() {
				return s.finish(outcome)
			}
			if s.hardDeadline.Load() && s.waitDone.Load() && !s.statusEOFObserved.Load() {
				_ = closeProcessFile(&s.statusRead)
				s.statusReadFailed.Store(true)
			}
		case <-workersDone:
			workersDone = nil
			workersFinished = true
			if len(s.events) == 0 {
				return s.finishUnknown()
			}
		}
	}
}

func (s *namecoinProcess1) apply(actions []namecoinprocess.RunnerAction) {
	for _, action := range actions {
		switch action.Kind {
		case namecoinprocess.RunnerStartChild:
			s.startChild()
		case namecoinprocess.RunnerAdmitChild:
			s.admitChild()
		case namecoinprocess.RunnerReleaseInputs:
			s.releaseInputs()
		case namecoinprocess.RunnerTerminateChild:
			s.signalChild(syscall.SIGTERM)
		case namecoinprocess.RunnerKillChild:
			s.signalChild(syscall.SIGKILL)
		case namecoinprocess.RunnerReapChild:
			s.openWaitGate()
		case namecoinprocess.RunnerWaitUntil:
			s.schedule(action.At)
		case namecoinprocess.RunnerReadResult:
			s.readResult()
		case namecoinprocess.RunnerCloseOwned:
			s.closeForRunner()
		case namecoinprocess.RunnerEmitOutcome:
		}
	}
}

func (s *namecoinProcess1) startChild() {
	if s.ctx.Err() != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStartRefused, Code: namecoinwire.AuthRefused})
		return
	}
	resultFile, err := s.output.FileForChild()
	if err != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStartRefused, Code: namecoinwire.OutputUnavailable})
		return
	}
	cmd := s.command(s.helper, s.helperArgv...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.stdinRead, s.stdoutWrite, s.stderrWrite
	cmd.ExtraFiles = []*os.File{resultFile, s.statusWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.cmd = cmd
	startErr := cmd.Start()
	if cmd.Process == nil {
		if s.closeTransferFiles() != nil {
			s.transferErr = true
		}
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStartRefused, Code: namecoinwire.HelperNotAdmitted})
		return
	}
	if s.closeTransferFiles() != nil {
		s.transferErr = true
	}
	statusRead, stdoutRead, stderrRead := s.statusRead, s.stdoutRead, s.stderrRead
	s.workerWG.Add(4)
	go func() { defer s.workerWG.Done(); s.readStatus(statusRead) }()
	go func() { defer s.workerWG.Done(); s.readStdout(stdoutRead) }()
	go func() { defer s.workerWG.Done(); s.readStderr(stderrRead) }()
	go func() { defer s.workerWG.Done(); s.waitChild() }()
	go func() { s.workerWG.Wait(); close(s.workersDone) }()
	s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStarted, Child: s.child})
	if startErr != nil || s.transferErr {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
	}
}

func (s *namecoinProcess1) admitChild() {
	if s.ctx.Err() != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerCancel})
		return
	}
	if s.cmd == nil || s.cmd.Process == nil || s.waitDone.Load() || s.verifyChild(s.cmd.Process.Pid, s.pin) != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
		return
	}
	if s.ctx.Err() != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerCancel})
		return
	}
	s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerAdmitted, Child: s.child})
}

func (s *namecoinProcess1) releaseInputs() {
	s.gateMu.Lock()
	earlyObservation := s.earlyObservation
	cancelled := s.ctx.Err() != nil
	if earlyObservation || cancelled {
		s.gateMu.Unlock()
		kind := namecoinprocess.RunnerFault
		if cancelled {
			kind = namecoinprocess.RunnerCancel
		}
		s.post(namecoinprocess.RunnerEvent{Kind: kind})
		return
	}
	err := closeProcessFile(&s.stdinWrite)
	if err == nil {
		s.inputReleased = true
	}
	s.gateMu.Unlock()
	if err != nil {
		s.transferErr = true
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
		return
	}
	s.openWaitGate()
}

func (s *namecoinProcess1) signalChild(signal os.Signal) {
	if s.cmd == nil || s.cmd.Process == nil || s.waitDone.Load() {
		return
	}
	_ = s.cmd.Process.Signal(signal)
	if signal == syscall.SIGKILL {
		s.hardDeadline.Store(true)
	}
	s.openWaitGate()
}

func (s *namecoinProcess1) openWaitGate() {
	s.waitGateOnce.Do(func() { close(s.waitGate) })
}

func (s *namecoinProcess1) waitChild() {
	<-s.waitGate
	_ = s.cmd.Wait()
	state := s.cmd.ProcessState
	s.waitDone.Store(true)
	if state == nil {
		s.waitUnconfirmed.Store(true)
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
		return
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
		s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerExited, Child: s.child, Exit: -1})
		s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerReaped, Child: s.child})
		return
	}
	s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerExited, Child: s.child,
		Exit: status.ExitStatus(), Normal: status.Exited()})
	s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerReaped, Child: s.child})
}

func (s *namecoinProcess1) readStatus(reader *os.File) {
	defer close(s.statusReaderDone)
	eof, err := s.status.ReadStatus(s.ctx, namecoinObservedReader{state: s, reader: reader}, s.expect, func(record namecoinprocess.StatusRecord) error {
		s.postChild(namecoinprocess.RunnerEvent{Kind: record.Kind, Child: s.child, Digest: record.Digest})
		return nil
	})
	if err != nil {
		s.statusReadFailed.Store(true)
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
	}
	if eof {
		s.statusEOFObserved.Store(true)
		s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStatusEOF})
	}
}

func (s *namecoinProcess1) readStdout(reader *os.File) {
	var captured []byte
	var chunk [512]byte
	overflow := false
	for {
		n, err := reader.Read(chunk[:])
		if n != 0 || errors.Is(err, io.EOF) {
			s.recordChildObservation()
		}
		if n > 0 {
			if len(captured)+n > 512 {
				overflow = true
			} else if !overflow {
				captured = append(captured, chunk[:n]...)
			}
		}
		if err == io.EOF {
			if overflow {
				s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
			} else if len(captured) != 0 {
				s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStdout, Child: s.child, Data: captured})
			}
			s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerEOF, Child: s.child})
			return
		}
		if err != nil {
			s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
			return
		}
	}
}

func (s *namecoinProcess1) readStderr(reader *os.File) {
	var chunk [256]byte
	seen := false
	for {
		n, err := reader.Read(chunk[:])
		if n != 0 || errors.Is(err, io.EOF) {
			s.recordChildObservation()
		}
		if n > 0 {
			seen = true
		}
		if err == io.EOF {
			if seen {
				s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
			}
			s.postChild(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerStderrEOF, Child: s.child})
			return
		}
		if err != nil {
			s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerFault})
			return
		}
	}
}

func (s *namecoinProcess1) readResult() {
	if s.output == nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerReadbackFailed})
		return
	}
	raw, err := s.output.ReadResult(namecoinprocess.MaxProcessResultBytes)
	if err != nil {
		s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerReadbackFailed})
		return
	}
	s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerReadback, Data: raw})
}

func (s *namecoinProcess1) closeForRunner() {
	err := s.closeOwned()
	s.post(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerClosed, OK: err == nil})
}

func (s *namecoinProcess1) closeTransferFiles() error {
	var failed bool
	for _, file := range []**os.File{&s.statusWrite, &s.stdoutWrite, &s.stderrWrite, &s.stdinRead} {
		if closeProcessFile(file) != nil {
			failed = true
		}
	}
	if failed {
		return namecoinfiles.ErrUnsafe
	}
	return nil
}

func closeProcessFile(file **os.File) error {
	if file == nil || *file == nil {
		return nil
	}
	f := *file
	*file = nil // A failed close is consumed; never retry a possibly reused fd.
	return f.Close()
}

func (s *namecoinProcess1) closeOwned() error {
	if s.resourcesClosed {
		if s.closeErr || s.transferErr {
			return namecoinfiles.ErrUnsafe
		}
		return nil
	}
	s.resourcesClosed = true
	for _, file := range []**os.File{&s.stdinRead, &s.stdinWrite, &s.statusRead, &s.statusWrite,
		&s.stdoutRead, &s.stdoutWrite, &s.stderrRead, &s.stderrWrite} {
		if closeProcessFile(file) != nil {
			s.closeErr = true
		}
	}
	if s.output != nil {
		output := s.output
		s.output = nil
		if output.Close() != nil {
			s.closeErr = true
		}
	}
	if s.closeErr || s.transferErr {
		return namecoinfiles.ErrUnsafe
	}
	return nil
}

func (s *namecoinProcess1) finish(outcome namecoinprocess.Outcome) (namecoinprocess.Outcome, error) {
	if outcome.Success() {
		return outcome, nil
	}
	failure, err := namecoinwire.DecodeFailure(outcome.Line())
	if err != nil {
		return outcome, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
	}
	return outcome, failure
}

func (s *namecoinProcess1) finishUnknown() (namecoinprocess.Outcome, error) {
	_ = s.closeOwned()
	return namecoinprocess.Outcome{}, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
}

func (s *namecoinProcess1) elapsed() time.Duration { return time.Since(s.started) }

func (s *namecoinProcess1) schedule(at time.Duration) {
	delay := time.Until(s.started.Add(at))
	if delay < 0 {
		delay = 0
	}
	if s.timer == nil {
		s.timer = time.NewTimer(delay)
	} else {
		if !s.timer.Stop() {
			select {
			case <-s.timer.C:
			default:
			}
		}
		s.timer.Reset(delay)
	}
	s.timerC = s.timer.C
}

func (s *namecoinProcess1) stopTimer() {
	if s.timer != nil && !s.timer.Stop() {
		select {
		case <-s.timer.C:
		default:
		}
	}
}

func (s *namecoinProcess1) post(event namecoinprocess.RunnerEvent) {
	s.events <- namecoinObservation{event: event}
}

func (s *namecoinProcess1) postChild(event namecoinprocess.RunnerEvent) {
	beforeInput := s.recordChildObservation()
	s.events <- namecoinObservation{event: event, beforeInput: beforeInput}
}

func (s *namecoinProcess1) recordChildObservation() bool {
	s.gateMu.Lock()
	beforeInput := !s.inputReleased
	if beforeInput {
		s.earlyObservation = true
		s.protocolEarly.Store(true)
	}
	s.gateMu.Unlock()
	return beforeInput
}

func namecoinResultDigest(result []byte) string {
	digest := sha256.Sum256(result)
	return hex.EncodeToString(digest[:])
}

func namecoinSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
