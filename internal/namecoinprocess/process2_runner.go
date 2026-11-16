//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"golang.org/x/sys/unix"
)

const (
	process2MaxStatusBytes = Process2SuccessStatusBytes
	process2MaxStdoutBytes = 512
)

// Process2Admission must synchronously, read-only check the exact retained,
// still-unreaped child against the full helper identity pinned by its trusted
// caller. It must honor ctx and must not wait, signal, release, retain, or
// otherwise act on the process. No default admission exists; a fixture
// callback is not production identity evidence.
type Process2Admission func(context.Context, *os.Process, [32]byte) error

type Process2RunOptions struct {
	Invocation          Process2Invocation
	AttemptInputs       Process2AttemptInputs
	Verification        RunnerContext
	Frame               []byte
	Deadline            time.Time
	Admit               Process2Admission
	custodyPipeCapacity int
	testHooks           *process2RunTestHooks
}

// process2RunTestHooks provide deterministic scheduling seams to same-package
// subprocess tests. Production callers cannot set these hooks.
type process2RunTestHooks struct {
	beforeAdmission       func(*os.Process)
	beforeWriter          func()
	writerComplete        func()
	contextSelected       func()
	contextWriterSelected func()
	deadlineSelected      func()
	beforeReader          func(process2ReaderKind)
	afterReader           func(process2ReaderResult)
	afterWait             func()
	afterEvidence         func()
	afterFinalValidation  func()
	finalDeadlineNow      func() time.Time
}

// RunProcess2 consumes command for one process/2 sign-psbt attempt. The trusted
// caller must resolve command.Path to the fixed paired helper and supply its
// pinned live identity admission callback. Callers must not separately wait,
// release or signal the child. This adapter exposes no helper-path setting to
// request parsing and never retries an attempt.
func RunProcess2(ctx context.Context, command *exec.Cmd, options Process2RunOptions) Outcome {
	outcome, _ := runProcess2(ctx, command, options)
	return outcome
}

type process2FD struct {
	name     string
	file     *os.File
	mu       sync.Mutex
	closed   bool
	closeErr error
}

type process2CloseObservation struct {
	resource  string
	attempted bool
	ok        bool
}

func ownProcess2FD(name string, file *os.File) *process2FD {
	if file == nil {
		return nil
	}
	return &process2FD{name: name, file: file}
}

func (fd *process2FD) close() error {
	if fd == nil {
		return os.ErrInvalid
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.closed {
		fd.closed = true
		fd.closeErr = fd.file.Close()
	}
	return fd.closeErr
}

func (fd *process2FD) closeObservation() process2CloseObservation {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return process2CloseObservation{resource: fd.name, attempted: fd.closed, ok: fd.closed && fd.closeErr == nil}
}

type process2Pipe struct {
	read, write *process2FD
}

func newProcess2Pipe(name string) (process2Pipe, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return process2Pipe{}, err
	}
	return process2Pipe{read: ownProcess2FD(name+".read", r), write: ownProcess2FD(name+".write", w)}, nil
}

type process2ReaderKind uint8

const (
	process2ReaderStatus process2ReaderKind = iota + 1
	process2ReaderStdout
	process2ReaderStderr
)

type process2ReaderResult struct {
	kind     process2ReaderKind
	data     []byte
	eof      bool
	overflow bool
	hadBytes bool
	readErr  error
	closeErr error
}

type process2WaitResult struct {
	err  error
	exit int
}

// process2Child serializes every signal against the one WNOHANG wait loop. A
// successful Wait4 marks the retained child reaped while holding mu; after
// that point no PID-derived operation is issued. Using WNOHANG lets abort
// signaling proceed without racing a blocking reap.
type process2Child struct {
	mu       sync.Mutex
	process  *os.Process
	pid      int
	terminal bool
}

func newProcess2Child(process *os.Process) *process2Child {
	return &process2Child{process: process, pid: process.Pid}
}

func (child *process2Child) wait() process2WaitResult {
	for {
		child.mu.Lock()
		if child.terminal {
			child.mu.Unlock()
			return process2WaitResult{err: os.ErrProcessDone, exit: -1}
		}
		var status unix.WaitStatus
		pid, err := unix.Wait4(child.pid, &status, unix.WNOHANG, nil)
		if err == nil && pid == child.pid {
			child.terminal = true
			releaseErr := child.process.Release()
			child.mu.Unlock()
			exit := -1
			if status.Exited() {
				exit = status.ExitStatus()
			} else if status.Signaled() {
				exit = 128 + int(status.Signal())
			}
			return process2WaitResult{err: releaseErr, exit: exit}
		}
		if err == unix.EINTR {
			child.mu.Unlock()
			continue
		}
		if err != nil {
			child.terminal = true
			releaseErr := child.process.Release()
			child.mu.Unlock()
			if releaseErr != nil {
				err = errors.Join(err, releaseErr)
			}
			return process2WaitResult{err: err, exit: -1}
		}
		if pid != 0 {
			child.terminal = true
			releaseErr := child.process.Release()
			child.mu.Unlock()
			err := error(os.ErrProcessDone)
			if releaseErr != nil {
				err = errors.Join(err, releaseErr)
			}
			return process2WaitResult{err: err, exit: -1}
		}
		child.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

func (child *process2Child) kill() error {
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.terminal {
		return os.ErrProcessDone
	}
	return child.process.Kill()
}

func readProcess2Bounded(kind process2ReaderKind, fd *process2FD, maximum int) process2ReaderResult {
	result := process2ReaderResult{kind: kind, data: make([]byte, 0, maximum)}
	buffer := make([]byte, 4096)
	for {
		n, err := fd.file.Read(buffer)
		if n > 0 {
			result.hadBytes = true
			keep := maximum - len(result.data)
			if keep > n {
				keep = n
			}
			if keep > 0 {
				result.data = append(result.data, buffer[:keep]...)
			}
			if keep < n {
				result.overflow = true
			}
		}
		if err == io.EOF {
			result.eof = true
			break
		}
		if err != nil {
			result.readErr = err
			break
		}
	}
	result.closeErr = fd.close()
	return result
}

func closeProcess2FDs(fds ...*process2FD) bool {
	ok := true
	for _, fd := range fds {
		if fd != nil && fd.close() != nil {
			ok = false
		}
	}
	return ok
}

func runProcess2(ctx context.Context, command *exec.Cmd, options Process2RunOptions) (Outcome, process2Evidence) {
	evidence := process2Evidence{context: options.Verification, invocation: options.Invocation,
		binding: options.AttemptInputs.binding(), frameLength: len(options.Frame)}
	unknown := unknownProcess2Outcome()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return unknown, evidence
	}
	if !validProcess2Request(options) {
		return invalidProcess2RequestOutcome(), evidence
	}
	if !validProcess2Launch(command, options) {
		return unknown, evidence
	}
	remaining := time.Until(options.Deadline)
	if remaining <= 0 || remaining > options.Invocation.args.Timeout {
		return unknown, evidence
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	deadlineChannel := timer.C
	contextChannel := ctx.Done()
	frame := bytes.Clone(options.Frame)
	defer clear(frame)
	output, err := namecoinfiles.CreateOutput(options.Invocation.args.OutputPath)
	if err != nil {
		return unknown, evidence
	}
	outputFile, err := output.FileForChild()
	if err != nil {
		_ = output.Close()
		return unknown, evidence
	}
	unix.CloseOnExec(int(outputFile.Fd()))

	stdin, err := newProcess2Pipe("stdin")
	if err != nil {
		_ = output.Close()
		return unknown, evidence
	}
	status, err := newProcess2Pipe("fd4-status")
	if err != nil {
		closeProcess2FDs(stdin.read, stdin.write)
		_ = output.Close()
		return unknown, evidence
	}
	custody, err := newProcess2Pipe("fd5-custody")
	if err != nil {
		closeProcess2FDs(stdin.read, stdin.write, status.read, status.write)
		_ = output.Close()
		return unknown, evidence
	}
	if options.custodyPipeCapacity > 0 {
		if err := setProcess2PipeCapacity(custody.read.file.Fd(), options.custodyPipeCapacity); err != nil {
			closeProcess2FDs(stdin.read, stdin.write, status.read, status.write, custody.read, custody.write)
			_ = output.Close()
			return unknown, evidence
		}
	}
	stdout, err := newProcess2Pipe("stdout")
	if err != nil {
		closeProcess2FDs(stdin.read, stdin.write, status.read, status.write, custody.read, custody.write)
		_ = output.Close()
		return unknown, evidence
	}
	stderr, err := newProcess2Pipe("stderr")
	if err != nil {
		closeProcess2FDs(stdin.read, stdin.write, status.read, status.write, custody.read, custody.write, stdout.read, stdout.write)
		_ = output.Close()
		return unknown, evidence
	}
	allFDs := []*process2FD{stdin.read, stdin.write, status.read, status.write, custody.read, custody.write,
		stdout.read, stdout.write, stderr.read, stderr.write}
	for _, fd := range allFDs {
		unix.CloseOnExec(int(fd.file.Fd()))
	}
	if ctx.Err() != nil || !time.Now().Before(options.Deadline) {
		closeProcess2FDs(allFDs...)
		_ = output.Close()
		return unknown, evidence
	}

	readerChannel := make(chan process2ReaderResult, 3)
	startReader := func(kind process2ReaderKind, fd *process2FD, maximum int) {
		go func() {
			if hooks := options.testHooks; hooks != nil && hooks.beforeReader != nil {
				hooks.beforeReader(kind)
			}
			result := readProcess2Bounded(kind, fd, maximum)
			if hooks := options.testHooks; hooks != nil && hooks.afterReader != nil {
				hooks.afterReader(result)
			}
			readerChannel <- result
		}()
	}
	startReader(process2ReaderStatus, status.read, process2MaxStatusBytes)
	startReader(process2ReaderStdout, stdout.read, process2MaxStdoutBytes)
	startReader(process2ReaderStderr, stderr.read, 0)

	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = stdin.read.file
	command.Stdout = stdout.write.file
	command.Stderr = stderr.write.file
	command.ExtraFiles = []*os.File{outputFile, status.write.file, custody.read.file}
	startErr := command.Start()
	if startErr != nil && command.Process == nil {
		closeProcess2FDs(allFDs...)
		for i := 0; i < 3; i++ {
			<-readerChannel
		}
		evidence.outputCloseOK = output.Close() == nil
		return unknown, evidence
	}
	if command.Process == nil {
		closeProcess2FDs(allFDs...)
		for i := 0; i < 3; i++ {
			<-readerChannel
		}
		evidence.outputCloseOK = output.Close() == nil
		return unknown, evidence
	}

	waitPermit := make(chan struct{})
	waitChannel := make(chan process2WaitResult, 1)
	child := newProcess2Child(command.Process)
	go func() {
		<-waitPermit
		result := child.wait()
		if hooks := options.testHooks; hooks != nil && hooks.afterWait != nil {
			hooks.afterWait()
		}
		waitChannel <- result
	}()
	permitOnce := sync.Once{}
	releaseWait := func() { permitOnce.Do(func() { close(waitPermit) }) }
	childEndsCloseOK := closeProcess2FDs(stdin.read, status.write, custody.read, stdout.write, stderr.write)
	evidence.childEndsCloseOK = childEndsCloseOK
	inputTerminal := false
	deadlineExpired := false
	contextWriterReady := false
	stdinClosed := false
	closeStdinWriter := func() bool {
		if stdinClosed {
			return evidence.stdinCloseOK
		}
		stdinClosed = true
		evidence.stdinCloseOK = stdin.write.close() == nil
		return evidence.stdinCloseOK
	}
	closeCustodyWriter := func() bool {
		evidence.writerCloseOK = custody.write.close() == nil
		return evidence.writerCloseOK
	}
	killRetainedChild := func() {
		// child.mu fences this retained handle's signal against Wait4 reaping;
		// no name/PID lookup or signal occurs after the wait loop is terminal.
		_ = child.kill()
	}
	abortBeforeWait := func() {
		closeStdinWriter()
		closeCustodyWriter()
		inputTerminal = true
		killRetainedChild()
		releaseWait()
	}

	processStarted := startErr == nil
	if !childEndsCloseOK || !processStarted {
		abortBeforeWait()
	} else {
		if hooks := options.testHooks; hooks != nil && hooks.beforeAdmission != nil {
			hooks.beforeAdmission(command.Process)
		}
		admissionContext, cancelAdmission := context.WithDeadline(ctx, options.Deadline)
		admitErr := options.Admit(admissionContext, command.Process, evidence.binding)
		cancelAdmission()
		if admitErr != nil || ctx.Err() != nil || !time.Now().Before(options.Deadline) {
			abortBeforeWait()
		} else if !childEndsCloseOK {
			abortBeforeWait()
		} else if !closeStdinWriter() {
			closeCustodyWriter()
			inputTerminal = true
			killRetainedChild()
			releaseWait()
		} else {
			evidence.admitted = true
			writerChannel := make(chan struct {
				written int
				err     error
				close   error
			}, 1)
			go func() {
				if hooks := options.testHooks; hooks != nil && hooks.beforeWriter != nil {
					hooks.beforeWriter()
				}
				written, writeErr := custody.write.file.Write(frame)
				closeErr := custody.write.close()
				writerChannel <- struct {
					written int
					err     error
					close   error
				}{written: written, err: writeErr, close: closeErr}
				if hooks := options.testHooks; hooks != nil && hooks.writerComplete != nil {
					hooks.writerComplete()
				}
			}()
			select {
			case writer := <-writerChannel:
				evidence.frameBytes = writer.written
				evidence.writeErr = writer.err != nil
				evidence.writerCloseOK = writer.close == nil
				evidence.writerJoined = true
				inputTerminal = true
				releaseWait()
			case <-contextChannel:
				evidence.contextCancelledDuringInput = true
				if hooks := options.testHooks; hooks != nil && hooks.contextSelected != nil {
					hooks.contextSelected()
				}
				select {
				case writer := <-writerChannel:
					contextWriterReady = true
					evidence.frameBytes = writer.written
					evidence.writeErr = writer.err != nil
					evidence.writerCloseOK = writer.close == nil
					evidence.writerJoined = true
					inputTerminal = true
					releaseWait()
					if hooks := options.testHooks; hooks != nil && hooks.contextWriterSelected != nil {
						hooks.contextWriterSelected()
					}
				default:
					closeCustodyWriter()
					inputTerminal = true
					killRetainedChild()
					writer := <-writerChannel
					evidence.frameBytes = writer.written
					evidence.writeErr = writer.err != nil
					evidence.writerCloseOK = writer.close == nil
					evidence.writerJoined = true
					releaseWait()
				}
				contextChannel = nil
			case <-deadlineChannel:
				deadlineExpired = true
				if hooks := options.testHooks; hooks != nil && hooks.deadlineSelected != nil {
					hooks.deadlineSelected()
				}
				select {
				case writer := <-writerChannel:
					evidence.frameBytes = writer.written
					evidence.writeErr = writer.err != nil
					evidence.writerCloseOK = writer.close == nil
					evidence.writerJoined = true
					inputTerminal = true
					releaseWait()
				default:
					closeCustodyWriter()
					inputTerminal = true
					killRetainedChild()
					writer := <-writerChannel
					evidence.frameBytes = writer.written
					evidence.writeErr = writer.err != nil
					evidence.writerCloseOK = writer.close == nil
					evidence.writerJoined = true
					releaseWait()
				}
				deadlineChannel = nil
			}
		}
	}
	if !inputTerminal {
		abortBeforeWait()
	}

	var statusResult, stdoutResult, stderrResult *process2ReaderResult
	waitReceived := evidence.waitDone
	readerCount := 0
	collectReady := func() {
		for {
			select {
			case result := <-readerChannel:
				copy := result
				switch result.kind {
				case process2ReaderStatus:
					statusResult = &copy
				case process2ReaderStdout:
					stdoutResult = &copy
				case process2ReaderStderr:
					stderrResult = &copy
				}
				readerCount++
			default:
				if !waitReceived {
					select {
					case wait := <-waitChannel:
						evidence.waitDone = true
						evidence.waitErr = wait.err != nil
						evidence.waitExit = wait.exit
						waitReceived = true
					default:
					}
				}
				return
			}
		}
	}
	collectReady()
	if contextWriterReady && (!waitReceived || readerCount < 3) {
		if !waitReceived {
			killRetainedChild()
		}
		closeProcess2FDs(status.read, stdout.read, stderr.read)
	}
	if deadlineExpired && (!waitReceived || readerCount < 3) {
		if !waitReceived {
			killRetainedChild()
		}
		closeProcess2FDs(status.read, stdout.read, stderr.read)
	}
	if !processStarted || !childEndsCloseOK || !evidence.admitted {
		closeProcess2FDs(status.read, stdout.read, stderr.read)
	}
	for readerCount < 3 || !waitReceived {
		select {
		case result := <-readerChannel:
			copy := result
			switch result.kind {
			case process2ReaderStatus:
				statusResult = &copy
			case process2ReaderStdout:
				stdoutResult = &copy
			case process2ReaderStderr:
				stderrResult = &copy
			}
			readerCount++
		case wait := <-waitChannel:
			evidence.waitDone = true
			evidence.waitErr = wait.err != nil
			evidence.waitExit = wait.exit
			waitReceived = true
		case <-contextChannel:
			collectReady()
			if !waitReceived || readerCount < 3 {
				if !waitReceived {
					killRetainedChild()
				}
				closeProcess2FDs(status.read, stdout.read, stderr.read)
			}
			contextChannel = nil
		case <-deadlineChannel:
			deadlineExpired = true
			collectReady()
			if !waitReceived || readerCount < 3 {
				if !waitReceived {
					killRetainedChild()
				}
				closeProcess2FDs(status.read, stdout.read, stderr.read)
			}
			deadlineChannel = nil
		}
	}
	if statusResult != nil {
		evidence.status = statusResult.data
		evidence.statusEOF = statusResult.eof
		evidence.statusOverflow = statusResult.overflow
	}
	if stdoutResult != nil {
		evidence.stdout = stdoutResult.data
		evidence.stdoutEOF = stdoutResult.eof
		evidence.stdoutOverflow = stdoutResult.overflow
	}
	if stderrResult != nil {
		evidence.stderrEOF = stderrResult.eof
		evidence.stderrHadBytes = stderrResult.hadBytes
	}
	evidence.readerCloseOK = statusResult != nil && statusResult.closeErr == nil &&
		stdoutResult != nil && stdoutResult.closeErr == nil && stderrResult != nil && stderrResult.closeErr == nil
	if evidence.waitDone && evidence.waitExit == 0 && !evidence.waitErr {
		result, readErr := output.ReadResult(MaxProcessResultBytes)
		if readErr == nil {
			evidence.result = result
			evidence.resultReadbackOK = true
		}
	}
	evidence.outputCloseOK = output.Close() == nil
	evidence.closeObservations = make([]process2CloseObservation, 0, len(allFDs)+1)
	for _, fd := range allFDs {
		evidence.closeObservations = append(evidence.closeObservations, fd.closeObservation())
	}
	evidence.closeObservations = append(evidence.closeObservations,
		process2CloseObservation{resource: "fd3-retained-output", attempted: true, ok: evidence.outputCloseOK})
	if deadlineExpired || !time.Now().Before(options.Deadline) {
		evidence.resultReadbackOK = false
	}
	if hooks := options.testHooks; hooks != nil && hooks.afterEvidence != nil {
		hooks.afterEvidence()
	}
	evidence.finalDeadlineOK = func() bool {
		if deadlineExpired {
			return false
		}
		now := time.Now()
		if hooks := options.testHooks; hooks != nil && hooks.finalDeadlineNow != nil {
			now = hooks.finalDeadlineNow()
		}
		return now.Before(options.Deadline)
	}
	if hooks := options.testHooks; hooks != nil {
		evidence.afterFinalValidation = hooks.afterFinalValidation
	}
	return process2Outcome(evidence), evidence
}

// validProcess2Request contains checks over the frozen public request only.
// A false result proves a local pre-start invalid_request. Missing or invalid
// runner context remains UNKNOWN in validProcess2Launch.
func validProcess2Request(options Process2RunOptions) bool {
	args := options.Invocation.args
	profileSHA256, profileErr := hex.DecodeString(args.ProfileSHA256)
	requestSHA256, requestErr := hex.DecodeString(args.RequestSHA256)
	if len(options.Invocation.argv) < 2 || args.Mode != SignPSBT || args.validate() != nil ||
		options.AttemptInputs.Mode != SignPSBT || options.AttemptInputs.Group != args.Group || options.AttemptInputs.Account != args.Account ||
		profileErr != nil || requestErr != nil || !bytes.Equal(profileSHA256, options.AttemptInputs.ProfileSHA256[:]) ||
		!bytes.Equal(requestSHA256, options.AttemptInputs.OperationInputSHA256[:]) {
		return false
	}
	if options.Verification.Mode != RunnerSign || !validRunnerContext(options.Verification, args.Timeout) {
		return true
	}
	frame, err := DecodeProcess2CustodyFrame(options.Frame)
	if err != nil || frame.Metadata.PhysicalAccount != args.Group {
		return false
	}
	selection := options.Verification.Attempt.Selection()
	return selection.Group == args.Group && selection.Account == args.Account
}

func validProcess2Launch(command *exec.Cmd, options Process2RunOptions) bool {
	args := options.Invocation.args
	if command == nil || options.Admit == nil ||
		options.Verification.Mode != RunnerSign || !validRunnerContext(options.Verification, args.Timeout) ||
		command.Path == "" || !filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path ||
		command.Args == nil || len(command.Args) != len(options.Invocation.argv)+1 || command.Args[0] != command.Path ||
		!slices.Equal(command.Args[1:], options.Invocation.argv) || command.Process != nil || command.ProcessState != nil ||
		command.Cancel != nil || command.WaitDelay != 0 || command.SysProcAttr != nil || len(command.ExtraFiles) != 0 {
		return false
	}
	return true
}
