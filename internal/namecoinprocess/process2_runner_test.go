//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func buildProcess2FixtureHelper(t *testing.T) string {
	t.Helper()
	fixtureResult, err := os.ReadFile("../namecoinwire/testdata/all-four-before-release/A-result.json")
	if err != nil {
		t.Fatal(err)
	}
	embeddedResult, err := os.ReadFile("testdata/process2helper/result.json")
	if err != nil || !bytes.Equal(fixtureResult, embeddedResult) {
		t.Fatal("subprocess fixture result differs from the existing public verification fixture", err)
	}
	binaryPath := filepath.Join(t.TempDir(), "process2-helper")
	build := exec.Command("go", "build", "-o", binaryPath, "./testdata/process2helper")
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build public process2 helper fixture: %v: %s", err, output)
	}
	return binaryPath
}

func process2RunnerFixture(t *testing.T, helper, outputPath string, timeoutSeconds string) (*exec.Cmd, Process2RunOptions, []byte, []byte) {
	t.Helper()
	verification, result, ack := publicContext(t, "all-four-before-release", "A")
	argv := process2ArgsFixture()
	argv = replaceArg(argv, "--output", outputPath)
	argv = replaceArg(argv, "--timeout-seconds", timeoutSeconds)
	invocation, err := ParseProcess2Args(argv)
	if err != nil {
		t.Fatal(err)
	}
	var profileHash, requestHash [32]byte
	for i := range profileHash {
		profileHash[i] = 0xaa
		requestHash[i] = 0xbb
	}
	selected := verification.Attempt.Selection()
	attemptInputs := Process2AttemptInputs{Mode: SignPSBT, Group: selected.Group, Account: selected.Account,
		ProfileSHA256: profileHash, OperationInputSHA256: requestHash}
	frame := process2FrameFixture(1)
	frame.Metadata.PhysicalAccount = selected.Group
	frameBytes, err := EncodeProcess2CustodyFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	command := &exec.Cmd{Path: helper, Args: append([]string{helper}, invocation.Argv()...)}
	options := Process2RunOptions{Invocation: invocation, AttemptInputs: attemptInputs, Verification: verification,
		Frame: frameBytes, Deadline: time.Now().Add(time.Duration(invocation.args.Timeout) - 20*time.Millisecond),
		Admit: func(ctx context.Context, process *os.Process, binding [32]byte) error {
			// This checks only that the fixture received a live handle-shaped value;
			// it is deliberately not a production helper identity admission.
			if ctx.Err() != nil || process == nil || process.Pid <= 0 || binding != attemptInputs.binding() {
				return errors.New("fixture admission refused")
			}
			return nil
		}}
	return command, options, result, ack
}

type process2SetupFailure struct {
	stage string
	err   error
}

func runProcess2WithSetupFailureEvidence(ctx context.Context, command *exec.Cmd, options Process2RunOptions) (Outcome, process2Evidence, process2SetupFailure) {
	if options.testHooks == nil {
		options.testHooks = &process2RunTestHooks{}
	}
	previous := options.testHooks.onSetupError
	var failure process2SetupFailure
	options.testHooks.onSetupError = func(stage string, err error) {
		if failure.err == nil {
			failure = process2SetupFailure{stage: stage, err: err}
		}
		if previous != nil {
			previous(stage, err)
		}
	}
	outcome, evidence := runProcess2(ctx, command, options)
	return outcome, evidence, failure
}

func assertNoProcess2SetupFailure(t *testing.T, failure process2SetupFailure) {
	t.Helper()
	if failure.err != nil {
		t.Fatalf("unexpected Process2 setup failure at %s: %s", failure.stage, process2SetupErrorText(failure.err))
	}
}

func requireProcess2SetupFailure(t *testing.T, failure process2SetupFailure, wantStage string) error {
	t.Helper()
	if failure.stage != wantStage || failure.err == nil {
		t.Fatalf("Process2 setup failure = stage %q error %q; want stage %q and an error", failure.stage, process2SetupErrorText(failure.err), wantStage)
	}
	return failure.err
}

// process2SetupErrorText exposes the OS cause to test logs without a PathError path.
func process2SetupErrorText(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return process2SetupErrorText(pathErr.Err)
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return process2SetupErrorText(execErr.Err)
	}
	if cause := errors.Unwrap(err); cause != nil {
		return process2SetupErrorText(cause)
	}
	return err.Error()
}

// isProcess2TestHookField names only the private fields whose values must stay test-installed.
func isProcess2TestHookField(name string) bool {
	switch name {
	case "testHooks", "onSetupError", "createPipe":
		return true
	default:
		return false
	}
}

func TestProcess2TestHooksAreAssignedOnlyInTestFiles(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal("read Process2 source directory")
	}
	fset := token.NewFileSet()
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse non-test Go source %q", name)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					selector, ok := lhs.(*ast.SelectorExpr)
					if ok && isProcess2TestHookField(selector.Sel.Name) {
						violations = append(violations, fmt.Sprintf("%s:%d", name, fset.Position(selector.Pos()).Line))
					}
				}
			case *ast.KeyValueExpr:
				if field, ok := node.Key.(*ast.Ident); ok && isProcess2TestHookField(field.Name) {
					violations = append(violations, fmt.Sprintf("%s:%d", name, fset.Position(field.Pos()).Line))
				}
			case *ast.CompositeLit:
				typ, ok := node.Type.(*ast.Ident)
				if !ok || (typ.Name != "Process2RunOptions" && typ.Name != "process2RunTestHooks") {
					break
				}
				for _, element := range node.Elts {
					if _, keyed := element.(*ast.KeyValueExpr); !keyed {
						violations = append(violations, fmt.Sprintf("%s:%d", name, fset.Position(node.Pos()).Line))
						break
					}
				}
			}
			return true
		})
	}
	if len(violations) != 0 {
		t.Fatalf("non-test source assigns Process2 test hook or pipe factory: %s", strings.Join(violations, ", "))
	}
}

func TestProcess2DiagnosticTextRedactsPathErrors(t *testing.T) {
	pathErr := &os.PathError{Op: "fork/exec", Path: "/private/test/missing-helper", Err: syscall.ENOENT}
	for _, err := range []error{pathErr, &exec.Error{Name: "/private/test/missing-helper", Err: pathErr}} {
		got := process2SetupErrorText(err)
		if got != syscall.ENOENT.Error() || strings.Contains(got, "/private/test") {
			t.Fatal("diagnostic text did not retain only the path-free OS cause")
		}
	}
}

func assertInvalidProcess2Request(t *testing.T, outcome Outcome) {
	t.Helper()
	failure, err := namecoinwire.DecodeFailure(outcome.Line())
	want := namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	if err != nil || !outcome.Done() || outcome.Success() || failure.Code() != namecoinwire.InvalidRequest ||
		failure.Status() != "REFUSED" || failure.Exit() != 2 || !bytes.Equal(outcome.Line(), want.Bytes()) ||
		len(outcome.Result()) != 0 || len(outcome.FinalTransaction()) != 0 {
		t.Fatalf("pre-start invalid request did not retain the existing REFUSED/exit-2/no-effect outcome: failure=%v err=%v", failure, err)
	}
}

// Claim: the Linux/Darwin adapter transports one frame through fd5, verifies
// retained fd3 bytes, status-r3, ACK, streams and same-child reap before release.
// Limit: the helper and admission are public software fixtures, not native or
// production identity evidence.
func TestProcess2RunnerIntegrationAndForbiddenOutcomes(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	t.Run("complete-pair-control", func(t *testing.T) {
		// A matched public fixture transcript clears every transport and result gate.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, wantResult, wantAck := process2RunnerFixture(t, helper, outputPath, "10")
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		if !outcome.Success() || !bytes.Equal(outcome.Result(), wantResult) || !bytes.Equal(outcome.Line(), wantAck) ||
			!evidence.admitted || evidence.frameBytes != evidence.frameLength || !evidence.writerJoined ||
			!evidence.statusEOF || !evidence.stdoutEOF || !evidence.stderrEOF || evidence.stderrHadBytes ||
			!evidence.resultReadbackOK || !evidence.waitDone || evidence.waitExit != 0 || !evidence.outputCloseOK || len(evidence.closeObservations) != 11 {
			t.Fatal("complete public-fixture subprocess did not satisfy the success barrier")
		}
		for _, close := range evidence.closeObservations {
			if !close.attempted || !close.ok {
				t.Fatalf("owned close lacked one successful observation: %+v", close)
			}
		}
		info, err := os.Stat(outputPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("fd3 output did not remain an exclusive mode-0600 public result", err)
		}
		if raw, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(raw, wantResult) {
			t.Fatal("retained result file differs from the public fixture", err)
		}
	})

	t.Run("partial-status", func(t *testing.T) {
		// A one-frame success-shaped status remains UNKNOWN and retains empty output.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "11")
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		assertUnknown(t, outcome)
		if !evidence.admitted || !evidence.waitDone || evidence.waitErr || !evidence.statusEOF || len(evidence.status) != Process2StatusFrameBytes {
			t.Fatal("partial status control did not reach the intended one-frame exit")
		}
		if info, err := os.Stat(outputPath); err != nil || info.Size() != 0 {
			t.Fatal("partial status unexpectedly released or replaced the empty public output", err)
		}
	})

	t.Run("stderr-and-preserved-result", func(t *testing.T) {
		// Unexpected stderr blocks release without deleting a fully written public file.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, wantResult, _ := process2RunnerFixture(t, helper, outputPath, "12")
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		assertUnknown(t, outcome)
		if !evidence.stderrHadBytes || !evidence.waitDone || !evidence.statusEOF || !evidence.stdoutEOF {
			t.Fatal("stderr violation did not reach the intended closed transcript")
		}
		if raw, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(raw, wantResult) {
			t.Fatal("partial public output was deleted or changed after UNKNOWN", err)
		}
	})

	t.Run("admission-refusal-does-not-release-frame", func(t *testing.T) {
		// Failed fixture admission closes inputs and reaps the same child with no write.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		options.Admit = func(context.Context, *os.Process, [32]byte) error { return errors.New("fixture admission refusal") }
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		assertUnknown(t, outcome)
		if evidence.admitted || evidence.frameBytes != 0 || evidence.writerJoined || !evidence.stdinCloseOK || !evidence.writerCloseOK || !evidence.waitDone {
			t.Fatal("failed admission released custody bytes or left its child unresolved")
		}
		if info, err := os.Stat(outputPath); err != nil || info.Size() != 0 {
			t.Fatal("failed admission did not preserve its empty output", err)
		}
	})

	t.Run("deadline-during-admission", func(t *testing.T) {
		// The original deadline reaches admission, which must return before fd5 opens.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "1")
		options.Deadline = time.Now().Add(80 * time.Millisecond)
		options.Admit = func(ctx context.Context, _ *os.Process, _ [32]byte) error {
			<-ctx.Done()
			return ctx.Err()
		}
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		assertUnknown(t, outcome)
		if evidence.admitted || evidence.frameBytes != 0 || evidence.writerJoined || !evidence.waitDone {
			t.Fatal("deadline during admission released custody or failed to resolve the retained child")
		}
	})

	t.Run("parent-cancel-during-admission", func(t *testing.T) {
		// Parent cancellation during live-child admission remains UNKNOWN and resolves the same child.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "13")
		ctx, cancel := context.WithCancel(context.Background())
		options.Admit = func(admissionContext context.Context, _ *os.Process, _ [32]byte) error {
			cancel()
			<-admissionContext.Done()
			return admissionContext.Err()
		}
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(ctx, command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		assertUnknown(t, outcome)
		if evidence.admitted || evidence.frameBytes != 0 || evidence.writerJoined || !evidence.waitDone || evidence.waitErr ||
			!evidence.stdinCloseOK || !evidence.writerCloseOK || !allProcess2ClosesOK(evidence.closeObservations) {
			t.Fatal("parent cancellation during admission released the frame or failed to close/reap the same child")
		}
		if info, err := os.Stat(outputPath); err != nil || info.Size() != 0 {
			t.Fatal("parent cancellation during admission changed the retained empty output", err)
		}
	})

	t.Run("unbound-argv-is-rejected-before-start", func(t *testing.T) {
		// A request digest differing from frozen parent inputs yields invalid_request before resource creation.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		options.AttemptInputs.OperationInputSHA256[0] ^= 1
		outcome, evidence := runProcess2(context.Background(), command, options)
		assertInvalidProcess2Request(t, outcome)
		if command.Process != nil || evidence.frameBytes != 0 {
			t.Fatal("argv whose operation-input hash differs from the frozen attempt was launched")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatal("invalid binding created a result file before launch")
		}
	})

	t.Run("malformed-custody-frame-refuses-before-start", func(t *testing.T) {
		// A locally malformed request frame is the existing invalid_request before resource creation.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		options.Frame = []byte("malformed-frame")
		outcome, evidence := runProcess2(context.Background(), command, options)
		assertInvalidProcess2Request(t, outcome)
		if command.Process != nil || evidence.frameBytes != 0 {
			t.Fatal("malformed frame started a child or wrote custody bytes")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatal("malformed request created an output file before refusal")
		}
	})

	t.Run("frozen-selected-account-mismatch-refuses-before-start", func(t *testing.T) {
		// A frozen selected account inconsistent with parsed argv is a proven local invalid_request.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		options.AttemptInputs.Account = "fixture/other-namecoin@1"
		outcome, evidence := runProcess2(context.Background(), command, options)
		assertInvalidProcess2Request(t, outcome)
		if command.Process != nil || evidence.frameBytes != 0 {
			t.Fatal("wrong frozen account selection started a child or wrote custody bytes")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatal("wrong frozen account selection created an output file before refusal")
		}
	})

	t.Run("missing-production-admission-refuses-before-start", func(t *testing.T) {
		// An absent real pin/admission implementation has no production fallback.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		options.Admit = nil
		outcome := RunProcess2(context.Background(), command, options)
		assertUnknown(t, outcome)
		if command.Process != nil {
			t.Fatal("runner started without an admitted helper identity check")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatal("missing admission created a result file", err)
		}
	})

	t.Run("frame-selection-mismatch-refuses-before-start", func(t *testing.T) {
		// A frame naming a different physical account yields invalid_request before resource creation.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		frame, err := DecodeProcess2CustodyFrame(options.Frame)
		if err != nil {
			t.Fatal(err)
		}
		frame.Metadata.PhysicalAccount = "other/recovery@1"
		options.Frame, err = EncodeProcess2CustodyFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		outcome, evidence := runProcess2(context.Background(), command, options)
		assertInvalidProcess2Request(t, outcome)
		if command.Process != nil {
			t.Fatal("frame selection mismatch started a helper")
		}
		if evidence.frameBytes != 0 {
			t.Fatal("frame selection mismatch wrote custody bytes")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatal("frame selection mismatch created a result file", err)
		}
	})

	t.Run("generic-spawn-failure-stays-unknown", func(t *testing.T) {
		// A generic Start error lacks positive no-effect evidence and remains UNKNOWN.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		command.Path = filepath.Join(t.TempDir(), "missing-helper")
		command.Args[0] = command.Path
		outcome, _, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertUnknown(t, outcome)
		startErr := requireProcess2SetupFailure(t, setupFailure, "command.Start")
		var pathErr *os.PathError
		if !errors.Is(startErr, os.ErrNotExist) || !errors.As(startErr, &pathErr) || pathErr.Path != command.Path {
			t.Fatal("command.Start did not retain the missing-helper not-exist cause")
		}
		t.Logf("Process2 setup stage=%s OS error=%s", setupFailure.stage, process2SetupErrorText(startErr))
		if command.Process != nil {
			t.Fatal("failed generic spawn unexpectedly started a child")
		}
	})

	t.Run("late-parent-cancel-after-complete-barrier-keeps-success", func(t *testing.T) {
		// Cancellation after all real child/read/close evidence does not erase a complete success.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		command, options, wantResult, wantAck := process2RunnerFixture(t, helper, outputPath, "10")
		ctx, cancel := context.WithCancel(context.Background())
		options.testHooks = &process2RunTestHooks{afterEvidence: cancel}
		outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(ctx, command, options)
		assertNoProcess2SetupFailure(t, setupFailure)
		if ctx.Err() == nil || !outcome.Success() || !bytes.Equal(outcome.Result(), wantResult) || !bytes.Equal(outcome.Line(), wantAck) ||
			!evidence.writerJoined || !evidence.waitDone || !evidence.readerCloseOK || !evidence.outputCloseOK {
			t.Fatal("authentic cancellation after the completed lifecycle barrier changed its valid success")
		}
	})

	t.Run("existing-output-preserved", func(t *testing.T) {
		// Exclusive fd3 creation refuses an existing path and preserves its bytes.
		outputPath := filepath.Join(t.TempDir(), "result.json")
		sentinel := []byte("existing output must remain untouched")
		if err := os.WriteFile(outputPath, sentinel, 0o600); err != nil {
			t.Fatal("could not create existing-output fixture")
		}
		command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		outcome, _, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
		assertUnknown(t, outcome)
		outputErr := requireProcess2SetupFailure(t, setupFailure, "output-create")
		var errno syscall.Errno
		if !errors.Is(outputErr, namecoinfiles.ErrUnsafe) || outputErr.Error() != "namecoin_file_unavailable" ||
			!errors.As(outputErr, &errno) || errno != syscall.EEXIST {
			t.Fatal("existing-output refusal did not preserve its sentinel and EEXIST cause")
		}
		t.Logf("Process2 setup stage=%s OS error=%s", setupFailure.stage, process2SetupErrorText(outputErr))
		if command.Process != nil {
			t.Fatal("existing path was replaced after helper start")
		}
		if raw, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(raw, sentinel) {
			t.Fatal("existing output was truncated or replaced")
		}

		publicCommand, publicOptions, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
		publicOutcome := RunProcess2(context.Background(), publicCommand, publicOptions)
		assertUnknown(t, publicOutcome)
		if !bytes.Equal(publicOutcome.Line(), unknownProcess2Outcome().Line()) ||
			bytes.Contains(publicOutcome.Line(), []byte(outputPath)) || bytes.Contains(publicOutcome.Line(), []byte("EEXIST")) {
			t.Fatal("public Process2 outcome exposed the internal output-creation cause")
		}
	})

	// complete-pair-control above is the paired positive for these forced setup failures.
	for _, pipeName := range []string{"stdin", "fd4-status", "fd5-custody", "stdout", "stderr"} {
		t.Run("pipe-creation-error-"+pipeName, func(t *testing.T) {
			// Each named pipe refusal reports its exact error before child start.
			outputPath := filepath.Join(t.TempDir(), "result.json")
			command, options, _, _ := process2RunnerFixture(t, helper, outputPath, "10")
			wantErr := errors.New("fixture pipe error for " + pipeName)
			options.testHooks = &process2RunTestHooks{createPipe: func(name string) (process2Pipe, error) {
				if name == pipeName {
					return process2Pipe{}, wantErr
				}
				return newProcess2Pipe(name)
			}}
			outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
			assertUnknown(t, outcome)
			err := requireProcess2SetupFailure(t, setupFailure, "pipe:"+pipeName)
			if err.Error() != wantErr.Error() {
				t.Fatalf("pipe setup error = %q; want %q", err, wantErr)
			}
			t.Logf("Process2 setup stage=%s OS error=%s", setupFailure.stage, process2SetupErrorText(err))
			if command.Process != nil || evidence.frameBytes != 0 {
				t.Fatal("pipe setup failure started a child or wrote custody bytes")
			}
			if info, err := os.Stat(outputPath); err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
				t.Fatalf("pipe setup failure did not retain an empty mode-0600 output: info=%v err=%v", info, err)
			}
		})
	}

}

// Claim: the final public result-validation barrier rechecks the original
// monotonic deadline before SUCCESS, while an in-budget result still releases.
// Limit: the child, helper admission, clock seam, and output are software fixtures.
func TestProcess2DeadlineRecheckedAfterPublicResultValidation(t *testing.T) {
	helper := buildProcess2FixtureHelper(t)
	for _, late := range []bool{false, true} {
		name := "unexpired-after-final-validation"
		if late {
			name = "deadline-expires-after-final-validation"
		}
		t.Run(name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "result.json")
			command, options, wantResult, wantAck := process2RunnerFixture(t, helper, outputPath, "3600")
			options.Deadline = time.Now().Add(time.Hour)
			originalFrame := bytes.Clone(options.Frame)
			deadline := options.Deadline
			finalNow := deadline.Add(-time.Nanosecond)
			validated := 0
			options.testHooks = &process2RunTestHooks{
				afterFinalValidation: func() {
					validated++
					if late {
						finalNow = deadline.Add(time.Nanosecond)
					}
				},
				finalDeadlineNow: func() time.Time { return finalNow },
			}
			outcome, evidence, setupFailure := runProcess2WithSetupFailureEvidence(context.Background(), command, options)
			assertNoProcess2SetupFailure(t, setupFailure)
			if validated != 1 || !evidence.admitted || evidence.frameBytes != evidence.frameLength || !evidence.resultReadbackOK ||
				!evidence.writerCloseOK || !evidence.writerJoined || !evidence.stdinCloseOK || !evidence.childEndsCloseOK ||
				!evidence.statusEOF || evidence.statusOverflow || !evidence.stdoutEOF || evidence.stdoutOverflow ||
				!bytes.Equal(evidence.stdout, wantAck) || !evidence.stderrEOF || evidence.stderrHadBytes ||
				!evidence.waitDone || evidence.waitErr || evidence.waitExit != 0 || !evidence.readerCloseOK || !evidence.outputCloseOK ||
				!bytes.Equal(evidence.result, wantResult) || !allProcess2ClosesOK(evidence.closeObservations) || !bytes.Equal(options.Frame, originalFrame) {
				t.Fatal("final deadline witness did not follow validated output and complete unchanged custody cleanup")
			}
			if late {
				assertUnknown(t, outcome)
			} else if !outcome.Success() || !bytes.Equal(outcome.Result(), wantResult) || !bytes.Equal(outcome.Line(), wantAck) {
				t.Fatal("unexpired final-validation control did not preserve the valid success")
			}
			if raw, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(raw, wantResult) {
				t.Fatal("final deadline decision deleted or changed the retained public result", err)
			}
		})
	}
}

func allProcess2ClosesOK(observations []process2CloseObservation) bool {
	if len(observations) != 11 {
		return false
	}
	for _, observation := range observations {
		if !observation.attempted || !observation.ok {
			return false
		}
	}
	return true
}
