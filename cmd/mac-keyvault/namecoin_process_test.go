//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const namecoinProcessTestHelperArg = "namecoin-process-test-helper"
const namecoinProcessEarlyHelperArg = "namecoin-process-early-helper"
const namecoinProcessValidHelperArg = "namecoin-process-valid-result-helper"

func namecoinProcessTestStatusFrame(event byte, binding, digest [32]byte) []byte {
	frame := make([]byte, 80)
	copy(frame[:4], "KVNS")
	frame[5] = 1
	frame[6] = event
	copy(frame[8:40], binding[:])
	copy(frame[40:72], digest[:])
	return frame
}

// This subprocess emits an ACK whose digest matches its fd-3 bytes, exits 0,
// and writes no native status frame. It is only an OS-pipe fixture; the parent
// still must refuse success because completion evidence is absent.
func TestNamecoinProcessTestHelper(t *testing.T) {
	if len(os.Args) < 4 {
		return
	}
	if os.Args[2] == namecoinProcessEarlyHelperArg {
		if err := os.WriteFile(os.Args[3], []byte("early-output"), 0600); err != nil {
			os.Exit(82)
		}
		if _, err := os.Stdout.Write([]byte("pre-release\n")); err != nil {
			os.Exit(81)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(83)
		}
		if err := os.WriteFile(os.Args[3]+".released", []byte("stdin-eof"), 0600); err != nil {
			os.Exit(84)
		}
		os.Exit(0)
	}
	if os.Args[2] == namecoinProcessValidHelperArg {
		if len(os.Args) != 7 {
			os.Exit(98)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(109)
		}
		result, err := os.ReadFile(os.Args[4])
		if err != nil {
			os.Exit(99)
		}
		resultFile := os.NewFile(3, "test result")
		statusFile := os.NewFile(4, "test status")
		if resultFile == nil || statusFile == nil {
			os.Exit(100)
		}
		if _, err := resultFile.Write(result); err != nil || resultFile.Sync() != nil {
			os.Exit(101)
		}
		if resultFile.Close() != nil {
			os.Exit(102)
		}
		bindingBytes, err := hex.DecodeString(os.Args[6])
		if err != nil || len(bindingBytes) != 32 {
			os.Exit(103)
		}
		if os.Args[5] == "complete" {
			var binding [32]byte
			copy(binding[:], bindingBytes)
			resultDigest := sha256.Sum256(result)
			for _, frame := range [][]byte{
				namecoinProcessTestStatusFrame(1, binding, [32]byte{}),
				namecoinProcessTestStatusFrame(2, binding, resultDigest),
			} {
				if _, err := statusFile.Write(frame); err != nil {
					os.Exit(104)
				}
			}
		} else if os.Args[5] != "missing" {
			os.Exit(105)
		}
		ack := namecoinwire.Acknowledgement(sha256.Sum256(result))
		if _, err := os.Stdout.Write(ack); err != nil {
			os.Exit(106)
		}
		if err := os.WriteFile(os.Args[3], []byte("valid-result-written"), 0600); err != nil {
			os.Exit(107)
		}
		if statusFile.Close() != nil {
			os.Exit(108)
		}
		os.Exit(0)
	}
	if os.Args[2] != namecoinProcessTestHelperArg {
		return
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(91)
	}
	result := []byte(`{"forged":true}`)
	resultFile := os.NewFile(3, "test result")
	statusFile := os.NewFile(4, "test status")
	if resultFile == nil || statusFile == nil {
		os.Exit(92)
	}
	if _, err := resultFile.Write(result); err != nil || resultFile.Sync() != nil {
		os.Exit(93)
	}
	if resultFile.Close() != nil {
		os.Exit(94)
	}
	ack := namecoinwire.Acknowledgement(sha256.Sum256(result))
	if _, err := os.Stdout.Write(ack); err != nil {
		os.Exit(95)
	}
	if err := os.WriteFile(os.Args[3], []byte("ack-written-exit-zero"), 0600); err != nil {
		os.Exit(96)
	}
	if statusFile.Close() != nil {
		os.Exit(97)
	}
	os.Exit(0)
}

func namecoinSigningFixture(t *testing.T) (namecoinprocess.Args, time.Time) {
	t.Helper()
	profile, err := os.ReadFile(filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", "native-selection", "two-stage-reservation.json"))
	if err != nil {
		t.Fatal(err)
	}
	selection, err := namecoinpsbt.DecodeNativeSelection(profile)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", "two-stage", "account-pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := os.ReadFile(filepath.Join("..", "..", "internal", "namecoinwire", "testdata", "two-stage", "A-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := namecoinPrivateFixtureDir(t)
	profilePath := filepath.Join(dir, "profile.json")
	pinPath := filepath.Join(dir, "account-pin.json")
	requestPath := filepath.Join(dir, "request.json")
	for path, raw := range map[string][]byte{profilePath: profile, pinPath: pin, requestPath: request} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	profileHash := sha256.Sum256(profile)
	requestHash := sha256.Sum256(request)
	args := namecoinprocess.Args{Mode: namecoinprocess.SignPSBT, Group: selection.Selection.Group, Account: selection.Selection.Account,
		ProfilePath: profilePath, ProfileSHA256: hex.EncodeToString(profileHash[:]), AccountPinPath: pinPath,
		RequestPath: requestPath, RequestSHA256: hex.EncodeToString(requestHash[:]), OutputPath: filepath.Join(dir, "result.json"), Timeout: 30 * time.Second}
	return args, time.Unix(int64(selection.Selection.Policy.CreatedAt)+1, 0)
}

func namecoinProcessPublicSignedResultFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	dir := filepath.Join("..", "..", "internal", "namecoinwire", "testdata", "two-stage")
	result, err := os.ReadFile(filepath.Join(dir, "A-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := os.ReadFile(filepath.Join(dir, "A-ack.stdout"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ack, namecoinwire.Acknowledgement(sha256.Sum256(result))) {
		t.Fatal("public result fixture ACK does not match its exact bytes")
	}
	return result, ack
}

func TestNamecoinProcessAdapterRequiresNativeCompletionForAckAndExit(t *testing.T) {
	args, now := namecoinSigningFixture(t)
	prepared, err := namecoinprocess.PrepareSigningFiles(args, now)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := prepared.StatusExpectation()
	if err != nil {
		t.Fatal(err)
	}
	helperArgs, err := namecoinprocess.HelperArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	testPin := []byte("test-only-code-pin")
	state, err := newNamecoinProcess1(context.Background(), args, "/test/paired-helper", testPin, helperArgs,
		namecoinprocess.FramedStatusSource{}, expectation, prepared)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(args.OutputPath), "helper.marker")
	identityChecks := 0
	state.command = func(path string, argv ...string) *exec.Cmd {
		if path != "/test/paired-helper" {
			t.Errorf("unexpected helper path %q", path)
		}
		if !reflect.DeepEqual(argv, helperArgs) {
			t.Errorf("helper argv=%q want=%q", argv, helperArgs)
		}
		return exec.Command(os.Args[0], "-test.run=^TestNamecoinProcessTestHelper$", namecoinProcessTestHelperArg, marker)
	}
	state.verifyChild = func(pid int, pin []byte) error {
		identityChecks++
		if pid <= 0 || !bytes.Equal(pin, testPin) {
			return errors.New("unexpected test child identity input")
		}
		return nil
	}
	runner, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: prepared.Attempt()}, args.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	state.runner = runner
	outcome, err := state.run()
	var failure namecoinwire.Failure
	if !errors.As(err, &failure) || failure.Code() != namecoinwire.OutcomeUnknown || failure.Status() != "UNKNOWN" || outcome.Success() {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if identityChecks != 1 {
		t.Fatalf("live child identity check count=%d", identityChecks)
	}
	markerBytes, err := os.ReadFile(marker)
	if err != nil || string(markerBytes) != "ack-written-exit-zero" {
		t.Fatalf("helper did not write matching ACK and exit marker: %q err=%v", markerBytes, err)
	}
	partial, err := os.ReadFile(args.OutputPath)
	if err != nil || string(partial) != `{"forged":true}` {
		t.Fatalf("partial result was not preserved: %q err=%v", partial, err)
	}
}

func TestNamecoinProcessAdapterRequiresNativeCompletionForValidResult(t *testing.T) {
	resultFixture, ackFixture := namecoinProcessPublicSignedResultFixture(t)
	for _, tc := range []struct {
		name           string
		statusMode     string
		completeStatus bool
	}{
		{name: "valid_result_without_native_completion", statusMode: "missing"},
		{name: "valid_result_with_native_completion", statusMode: "complete", completeStatus: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, now := namecoinSigningFixture(t)
			prepared, err := namecoinprocess.PrepareSigningFiles(args, now)
			if err != nil {
				t.Fatal(err)
			}
			expectation, err := prepared.StatusExpectation()
			if err != nil {
				t.Fatal(err)
			}
			helperArgs, err := namecoinprocess.HelperArgs(args)
			if err != nil {
				t.Fatal(err)
			}
			resultPath := args.OutputPath + ".public-fixture"
			if err := os.WriteFile(resultPath, resultFixture, 0600); err != nil {
				t.Fatal(err)
			}
			testPin := []byte("test-only-code-pin")
			state, err := newNamecoinProcess1(context.Background(), args, "/test/paired-helper", testPin, helperArgs,
				namecoinprocess.FramedStatusSource{}, expectation, prepared)
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(filepath.Dir(args.OutputPath), "valid-helper.marker")
			identityChecks := 0
			state.command = func(path string, argv ...string) *exec.Cmd {
				if path != "/test/paired-helper" {
					t.Errorf("unexpected helper path %q", path)
				}
				if !reflect.DeepEqual(argv, helperArgs) {
					t.Errorf("helper argv=%q want=%q", argv, helperArgs)
				}
				return exec.Command(os.Args[0], "-test.run=^TestNamecoinProcessTestHelper$",
					namecoinProcessValidHelperArg, marker, resultPath, tc.statusMode,
					hex.EncodeToString(expectation.AttemptBinding[:]))
			}
			state.verifyChild = func(pid int, pin []byte) error {
				identityChecks++
				if pid <= 0 || !bytes.Equal(pin, testPin) {
					return errors.New("unexpected test child identity input")
				}
				return nil
			}
			runner, err := namecoinprocess.NewRunner(
				namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: prepared.Attempt()}, args.Timeout)
			if err != nil {
				t.Fatal(err)
			}
			state.runner = runner
			outcome, err := state.run()
			if tc.completeStatus {
				if err != nil || !outcome.Success() {
					t.Fatalf("valid result with native completion refused: outcome=%+v err=%v", outcome, err)
				}
				if !bytes.Equal(outcome.Line(), ackFixture) || !bytes.Equal(outcome.Result(), resultFixture) {
					t.Fatal("successful outcome differs from exact public ACK/result fixtures")
				}
			} else {
				var failure namecoinwire.Failure
				if !errors.As(err, &failure) || failure.Code() != namecoinwire.OutcomeUnknown ||
					failure.Status() != "UNKNOWN" || outcome.Success() || len(outcome.Result()) != 0 {
					t.Fatalf("valid result without native completion was not closed UNKNOWN: outcome=%+v err=%v", outcome, err)
				}
			}
			if identityChecks != 1 {
				t.Fatalf("live child identity check count=%d", identityChecks)
			}
			markerBytes, err := os.ReadFile(marker)
			if err != nil || string(markerBytes) != "valid-result-written" {
				t.Fatalf("helper did not write fixture result marker: %q err=%v", markerBytes, err)
			}
			persisted, err := os.ReadFile(args.OutputPath)
			if err != nil || !bytes.Equal(persisted, resultFixture) {
				t.Fatal("public fixture output bytes were not preserved", err)
			}
		})
	}
}

func TestNamecoinProcessStatusEOFRetainsChildCorrelation(t *testing.T) {
	args, now := namecoinSigningFixture(t)
	prepared, err := namecoinprocess.PrepareSigningFiles(args, now)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := prepared.StatusExpectation()
	if err != nil {
		t.Fatal(err)
	}
	result, _ := namecoinProcessPublicSignedResultFixture(t)
	digest := sha256.Sum256(result)
	child := namecoinprocess.RunnerChild(41)
	state := &namecoinProcess1{
		ctx: context.Background(), status: namecoinprocess.FramedStatusSource{}, expect: expectation,
		child: child, events: make(chan namecoinObservation, 3), statusReaderDone: make(chan struct{}), inputReleased: true,
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	frames := append(namecoinProcessTestStatusFrame(1, expectation.AttemptBinding, [32]byte{}),
		namecoinProcessTestStatusFrame(2, expectation.AttemptBinding, digest)...)
	if n, err := writer.Write(frames); err != nil || n != len(frames) {
		_ = writer.Close()
		t.Fatalf("write framed status stream: wrote %d of %d bytes, err=%v", n, len(frames), err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	state.readStatus(reader)

	want := []namecoinprocess.RunnerEventKind{
		namecoinprocess.RunnerEffectStarted,
		namecoinprocess.RunnerNativeCompleted,
		namecoinprocess.RunnerStatusEOF,
	}
	for i, kind := range want {
		observation := <-state.events
		if observation.beforeInput || observation.event.Kind != kind || observation.event.Child != child {
			t.Fatalf("status event %d = {kind:%d child:%d beforeInput:%t}, want {kind:%d child:%d beforeInput:false}",
				i, observation.event.Kind, observation.event.Child, observation.beforeInput, kind, child)
		}
	}
	if len(state.events) != 0 || !state.statusEOFObserved.Load() {
		t.Fatalf("status stream not fully observed: queued=%d eof=%t", len(state.events), state.statusEOFObserved.Load())
	}
}

func TestNamecoinProcessAdapterDoesNotReleaseInputsAfterEarlyPipeData(t *testing.T) {
	args, now := namecoinSigningFixture(t)
	prepared, err := namecoinprocess.PrepareSigningFiles(args, now)
	if err != nil {
		t.Fatal(err)
	}
	expectation, err := prepared.StatusExpectation()
	if err != nil {
		t.Fatal(err)
	}
	helperArgs, err := namecoinprocess.HelperArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newNamecoinProcess1(context.Background(), args, "/test/paired-helper", []byte("test-only-code-pin"), helperArgs,
		namecoinprocess.FramedStatusSource{}, expectation, prepared)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filepath.Dir(args.OutputPath), "early.marker")
	state.command = func(path string, argv ...string) *exec.Cmd {
		if path != "/test/paired-helper" || !reflect.DeepEqual(argv, helperArgs) {
			t.Errorf("helper launch changed: path=%q argv=%q", path, argv)
		}
		return exec.Command(os.Args[0], "-test.run=^TestNamecoinProcessTestHelper$", namecoinProcessEarlyHelperArg, marker)
	}
	identityChecks := 0
	state.verifyChild = func(pid int, pin []byte) error {
		identityChecks++
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, markerErr := os.Stat(marker)
			state.gateMu.Lock()
			early := state.earlyObservation
			state.gateMu.Unlock()
			if pid > 0 && bytes.Equal(pin, []byte("test-only-code-pin")) && markerErr == nil && early {
				return nil
			}
			time.Sleep(time.Millisecond)
		}
		return errors.New("early pipe observation did not reach the admission gate")
	}
	runner, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: prepared.Attempt()}, args.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	state.runner = runner
	outcome, err := state.run()
	var failure namecoinwire.Failure
	if !errors.As(err, &failure) || failure.Code() != namecoinwire.OutcomeUnknown || outcome.Success() {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	if identityChecks != 1 {
		t.Fatalf("live child identity check count=%d", identityChecks)
	}
	markerBytes, err := os.ReadFile(marker)
	if err != nil || string(markerBytes) != "early-output" {
		t.Fatalf("early observation fixture did not run: %q err=%v", markerBytes, err)
	}
	if _, err := os.Stat(marker + ".released"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdin EOF released after an early observation: stat err=%v", err)
	}
}
