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
