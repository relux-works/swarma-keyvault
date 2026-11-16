package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const namecoinReceiptLostDiagnostic = "namecoin_signature_receipt_unavailable: signing may have completed; preserve the stored result and do not retry automatically\n"

// Claim: JSON and text success are reported only after their complete canonical
// receipt bytes reach stdout using privately staged public software fixtures.
func TestNamecoinSuccessReceiptRequiresCompleteDelivery(t *testing.T) {
	fixture := newNamecoinReceiptFixture(t)
	for _, jsonMode := range []bool{true, false} {
		t.Run(map[bool]string{true: "json", false: "text"}[jsonMode], func(t *testing.T) {
			storedPath := filepath.Join(t.TempDir(), "stored-result.json")
			var stdout, stderr bytes.Buffer
			calls := 0
			code := runNamecoinWith(context.Background(), namecoinReceiptArgs(storedPath),
				output{command: "namecoin", json: jsonMode, stdout: &stdout, stderr: &stderr},
				fixture.signer(t, &calls))
			if code != exitOK || calls != 1 || stderr.Len() != 0 {
				t.Fatalf("code=%d signer calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
			}
			wantHash := namecoinResultDigest(fixture.result)
			if jsonMode {
				var got response
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("decode complete JSON receipt: %v; stdout=%q", err, stdout.String())
				}
				result, ok := got.Result.(map[string]any)
				if !ok || !got.OK || got.Command != "namecoin" || result["status"] != "SIGNED" ||
					result["result_path"] != storedPath || result["result_sha256"] != wantHash ||
					result["request_id"] != fixture.requestID || result["sitting_id"] != fixture.sittingID ||
					result["unsigned_txid"] != fixture.unsignedTxID || stdout.Bytes()[len(stdout.Bytes())-1] != '\n' {
					t.Fatalf("complete JSON receipt differs: %+v", got)
				}
			} else {
				want := "status: SIGNED\nresult_path: " + storedPath + "\nresult_sha256: " + wantHash + "\n"
				if stdout.String() != want {
					t.Fatalf("text receipt=%q want=%q", stdout.String(), want)
				}
			}
			assertNamecoinStoredResult(t, storedPath, fixture.result)
		})
	}
}

// Claim: ENOSPC and incomplete writers return exit 1 with one bounded preserve/no-retry
// diagnostic, retain the stored result, and do not invoke the signing runner twice.
func TestNamecoinReceiptDeliveryFailuresDoNotRepeatSigning(t *testing.T) {
	fixture := newNamecoinReceiptFixture(t)
	faults := []string{"enospc", "short-nil", "partial-enospc"}
	for _, jsonMode := range []bool{true, false} {
		for _, fault := range faults {
			t.Run(map[bool]string{true: "json", false: "text"}[jsonMode]+"/"+fault, func(t *testing.T) {
				storedPath := filepath.Join(t.TempDir(), "stored-result.json")
				writer := &namecoinReceiptFaultWriter{fault: fault}
				var stderr bytes.Buffer
				calls := 0
				code := runNamecoinWith(context.Background(), namecoinReceiptArgs(storedPath),
					output{command: "namecoin", json: jsonMode, stdout: writer, stderr: &stderr},
					fixture.signer(t, &calls))
				if code != exitFailure || calls != 1 || writer.calls != 1 {
					t.Fatalf("code=%d signer calls=%d stdout writes=%d", code, calls, writer.calls)
				}
				if stderr.String() != namecoinReceiptLostDiagnostic || strings.Contains(stderr.String(), "not_applied") {
					t.Fatalf("receipt failure diagnostic=%q", stderr.String())
				}
				wantReceipt := namecoinExpectedSuccessReceipt(t, jsonMode, storedPath, fixture)
				if len(writer.written) > len(wantReceipt) || !bytes.Equal(writer.written, wantReceipt[:len(writer.written)]) {
					t.Fatal("failed stdout writer did not retain only a receipt prefix")
				}
				if len(writer.written) == 0 && fault != "enospc" {
					t.Fatal("partial writer control did not retain any bytes")
				}
				if len(writer.written) >= len(wantReceipt) {
					t.Fatal("stdout failure unexpectedly retained a complete receipt")
				}
				assertNamecoinStoredResult(t, storedPath, fixture.result)
			})
		}
	}
}

func namecoinExpectedSuccessReceipt(t *testing.T, jsonMode bool, path string, fixture namecoinReceiptFixture) []byte {
	t.Helper()
	hash := namecoinResultDigest(fixture.result)
	if !jsonMode {
		return []byte("status: SIGNED\nresult_path: " + path + "\nresult_sha256: " + hash + "\n")
	}
	reply := response{OK: true, Command: "namecoin", Result: map[string]string{
		"status": "SIGNED", "mode": "sign-psbt", "result_path": path, "result_sha256": hash,
		"request_id": fixture.requestID, "sitting_id": fixture.sittingID, "unsigned_txid": fixture.unsignedTxID,
	}}
	raw, err := json.MarshalIndent(reply, "", "  ")
	if err != nil {
		t.Fatal("encode expected JSON receipt:", err)
	}
	return append(raw, '\n')
}

type namecoinReceiptFaultWriter struct {
	fault   string
	calls   int
	written []byte
}

func (w *namecoinReceiptFaultWriter) Write(p []byte) (int, error) {
	w.calls++
	switch w.fault {
	case "enospc":
		return 0, syscall.ENOSPC
	case "short-nil":
		n := len(p) / 2
		w.written = append(w.written, p[:n]...)
		return n, nil
	case "partial-enospc":
		n := len(p) / 3
		w.written = append(w.written, p[:n]...)
		return n, syscall.ENOSPC
	default:
		return 0, errors.New("unknown test writer fault")
	}
}

type namecoinReceiptFixture struct {
	result       []byte
	outcome      namecoinprocess.Outcome
	requestID    string
	sittingID    string
	unsignedTxID string
}

func newNamecoinReceiptFixture(t *testing.T) namecoinReceiptFixture {
	t.Helper()
	profileSource := filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", "native-selection", "two-stage-reservation.json")
	pinSource := filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", "two-stage", "account-pin.json")
	requestSource := filepath.Join("..", "..", "internal", "namecoinwire", "testdata", "two-stage", "A-request.json")
	profile, err := os.ReadFile(profileSource)
	if err != nil {
		t.Fatal("read public profile fixture:", err)
	}
	selection, err := namecoinpsbt.DecodeNativeSelection(profile)
	if err != nil {
		t.Fatal("decode public profile fixture:", err)
	}
	pin, err := os.ReadFile(pinSource)
	if err != nil {
		t.Fatal("read public account pin fixture:", err)
	}
	request, err := os.ReadFile(requestSource)
	if err != nil {
		t.Fatal("read public request fixture:", err)
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal("lookup fixture owner home:", err)
	}
	fixtureDir, err := os.MkdirTemp(account.HomeDir, ".namecoin-receipt-fixture-")
	if err != nil {
		t.Fatal("create private fixture directory:", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureDir); err != nil {
			t.Error("remove private fixture directory:", err)
		}
	})
	// Checked-in public inputs remain readable; only disposable staged copies
	// receive the exact private modes required by the production file guard.
	stagePrivate := func(name string, raw []byte) string {
		path := filepath.Join(fixtureDir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("stage private fixture:", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("staged fixture mode=%v err=%v, want 0600", info, err)
		}
		return path
	}
	profilePath := stagePrivate("profile.json", profile)
	pinPath := stagePrivate("account-pin.json", pin)
	requestPath := stagePrivate("request.json", request)
	profileAbs, err := filepath.Abs(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	pinAbs, err := filepath.Abs(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	requestAbs, err := filepath.Abs(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	profileHash := sha256.Sum256(profile)
	requestHash := sha256.Sum256(request)
	args := namecoinprocess.Args{
		Mode: namecoinprocess.SignPSBT, Group: selection.Selection.Group, Account: selection.Selection.Account,
		ProfilePath: profileAbs, ProfileSHA256: hex.EncodeToString(profileHash[:]), AccountPinPath: pinAbs,
		RequestPath: requestAbs, RequestSHA256: hex.EncodeToString(requestHash[:]),
		OutputPath: filepath.Join(t.TempDir(), "synthetic-stored-result.json"), Timeout: 30 * time.Second,
	}
	prepared, err := namecoinprocess.PrepareSigningFiles(args, time.Unix(int64(selection.Selection.Policy.CreatedAt)+1, 0))
	if err != nil {
		t.Fatal("prepare public signing fixture:", err)
	}
	result, ack := namecoinProcessPublicSignedResultFixture(t)
	outcome := namecoinReceiptFixtureOutcome(t, prepared.Attempt(), result, ack)
	snapshot, err := namecoinwire.Decode(prepared.InputBytes())
	if err != nil {
		t.Fatal("decode prepared public request:", err)
	}
	req := snapshot.Request()
	return namecoinReceiptFixture{result: result, outcome: outcome, requestID: req.RequestID,
		sittingID: req.SittingID, unsignedTxID: prepared.Attempt().Candidate().View().UnsignedTxID}
}

func namecoinReceiptArgs(resultPath string) []string {
	args := namecoinPublicArgs(namecoinprocess.SignPSBT)
	for i := range args {
		if args[i] == "--output" {
			args[i+1] = resultPath
			return args
		}
	}
	panic("sign-psbt fixture lacks output flag")
}

func (f namecoinReceiptFixture) signer(t *testing.T, calls *int) namecoinSignRunner {
	t.Helper()
	return func(_ context.Context, args namecoinprocess.Args, _ namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
		*calls = *calls + 1
		if *calls != 1 {
			return namecoinSigningResult{}, errors.New("synthetic signer invoked more than once")
		}
		file, err := os.OpenFile(args.OutputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return namecoinSigningResult{}, err
		}
		n, writeErr := file.Write(f.result)
		closeErr := file.Close()
		if writeErr != nil || n != len(f.result) || closeErr != nil {
			return namecoinSigningResult{}, errors.New("synthetic stored result write was incomplete")
		}
		return namecoinSigningResult{outcome: f.outcome, requestID: f.requestID, sittingID: f.sittingID, unsignedTxID: f.unsignedTxID}, nil
	}
}

func namecoinReceiptFixtureOutcome(t *testing.T, attempt namecoinpsbt.PublicAttempt, result, ack []byte) namecoinprocess.Outcome {
	t.Helper()
	runner, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: attempt}, time.Minute)
	if err != nil {
		t.Fatal("create public reducer fixture:", err)
	}
	events := []namecoinprocess.RunnerEvent{
		{Kind: namecoinprocess.RunnerBegin},
		{Kind: namecoinprocess.RunnerStarted, Child: 7},
		{Kind: namecoinprocess.RunnerAdmitted, Child: 7},
		{Kind: namecoinprocess.RunnerEffectStarted, Child: 7},
		{Kind: namecoinprocess.RunnerStdout, Child: 7, Data: ack},
		{Kind: namecoinprocess.RunnerNativeCompleted, Child: 7, Digest: sha256.Sum256(result)},
		{Kind: namecoinprocess.RunnerStatusEOF, Child: 7},
		{Kind: namecoinprocess.RunnerEOF, Child: 7},
		{Kind: namecoinprocess.RunnerStderrEOF, Child: 7},
		{Kind: namecoinprocess.RunnerExited, Child: 7, Normal: true, Exit: 0},
		{Kind: namecoinprocess.RunnerReaped, Child: 7},
		{Kind: namecoinprocess.RunnerReadback, Data: result},
		{Kind: namecoinprocess.RunnerClosed, OK: true},
	}
	var outcome namecoinprocess.Outcome
	for i, event := range events {
		_, outcome = runner.Step(event)
		if outcome.Done() && i != len(events)-1 {
			t.Fatalf("public reducer fixture completed early at event %d: %+v", i, outcome)
		}
	}
	if !outcome.Success() || !bytes.Equal(outcome.Result(), result) || !bytes.Equal(outcome.Line(), ack) {
		t.Fatalf("public software reducer fixture did not produce its exact result: %+v", outcome)
	}
	return outcome
}

func assertNamecoinStoredResult(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("stored synthetic result changed: bytes=%d want=%d err=%v", len(got), len(want), err)
	}
}
