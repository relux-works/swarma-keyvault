package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func namecoinPublicArgs(mode namecoinprocess.Mode) []string {
	base := []string{"--group", "fixture/recovery@1", "--account", "fixture/namecoin@1", "--profile", "/public/profile.json", "--profile-sha256", strings.Repeat("a", 64), "--account-pin", "/public/pin.json", "--timeout-seconds", "30"}
	switch mode {
	case namecoinprocess.SignPSBT:
		return append([]string{string(mode)}, append(append([]string(nil), base...), "--request", "/public/request.json", "--request-sha256", strings.Repeat("b", 64), "--output", "/public/result.json")...)
	case namecoinprocess.Reconcile:
		return append([]string{string(mode)}, append(append([]string(nil), base...), "--query", "/public/query.json", "--output", "/public/result.json")...)
	case namecoinprocess.InitializeJournal:
		return append([]string{string(mode)}, append(append([]string(nil), base...), "--adoption-plan-sha256", strings.Repeat("c", 64))...)
	default:
		return []string{string(mode)}
	}
}

func namecoinReconcileFixtureArgs(t *testing.T, resultPath string) []string {
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
	query, err := os.ReadFile(filepath.Join("..", "..", "internal", "namecoinwire", "testdata", "two-stage", "A-reconcile-query.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	pinPath := filepath.Join(dir, "account-pin.json")
	queryPath := filepath.Join(dir, "query.json")
	for path, raw := range map[string][]byte{profilePath: profile, pinPath: pin, queryPath: query} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	profileHash := sha256.Sum256(profile)
	return []string{"reconcile", "--group", selection.Selection.Group, "--account", selection.Selection.Account,
		"--profile", profilePath, "--profile-sha256", hex.EncodeToString(profileHash[:]), "--account-pin", pinPath,
		"--query", queryPath, "--output", resultPath, "--timeout-seconds", "30"}
}

func TestRunNamecoinReconcileIsUnknownWithoutCallingSigner(t *testing.T) {
	var stdout, stderr bytes.Buffer
	resultPath := filepath.Join(t.TempDir(), "must-not-be-created.json")
	args := namecoinReconcileFixtureArgs(t, resultPath)
	called := false
	sign := func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
		called = true
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
	}
	code := runNamecoinWith(context.Background(), args, output{command: "namecoin", json: true, stdout: &stdout, stderr: &stderr}, sign)
	var got response
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; stdout=%q", err, stdout.String())
	}
	result, ok := got.Result.(map[string]any)
	if code != exitFailure || called || got.OK || got.Command != "namecoin" || got.Error == nil || got.Error.Code != "outcome_unknown" || !strings.Contains(got.Error.Message, "unsupported") || !strings.Contains(got.Error.Hint, "do not retry") || !ok || result["status"] != "UNKNOWN" || result["mode"] != "reconcile" {
		t.Fatalf("code=%d called=%t response=%+v stderr=%q", code, called, got, stderr.String())
	}
	if _, err := os.Stat(resultPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconcile touched result path: stat err=%v", err)
	}
	if strings.Contains(stdout.String(), "result_sha256") || strings.Contains(stdout.String(), "SIGNED") {
		t.Fatalf("unsupported reconcile reported success: %s", stdout.String())
	}
}

func TestRunNamecoinReconcileRejectsMalformedQueryDuringPreflight(t *testing.T) {
	var stdout, stderr bytes.Buffer
	resultPath := filepath.Join(t.TempDir(), "must-not-be-created.json")
	args := namecoinReconcileFixtureArgs(t, resultPath)
	for i := range args {
		if args[i] == "--query" {
			if err := os.WriteFile(args[i+1], []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	called := false
	sign := func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
		called = true
		return namecoinSigningResult{}, nil
	}
	code := runNamecoinWith(context.Background(), args, output{command: "namecoin", json: true, stdout: &stdout, stderr: &stderr}, sign)
	var got response
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; stdout=%q", err, stdout.String())
	}
	if code != exitUsage || called || got.OK || got.Error == nil || got.Error.Code != "invalid_request" {
		t.Fatalf("code=%d called=%t response=%+v stderr=%q", code, called, got, stderr.String())
	}
	if _, err := os.Stat(resultPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid reconcile created result path: stat err=%v", err)
	}
}

func TestRunNamecoinDispatchesOnlySignPSBTToRunner(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := 0
	sign := func(_ context.Context, args namecoinprocess.Args, status namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
		called++
		if args.Mode != namecoinprocess.SignPSBT {
			t.Fatalf("mode dispatched to signing runner: %q", args.Mode)
		}
		if _, ok := status.(namecoinprocess.FramedStatusSource); !ok {
			t.Fatalf("unexpected status source %T", status)
		}
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
	}
	code := runNamecoinWith(context.Background(), namecoinPublicArgs(namecoinprocess.SignPSBT),
		output{command: "namecoin", json: true, stdout: &stdout, stderr: &stderr}, sign)
	var got response
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; stdout=%q", err, stdout.String())
	}
	if code != exitRefused || called != 1 || got.OK || got.Error == nil || got.Error.Code != "helper_not_admitted" {
		t.Fatalf("code=%d called=%d response=%+v stderr=%q", code, called, got, stderr.String())
	}
}

func TestRunNamecoinInitializationIsNotAdmittedInUnitOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	sign := func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
		called = true
		return namecoinSigningResult{}, nil
	}
	code := runNamecoinWith(context.Background(), namecoinPublicArgs(namecoinprocess.InitializeJournal),
		output{command: "namecoin", json: true, stdout: &stdout, stderr: &stderr}, sign)
	var got response
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; stdout=%q", err, stdout.String())
	}
	if code != exitRefused || called || got.OK || got.Error == nil || got.Error.Code != "helper_not_admitted" {
		t.Fatalf("code=%d called=%t response=%+v stderr=%q", code, called, got, stderr.String())
	}
}

func TestNamecoinUsageListsOnlyTheThreeClosedForms(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"namecoin"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, required := range []string{"namecoin sign-psbt", "namecoin reconcile", "namecoin initialize-journal"} {
		if !strings.Contains(stderr.String(), required) {
			t.Fatalf("missing %q in usage hint: %s", required, stderr.String())
		}
	}
	for _, forbidden := range []string{"name_update", "--process-contract", "<arbitrary"} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("public usage exposes %q: %s", forbidden, stderr.String())
		}
	}
}

func TestRunNamecoinRejectsCallerProcessVersionAndUnsupportedModes(t *testing.T) {
	cases := [][]string{
		{"namecoin", "sign-psbt", "--process-contract", "1"},
		{"namecoin", "name_update"},
		{"namecoin", "sign-psbt", "--unknown", "x"},
		{"namecoin", "reconcile", "--timeout-seconds", "01"},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitUsage || strings.Contains(stdout.String(), "helper_not_admitted") || !strings.Contains(stderr.String(), "error:") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
