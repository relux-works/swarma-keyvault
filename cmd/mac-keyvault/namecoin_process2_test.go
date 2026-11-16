package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Runner spies prove routing and zero downstream effects on grammar refusals;
// they do not establish native admission or successful signing.
func TestNamecoinProcess2ClosedDispatch(t *testing.T) {
	base := namecoinPublicArgs(namecoinprocess.SignPSBT)
	explicit := append(append([]string(nil), base...), "--process-contract", "2")
	cases := []struct {
		name     string
		args     []string
		one, two int
	}{
		{"implicit-one", base, 1, 0},
		{"explicit-two", explicit, 0, 1},
		{"duplicate-selector", append(append([]string(nil), explicit...), "--process-contract", "2"), 0, 0},
		{"explicit-one-still-refused", append(append([]string(nil), base...), "--process-contract", "1"), 0, 0},
		{"noncanonical", append(append([]string(nil), base...), "--process-contract", "02"), 0, 0},
		{"unknown", append(append([]string(nil), explicit...), "--helper", "/other"), 0, 0},
		{"duplicate-field", append(append([]string(nil), explicit...), "--group", "fixture/recovery@1"), 0, 0},
		{"absent-value", append(append([]string(nil), base...), "--process-contract"), 0, 0},
		{"equals-syntax", append(append([]string(nil), base...), "--process-contract=2"), 0, 0},
		{"unsupported-mode", append(namecoinPublicArgs(namecoinprocess.Reconcile), "--process-contract", "2"), 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string(nil), tc.args...)
			path := filepath.Join(t.TempDir(), "absent-result")
			for i := range args {
				if args[i] == "--output" {
					args[i+1] = path
				}
			}
			var stdout, stderr bytes.Buffer
			one, two := 0, 0
			refusal := namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
			runNamecoinWithRunners(context.Background(), args, output{stdout: &stdout, stderr: &stderr},
				func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
					one++
					return namecoinSigningResult{}, refusal
				}, func(_ context.Context, invocation namecoinprocess.Process2Invocation) (namecoinSigningResult, error) {
					two++
					if invocation.Args().OutputPath != path {
						t.Fatal("selection changed")
					}
					return namecoinSigningResult{}, refusal
				})
			if one != tc.one || two != tc.two {
				t.Fatalf("calls one=%d two=%d", one, two)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("output created", err)
			}
		})
	}
}

func TestNamecoinProcess2UnknownNeverFallsBack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	one, two := 0, 0
	args := append(namecoinPublicArgs(namecoinprocess.SignPSBT), "--process-contract", "2")
	code := runNamecoinWithRunners(context.Background(), args, output{json: true, stdout: &stdout, stderr: &stderr},
		func(context.Context, namecoinprocess.Args, namecoinprocess.StatusObservationSource) (namecoinSigningResult, error) {
			one++
			return namecoinSigningResult{}, nil
		}, func(context.Context, namecoinprocess.Process2Invocation) (namecoinSigningResult, error) {
			two++
			return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
		})
	if code != exitFailure || one != 0 || two != 1 || bytes.Contains(stdout.Bytes(), []byte("result_path")) || !bytes.Contains(stdout.Bytes(), []byte("UNKNOWN")) {
		t.Fatalf("exit=%d calls=%d/%d stdout=%s", code, one, two, stdout.String())
	}
}
