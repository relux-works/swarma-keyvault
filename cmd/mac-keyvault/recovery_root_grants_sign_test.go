package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func rootGrantsSignInputFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	grant := filepath.Join(dir, "grant.json")
	contract := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(grant, []byte(`{"version":3}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contract, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	return grant, contract
}

func rootGrantsSignCLIArgs(grant, contract string) []string {
	return []string{"--json", "recovery", rootGrantsSignV3Op,
		"--grants-identity", "example-root", "--grants-version", "7", "--owner-principal", "owner:id/example-owner",
		"--grant-file", grant, "--contract-file", contract}
}

// Claim: the public CLI admits one exact set of explicit file/address flags
// before calling the signing seam; malformed, repeated and extra inputs have
// no operation call.
func TestRootGrantsSignV3CLIClosedArguments(t *testing.T) {
	grant, contract := rootGrantsSignInputFiles(t)
	old := reviewSignRootGrants
	calls := 0
	reviewSignRootGrants = func(context.Context, keyvault.RootGrantsGrantV3SignRequest) (keyvault.RootGrantsGrantV3SignatureReceipt, error) {
		calls++
		return keyvault.RootGrantsGrantV3SignatureReceipt{}, errors.New("unexpected")
	}
	t.Cleanup(func() { reviewSignRootGrants = old })
	base := rootGrantsSignCLIArgs(grant, contract)
	cases := [][]string{
		base[:len(base)-2],
		append(append([]string(nil), base...), "--unknown", "x"),
		append(append([]string(nil), base...), "--grants-version", "8"),
		append(append([]string(nil), base...), "extra"),
		append(append([]string(nil), base...), "--format", "raw"),
	}
	for i, args := range cases {
		code, stdout, stderr := rgInvoke(args...)
		if code != exitUsage || stderr != "" || !strings.Contains(stdout, `"code": "usage"`) {
			t.Fatalf("case %d did not refuse as usage: code=%d stdout=%q stderr=%q", i, code, stdout, stderr)
		}
	}
	if calls != 0 {
		t.Fatal("malformed command reached signing operation")
	}
}

// Claim: the JSON success envelope binds the requested address and owner, and
// includes the complete public signature receipt without echoing source paths.
func TestRootGrantsSignV3CLISuccessReceipt(t *testing.T) {
	grant, contract := rootGrantsSignInputFiles(t)
	old := reviewSignRootGrants
	var got keyvault.RootGrantsGrantV3SignRequest
	reviewSignRootGrants = func(_ context.Context, q keyvault.RootGrantsGrantV3SignRequest) (keyvault.RootGrantsGrantV3SignatureReceipt, error) {
		got = keyvault.RootGrantsGrantV3SignRequest{Address: q.Address, OwnerPrincipal: q.OwnerPrincipal,
			Grant: bytes.Clone(q.Grant), Contract: bytes.Clone(q.Contract)}
		return keyvault.RootGrantsGrantV3SignatureReceipt{Schema: "keyvault-root-grants-signature-receipt/1", Operation: rootGrantsSignV3Op,
			Profile: "namecoin-landlord-root/1", ObservationPolicy: "offline-document-review/1", OwnerPrincipal: q.OwnerPrincipal,
			RecordService: q.Address.Service, RecordVersion: q.Address.Version, PublicKey: strings.Repeat("a", 64),
			Signature: strings.Repeat("b", 128), Outcome: "signed"}, nil
	}
	t.Cleanup(func() { reviewSignRootGrants = old })
	code, stdout, stderr := rgInvoke(rootGrantsSignCLIArgs(grant, contract)...)
	var reply struct {
		OK      bool                                       `json:"ok"`
		Command string                                     `json:"command"`
		Result  keyvault.RootGrantsGrantV3SignatureReceipt `json:"result"`
	}
	if code != exitOK || stderr != "" || json.Unmarshal([]byte(stdout), &reply) != nil || !reply.OK || reply.Command != "recovery" ||
		reply.Result.Schema != "keyvault-root-grants-signature-receipt/1" || reply.Result.Operation != rootGrantsSignV3Op ||
		reply.Result.RecordService != "example-root" || reply.Result.RecordVersion != 7 || reply.Result.Signature != strings.Repeat("b", 128) {
		t.Fatalf("invalid signing receipt: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got.Address != (keyvault.RootGrantsAddress{Service: "example-root", Version: 7}) || got.OwnerPrincipal != "owner:id/example-owner" ||
		string(got.Grant) != `{"version":3}` || string(got.Contract) != `{"version":1}` {
		t.Fatal("CLI changed explicit request inputs before the signing seam")
	}
}

// Claim: operation refusals preserve the closed phase/outcome error shape, and
// stdout loss after possible signature production is reported as UNKNOWN.
func TestRootGrantsSignV3CLIFailureAndReceiptLoss(t *testing.T) {
	grant, contract := rootGrantsSignInputFiles(t)
	old := reviewSignRootGrants
	t.Cleanup(func() { reviewSignRootGrants = old })
	reviewSignRootGrants = func(context.Context, keyvault.RootGrantsGrantV3SignRequest) (keyvault.RootGrantsGrantV3SignatureReceipt, error) {
		return keyvault.RootGrantsGrantV3SignatureReceipt{}, &keyvault.RootGrantsGrantV3Failure{Code: "review_refused", Phase: "review", Outcome: "not_applied", Message: "Root grants signature refused"}
	}
	code, stdout, stderr := rgInvoke(rootGrantsSignCLIArgs(grant, contract)...)
	if code != exitRefused || stderr != "" || !strings.Contains(stdout, `"phase": "review"`) || !strings.Contains(stdout, `"outcome": "not_applied"`) {
		t.Fatalf("closed refusal receipt missing: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	reviewSignRootGrants = func(context.Context, keyvault.RootGrantsGrantV3SignRequest) (keyvault.RootGrantsGrantV3SignatureReceipt, error) {
		return keyvault.RootGrantsGrantV3SignatureReceipt{Schema: "keyvault-root-grants-signature-receipt/1", Outcome: "signed"}, nil
	}
	var errout strings.Builder
	out := output{command: "recovery", json: true, stdout: rgFailingWriter{}, stderr: &errout}
	if got := runRecoveryReviewSignGrantV3(rootGrantsSignCLIArgs(grant, contract)[3:], out); got != exitFailure || !strings.Contains(errout.String(), "outcome_unknown") || !strings.Contains(errout.String(), "do not retry automatically") {
		t.Fatalf("signature receipt loss was not classified unknown: code=%d stderr=%q", got, errout.String())
	}
}
