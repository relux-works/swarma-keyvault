package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const namecoinUsage = `mac-keyvault [--json] namecoin sign-psbt [--process-contract 2] --group ID --account ID --profile ABS --profile-sha256 HEX --account-pin ABS --request ABS --request-sha256 HEX --output ABS --timeout-seconds N [--reveal-values-pin ABS]
mac-keyvault [--json] namecoin reconcile --group ID --account ID --profile ABS --profile-sha256 HEX --account-pin ABS --query ABS --output ABS --timeout-seconds N
mac-keyvault [--json] namecoin initialize-journal --group ID --account ID --profile ABS --profile-sha256 HEX --account-pin ABS --adoption-plan-sha256 HEX --timeout-seconds N`

func runNamecoin(args []string, out output) int {
	ctx, cancel := namecoinSignalContext()
	defer cancel()
	return runNamecoinWith(ctx, args, out, runNamecoinSign)
}

func runNamecoinWith(ctx context.Context, args []string, out output, sign namecoinSignRunner) int {
	return runNamecoinWithRunners(ctx, args, out, sign, runNamecoinSign2)
}

func runNamecoinWithRunners(ctx context.Context, args []string, out output, sign namecoinSignRunner, sign2 namecoinSign2Runner) int {
	if len(args) == 0 {
		return out.fail(usagef("namecoin requires an operation"))
	}
	// A caller selector always enters the closed process/2 parser. A malformed
	// selector cannot fall through to the selector-absent process/1 route.
	var invocation namecoinprocess.Process2Invocation
	var selection namecoinprocess.Args
	var err error
	process2 := false
	for _, arg := range args[1:] {
		if arg == "--process-contract" || strings.HasPrefix(arg, "--process-contract=") {
			process2 = true
		}
	}
	if process2 {
		invocation, err = namecoinprocess.ParseProcess2Args(append([]string{"namecoin"}, args...))
		selection = invocation.Args()
	} else {
		argv := []string{"namecoin", args[0], "--process-contract", "1"}
		selection, err = namecoinprocess.ParseArgs(append(argv, args[1:]...))
	}
	if err != nil {
		return out.fail(usagef("invalid Namecoin arguments; see help"))
	}

	switch selection.Mode {
	case namecoinprocess.Reconcile:
		// The query format has no agreed parent-local receipt selection contract.
		// Admit only its bounded public inputs. Unit 1 never reads native history,
		// opens output, starts a helper, retries, or starts a fresh signing attempt.
		if _, err := namecoinprocess.PrepareReconcileFiles(selection); err != nil {
			var failure namecoinwire.Failure
			if !errors.As(err, &failure) {
				failure = namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
			}
			return failNamecoin(out, selection.Mode, failure)
		}
		return failNamecoin(out, selection.Mode, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true))
	case namecoinprocess.InitializeJournal:
		return failNamecoin(out, selection.Mode, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false))
	case namecoinprocess.SignPSBT:
		if (!process2 && sign == nil) || (process2 && sign2 == nil) {
			return failNamecoin(out, selection.Mode, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false))
		}
		var completion namecoinSigningResult
		var err error
		if process2 {
			completion, err = sign2(ctx, invocation)
		} else {
			completion, err = sign(ctx, selection, namecoinprocess.FramedStatusSource{})
		}
		if err != nil {
			var failure namecoinwire.Failure
			if !errors.As(err, &failure) {
				failure = namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
			}
			return failNamecoin(out, selection.Mode, failure)
		}
		resultBytes := completion.outcome.Result()
		if !completion.outcome.Success() || len(resultBytes) == 0 || completion.requestID == "" || completion.sittingID == "" || completion.unsignedTxID == "" {
			return failNamecoin(out, selection.Mode, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true))
		}
		result := map[string]string{
			"status":        "SIGNED",
			"mode":          string(selection.Mode),
			"result_path":   selection.OutputPath,
			"result_sha256": namecoinResultDigest(resultBytes),
			"request_id":    completion.requestID,
			"sitting_id":    completion.sittingID,
			"unsigned_txid": completion.unsignedTxID,
		}
		return namecoinSuccessReceipt(out, result)
	default:
		return out.fail(usagef("unsupported Namecoin operation"))
	}
}

func namecoinSuccessReceipt(out output, result map[string]string) int {
	var receipt []byte
	if out.json {
		encoded, err := json.MarshalIndent(response{OK: true, Command: out.command, Result: result}, "", "  ")
		if err != nil {
			return namecoinReceiptLost(out)
		}
		receipt = append(encoded, '\n')
	} else {
		receipt = []byte(fmt.Sprintf("status: SIGNED\nresult_path: %s\nresult_sha256: %s\n", result["result_path"], result["result_sha256"]))
	}
	if !writeRecoveryReceipt(out.stdout, receipt) {
		return namecoinReceiptLost(out)
	}
	return exitOK
}

func namecoinReceiptLost(out output) int {
	writeRecoveryReceipt(out.stderr, []byte("namecoin_signature_receipt_unavailable: signing may have completed; preserve the stored result and do not retry automatically\n"))
	return exitFailure
}

func failNamecoin(out output, mode namecoinprocess.Mode, failure namecoinwire.Failure) int {
	hint := "check the Namecoin operation inputs and policy"
	message := failure.Error()
	switch failure.Code() {
	case namecoinwire.HelperNotAdmitted:
		if mode == namecoinprocess.InitializeJournal {
			message = "Namecoin journal initialization is unavailable in this unit."
			hint = "use an explicitly admitted initialization release"
		} else {
			hint = "the matched helper and native status source are not admitted; no child was started"
		}
	case namecoinwire.OutcomeUnknown:
		if mode == namecoinprocess.Reconcile {
			message = "Namecoin reconciliation is unsupported; the prior result remains unknown."
			hint = "preserve the query and original signing evidence; do not retry or start a new signing attempt"
		} else {
			hint = "the signing result is unknown; preserve the result file and do not submit this request again"
		}
	}
	err := &responseError{
		Code:    string(failure.Code()),
		Message: message,
		Hint:    hint,
	}
	result := map[string]string{"status": failure.Status(), "mode": string(mode)}
	if out.json {
		encodeJSON(out.stdout, response{OK: false, Command: out.command, Result: result, Error: err})
		return failure.Exit()
	}
	fmt.Fprintf(out.stdout, "status: %s\nmode: %s\n", failure.Status(), mode)
	fmt.Fprintf(out.stderr, "error: %s: %s\n", err.Code, err.Message)
	fmt.Fprintf(out.stderr, "hint: %s\n", err.Hint)
	return failure.Exit()
}
