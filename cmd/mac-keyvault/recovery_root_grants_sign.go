package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type rootGrantsSignErrorReceipt struct {
	Code    string `json:"code"`
	Phase   string `json:"phase"`
	Outcome string `json:"outcome"`
	Message string `json:"message"`
}

type rootGrantsSignFailureEnvelope struct {
	OK      bool                       `json:"ok"`
	Command string                     `json:"command"`
	Error   rootGrantsSignErrorReceipt `json:"error"`
}

// Public grant and contract documents are explicit, bounded file inputs. The
// owner policy remains in its independently selected fixed path inside keyvault.
func rootGrantsReadPublicDocument(path string) ([]byte, error) {
	if path == "" {
		return nil, usagef("both --grant-file and --contract-file are required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, usagef("could not read public signing document")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 65536 {
		return nil, usagef("public signing document must be a regular file of 1..65536 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) == 0 || len(data) > 65536 {
		return nil, usagef("public signing document must be a regular file of 1..65536 bytes")
	}
	return data, nil
}

func runRecoveryReviewSignGrantV3(args []string, out output) int {
	f := newRootGrantsFlags("recovery "+rootGrantsSignV3Op,
		[]string{"grants-identity", "grants-version", "owner-principal", "grant-file", "contract-file"})
	if err := f.parse(args); err != nil {
		return recoveryFailureReceipt(out, err)
	}
	var grantsIdentity string
	for _, identityFlag := range []string{"grants-identity"} {
		value, err := f.identity(identityFlag)
		if err != nil {
			return recoveryFailureReceipt(out, err)
		}
		grantsIdentity = value
	}
	version, err := f.generation("grants-version")
	if err != nil {
		return recoveryFailureReceipt(out, err)
	}
	grant, err := rootGrantsReadPublicDocument(f.values["grant-file"])
	if err != nil {
		return recoveryFailureReceipt(out, err)
	}
	defer clear(grant)
	contract, err := rootGrantsReadPublicDocument(f.values["contract-file"])
	if err != nil {
		return recoveryFailureReceipt(out, err)
	}
	defer clear(contract)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	receipt, err := reviewSignRootGrants(ctx, keyvault.RootGrantsGrantV3SignRequest{
		Address: keyvault.RootGrantsAddress{Service: grantsIdentity, Version: version}, OwnerPrincipal: f.ownerPrincipal,
		Grant: grant, Contract: contract,
	})
	if err != nil {
		return rootGrantsSignFailure(out, err)
	}
	return rootGrantsSignSuccess(out, receipt)
}

func rootGrantsSignFailure(out output, err error) int {
	var failure *keyvault.RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil {
		failure = &keyvault.RootGrantsGrantV3Failure{Code: "operation_unavailable", Phase: "preflight", Outcome: "not_applied", Message: "Root grants signature operation unavailable"}
	}
	code := exitRefused
	if failure.Outcome == "unknown" {
		code = exitFailure
	}
	if out.json {
		b, marshalErr := json.MarshalIndent(rootGrantsSignFailureEnvelope{OK: false, Command: out.command, Error: rootGrantsSignErrorReceipt{
			Code: failure.Code, Phase: failure.Phase, Outcome: failure.Outcome, Message: failure.Message,
		}}, "", "  ")
		if marshalErr != nil || !writeRecoveryReceipt(out.stdout, append(b, '\n')) {
			writeRecoveryReceipt(out.stderr, []byte("root_grants_signature_receipt_unavailable: failure result could not be delivered\n"))
			return exitFailure
		}
		return code
	}
	fmt.Fprintf(out.stderr, "error: %s: %s\nphase: %s\noutcome: %s\n", failure.Code, failure.Message, failure.Phase, failure.Outcome)
	return code
}

func rootGrantsSignSuccess(out output, receipt keyvault.RootGrantsGrantV3SignatureReceipt) int {
	var b []byte
	if out.json {
		raw, err := json.MarshalIndent(response{OK: true, Command: out.command, Result: receipt}, "", "  ")
		if err != nil {
			return rootGrantsSignReceiptLost(out)
		}
		b = append(raw, '\n')
	} else {
		raw, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			return rootGrantsSignReceiptLost(out)
		}
		b = append(raw, '\n')
	}
	if !writeRecoveryReceipt(out.stdout, b) {
		return rootGrantsSignReceiptLost(out)
	}
	return exitOK
}

func rootGrantsSignReceiptLost(out output) int {
	writeRecoveryReceipt(out.stderr, []byte("root_grants_signature_outcome_unknown: signing may have completed; preserve state and do not retry automatically\n"))
	return exitFailure
}
