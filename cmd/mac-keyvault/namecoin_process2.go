//go:build darwin || linux

package main

import (
	"context"
	"crypto/sha256"
	"os/exec"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type namecoinSign2Runner func(context.Context, namecoinprocess.Process2Invocation) (namecoinSigningResult, error)

func runNamecoinSign2(ctx context.Context, invocation namecoinprocess.Process2Invocation) (namecoinSigningResult, error) {
	if ctx == nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.InvalidRequest, false)
	}
	args := invocation.Args()
	started := time.Now()
	deadline := started.Add(args.Timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if ctx.Err() != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.AuthRefused, false)
	}
	prepared, err := namecoinprocess.PrepareSigningFiles(args, started)
	if err != nil {
		return namecoinSigningResult{}, namecoinFailure(err, false)
	}
	helper, _, err := keyvault.NamecoinProcessHelper()
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
	}
	frame, err := keyvault.PrepareNamecoinProcess2(ctx, prepared)
	if err != nil {
		return namecoinSigningResult{}, namecoinFailure(err, false)
	}
	defer clear(frame)
	if ctx.Err() != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.AuthRefused, false)
	}
	inputs := namecoinprocess.Process2AttemptInputs{Mode: args.Mode, Group: args.Group, Account: args.Account,
		ProfileSHA256: sha256.Sum256(prepared.ProfileBytes()), OperationInputSHA256: sha256.Sum256(prepared.InputBytes())}
	command := exec.Command(helper, invocation.Argv()...)
	outcome := namecoinprocess.RunProcess2(ctx, command, namecoinprocess.Process2RunOptions{
		Invocation: invocation, AttemptInputs: inputs, Frame: frame, Deadline: deadline,
		Verification: namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: prepared.Attempt()},
		Admit:        keyvault.AdmitNamecoinProcess2Child,
	})
	// The adapter owns all child/descriptor lifetimes and performs final public
	// signature verification before its original-deadline check. Never retry.
	if !outcome.Success() {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
	}
	request, err := namecoinwire.Decode(prepared.InputBytes())
	if err != nil {
		return namecoinSigningResult{}, namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
	}
	return namecoinSigningResult{outcome: outcome, requestID: request.Request().RequestID,
		sittingID: request.Request().SittingID, unsignedTxID: prepared.Attempt().Candidate().View().UnsignedTxID}, nil
}
