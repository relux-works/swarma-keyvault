package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

func runA2ACertificate(args []string, stdin io.Reader, stdout, stderr io.Writer, sign bool) int {
	command := "a2a-prepare"
	if sign {
		command = "a2a-issue"
	}
	usageText := "swarma-keyvault grants " + command + " --payload FILE|- --owner-spki-der FILE --requester-spki-der FILE" + ownerIdentityUsage
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	configuredOwner := addOwnerFlags(f)
	var payload, owner, requester onceString
	f.Var(&payload, "payload", "exact closed canonical certificate payload or -")
	f.Var(&owner, "owner-spki-der", "independent owner public P-256 DER")
	f.Var(&requester, "requester-spki-der", "independently admitted grantee public P-256 DER")
	usage := func() int { fmt.Fprintln(stderr, usageText); return 2 }
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, usageText)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !payload.set || payload.value == "" || !owner.set || owner.value == "" || owner.value == "-" || !requester.set || requester.value == "" || requester.value == "-" {
		return usage()
	}
	ownerConfig, ownerErr := configuredOwner.config()
	if ownerErr != nil {
		return usage()
	}
	raw, err := readInput(payload.value, stdin, 4096)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded a2a certificate payload")
		return 1
	}
	ownerDER, err := readInput(owner.value, nil, 1024)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded owner public key")
		return 1
	}
	requesterDER, err := readInput(requester.value, nil, 1024)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded grantee public key")
		return 1
	}
	if sign {
		prepared, err := grantissuer.PrepareA2A(ownerConfig, raw, ownerDER, requesterDER)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		result, err := prepared.Sign(newIssueManager(prepared.Prompt), stderr)
		if err != nil {
			fmt.Fprintln(stderr, "typed a2a grant issuance refused or unavailable")
			return 1
		}
		return writeA2AOutput(stdout, result)
	}
	prepared, err := grants.PrepareA2ACertificate(raw, ownerConfig.Principal, ownerDER, requesterDER)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	review := "Owner key pin: " + ownerkey.PublicPin(ownerConfig.Address, ownerDER) + prepared.Review()
	if n, err := io.WriteString(stderr, review); err != nil || n != len(review) {
		return 1
	}
	return writeA2AOutput(stdout, prepared.Payload())
}

func runA2ARequest(args []string, stdin io.Reader, stdout, stderr io.Writer, pack bool) int {
	command := "a2a-request-prepare"
	extra := ""
	if pack {
		command = "a2a-request-pack"
		extra = " --signature FILE --public-spki-der FILE"
	}
	usageText := "swarma-keyvault grants " + command + " --payload FILE|- --request FILE" + extra
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var payload, request, signature, public onceString
	f.Var(&payload, "payload", "exact canonical twelve-field signed request payload or -")
	f.Var(&request, "request", "exact canonical action payload file")
	if pack {
		f.Var(&signature, "signature", "strict DER low-S P-256 signature file")
		f.Var(&public, "public-spki-der", "public key matching the signing contribution")
	}
	usage := func() int { fmt.Fprintln(stderr, usageText); return 2 }
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, usageText)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !payload.set || payload.value == "" || !request.set || request.value == "" || request.value == "-" || (pack && (!signature.set || signature.value == "" || signature.value == "-" || !public.set || public.value == "" || public.value == "-")) {
		return usage()
	}
	raw, err := readInput(payload.value, stdin, 4096)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded a2a request payload")
		return 1
	}
	action, err := readInput(request.value, nil, 1024)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded a2a action payload")
		return 1
	}
	prepared, err := grants.PrepareA2ARequest(raw, action)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if pack {
		sig, err := readInput(signature.value, nil, 72)
		if err != nil {
			fmt.Fprintln(stderr, "cannot read bounded request signature")
			return 1
		}
		der, err := readInput(public.value, nil, 1024)
		if err != nil {
			fmt.Fprintln(stderr, "cannot read bounded public key")
			return 1
		}
		wire, err := prepared.SignedEnvelope(sig, der)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return writeA2AOutput(stdout, wire)
	}
	digest := prepared.Digest()
	result, err := json.Marshal(map[string]string{"type": "grants-a2a-request-prepared-1", "payload": base64.RawURLEncoding.EncodeToString(prepared.Payload()), "request": base64.RawURLEncoding.EncodeToString(action), "digest_sha256": hex.EncodeToString(digest[:])})
	if err != nil {
		return 1
	}
	return writeA2AOutput(stdout, result)
}

func writeA2AOutput(w io.Writer, raw []byte) int {
	if n, err := w.Write(raw); err != nil || n != len(raw) {
		return 1
	}
	return 0
}

func runA2AExecutor(args []string, stdout, stderr io.Writer, operation string) int {
	usageText := "swarma-keyvault grants " + operation + " --config FILE"
	if operation != "a2a-state-init" {
		usageText += " --event EVENT"
	}
	f := flag.NewFlagSet(operation, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var config, event onceString
	f.Var(&config, "config", "separately installed bounded public trust configuration")
	if operation != "a2a-state-init" {
		f.Var(&event, "event", "explicit original Matrix event ID")
	}
	usage := func() int { fmt.Fprintln(stderr, usageText); return 2 }
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, usageText)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !config.set || config.value == "" || config.value == "-" || (operation != "a2a-state-init" && (!event.set || event.value == "")) {
		return usage()
	}
	raw, err := grants.LoadA2AExecutorConfig(config.value)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded a2a public trust configuration")
		return 1
	}
	executor, err := grants.ParseA2AExecutor(raw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var result any
	switch operation {
	case "a2a-state-init":
		err = executor.InitializeState()
		result = map[string]string{"type": "grants-a2a-state-initialized-1"}
	case "a2a-verify":
		var verified *grants.A2AVerifiedEnvelope
		verified, err = executor.Verify(context.Background(), event.value)
		if err == nil {
			result = map[string]string{"type": "grants-a2a-verification-1", "certificate_id": verified.CertificateID, "entry_id": verified.EntryID, "sender_mxid": verified.SenderMXID, "event_id": verified.EventID, "request_sha256": verified.RequestSHA256}
		}
	case "a2a-execute":
		var out *grants.A2AOutcome
		out, err = executor.Execute(context.Background(), event.value)
		if out != nil {
			result = map[string]string{"type": "grants-a2a-outcome-1", "state": out.State, "repository_id": out.RepositoryID, "node_id": out.NodeID, "full_name": out.FullName}
		}
	default:
		return usage()
	}
	if err != nil {
		// A post-intent failure still reports UNKNOWN; failed publication cannot
		// roll back the held use or authorize retry. Never forward subprocess text.
		if result != nil && operation == "a2a-execute" {
			if b, merr := json.Marshal(result); merr == nil {
				_ = writeA2AOutput(stdout, b)
			}
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	raw, err = json.Marshal(result)
	if err != nil {
		return 1
	}
	return writeA2AOutput(stdout, raw)
}
