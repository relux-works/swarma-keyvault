package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/grants"
)

func runA2ACertificate(args []string, stdin io.Reader, stdout, stderr io.Writer, sign bool) int {
	command := "a2a-prepare"
	if sign {
		command = "a2a-issue"
	}
	usageText := "swarma-keyvault grants " + command + " --payload FILE|- --owner-spki-der FILE --requester-spki-der FILE"
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
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
		prepared, err := grantissuer.PrepareA2A(raw, ownerDER, requesterDER)
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
	prepared, err := grants.PrepareA2ACertificate(raw, grantissuer.OwnerMXID, ownerDER, requesterDER)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if n, err := io.WriteString(stderr, prepared.Review()); err != nil || n != len(prepared.Review()) {
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
