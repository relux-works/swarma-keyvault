package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grantrequester"
	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const requestUsage = "swarma-keyvault grants request --payload FILE|- --requester-spki-der FILE"
const executeUsage = "swarma-keyvault grants execute --config FILE --certificate FILE --request FILE|-"

var newRequestManager = func() *keyvault.Manager {
	return keyvault.NewManager(keyvault.RoutedBackend{Keychain: keyvault.NewSecurityStore(), Enclave: keyvault.DefaultEnclaveStore()}, nil, keyvault.Origin{})
}

var executeLocal = func(e *grants.LocalEnrollment, c, q []byte) (*grants.LocalOutcome, error) {
	return grants.NewLocalMediator(e).Execute(context.Background(), c, q)
}

func runRequest(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() int { _, _ = fmt.Fprintln(stderr, requestUsage); return 2 }
	var payload, public onceString
	f := flag.NewFlagSet("grants request", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.Var(&payload, "payload", "complete exact request payload or -")
	f.Var(&public, "requester-spki-der", "separately expected public requester SPKI DER")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, requestUsage)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !payload.set || !public.set || payload.value == "" || public.value == "" || public.value == "-" {
		return usage()
	}
	raw, err := readInput(payload.value, stdin, 8192)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded request payload")
		return 1
	}
	pin, err := readInput(public.value, nil, 1024)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded public requester SPKI DER")
		return 1
	}
	prepared, err := grantrequester.Prepare(raw, pin)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	result, err := prepared.Sign(newRequestManager())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "local request signing refused or unavailable")
		return 1
	}
	if n, err := stdout.Write(result); err != nil || n != len(result) {
		return 1
	}
	return 0
}

func runExecute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() int { _, _ = fmt.Fprintln(stderr, executeUsage); return 2 }
	var config, certificate, request onceString
	f := flag.NewFlagSet("grants execute", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.Var(&config, "config", "custodian-enrolled local private configuration")
	f.Var(&certificate, "certificate", "signed certificate envelope")
	f.Var(&request, "request", "signed local request envelope or -")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, executeUsage)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !config.set || !certificate.set || !request.set || config.value == "" || config.value == "-" || certificate.value == "" || certificate.value == "-" || request.value == "" {
		return usage()
	}
	enrolled, err := grants.LoadLocalEnrollment(config.value)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "local enrollment refused or unavailable")
		return 1
	}
	c, err := readInput(certificate.value, nil, 98304)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded certificate envelope")
		return 1
	}
	q, err := readInput(request.value, stdin, 12288)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded local request envelope")
		return 1
	}
	outcome, err := executeLocal(enrolled, c, q)
	if outcome != nil {
		raw, marshalErr := json.Marshal(outcome)
		if marshalErr != nil {
			return 1
		}
		if n, writeErr := stdout.Write(raw); writeErr != nil || n != len(raw) {
			return 1
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
