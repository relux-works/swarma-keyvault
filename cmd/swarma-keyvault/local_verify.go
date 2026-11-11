package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

const verifyUsage = "swarma-keyvault grants verify --config FILE --certificate FILE --request FILE|- [--owner-mxid MXID] [--at RFC3339 (test observation)]"

func runVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() int { _, _ = fmt.Fprintln(stderr, verifyUsage); return 2 }
	refuse := func(err error) int { _, _ = fmt.Fprintln(stderr, "refused:", err); return 1 }
	var config, certificate, request, at, owner onceString
	f := flag.NewFlagSet("grants verify", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.Var(&config, "config", "custodian-enrolled local configuration")
	f.Var(&certificate, "certificate", "signed certificate envelope")
	f.Var(&request, "request", "signed local request envelope or -")
	f.Var(&at, "at", "RFC3339 observation for tests; default is current time")
	f.Var(&owner, "owner-mxid", "expected principal of the enrolled verification key")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, verifyUsage)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !config.set || !certificate.set || !request.set || config.value == "" || config.value == "-" || certificate.value == "" || certificate.value == "-" || request.value == "" {
		return usage()
	}
	if owner.set && grants.ValidateOwnerPrincipal(owner.value) != nil {
		return usage()
	}
	var observedAt time.Time
	if at.set {
		var err error
		observedAt, err = time.Parse(time.RFC3339, at.value)
		if err != nil {
			return usage()
		}
	}
	enrolled, err := grants.LoadLocalEnrollment(config.value)
	if err != nil {
		return refuse(err)
	}
	if owner.set {
		if err := enrolled.RequireOwner(owner.value); err != nil {
			return refuse(err)
		}
	}
	c, err := readInput(certificate.value, nil, 98304)
	if err != nil {
		return refuse(errors.New("cannot read bounded certificate envelope"))
	}
	q, err := readInput(request.value, stdin, 12288)
	if err != nil {
		return refuse(errors.New("cannot read bounded local request envelope"))
	}
	if !at.set {
		observedAt = time.Now()
	}
	facts, err := enrolled.Verify(c, q, observedAt)
	if err != nil {
		return refuse(err)
	}
	raw, err := json.Marshal(struct {
		Verdict string `json:"verdict"`
		*grants.LocalVerification
	}{"accepted", facts})
	if err != nil {
		return 1
	}
	if n, err := stdout.Write(raw); err != nil || n != len(raw) {
		return 1
	}
	return 0
}
