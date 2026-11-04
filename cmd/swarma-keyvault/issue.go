package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const issueUsage = "swarma-keyvault grants issue --payload FILE|- --owner-spki-der FILE"

// Constructed only after complete typed preparation. Tests replace this factory
// with a software fixture; no real store is selected by ordinary CLI tests.
var newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
	enclave := keyvault.DefaultEnclaveStore()
	enclave.Describe = prompt
	backend := keyvault.RoutedBackend{Keychain: keyvault.NewSecurityStore(), Enclave: enclave}
	return keyvault.NewManager(backend, nil, keyvault.Origin{})
}

func runIssue(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() int { _, _ = fmt.Fprintln(stderr, issueUsage); return 2 }
	var payload, public onceString
	flags := flag.NewFlagSet("grants issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&payload, "payload", "complete exact canonical certificate payload, or -")
	flags.Var(&public, "owner-spki-der", "independently expected public owner P-256 DER")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, issueUsage)
			return 0
		}
		return usage()
	}
	if flags.NArg() != 0 || !payload.set || !public.set || payload.value == "" || public.value == "" || public.value == "-" {
		return usage()
	}
	raw, err := readInput(payload.value, stdin, 65536)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded certificate payload")
		return 1
	}
	pin, err := readInput(public.value, nil, 1024)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded public owner SPKI DER")
		return 1
	}
	prepared, err := grantissuer.Prepare(raw, pin)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	envelope, err := prepared.Sign(newIssueManager(prepared.Prompt), stderr)
	if err != nil {
		// No raw backend/helper stderr, local store paths or signing inputs are
		// forwarded. No failure triggers a retry, key creation or store fallback.
		_, _ = fmt.Fprintln(stderr, "typed grant issuance refused or unavailable")
		return 1
	}
	if n, err := stdout.Write(envelope); err != nil || n != len(envelope) {
		return 1
	}
	return 0
}
