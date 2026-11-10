package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const issueUsage = "swarma-keyvault grants issue --payload FILE|- --owner-spki-der FILE" + ownerIdentityUsage
const localIssueUsage = "swarma-keyvault grants local-issue --payload FILE|- --owner-spki-der FILE --requester-spki-der FILE" + ownerIdentityUsage

// Constructed only after complete typed preparation. Tests replace this factory
// with a software fixture; no real store is selected by ordinary CLI tests.
var newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
	enclave := keyvault.DefaultEnclaveStore()
	enclave.Describe = prompt
	backend := keyvault.RoutedBackend{Keychain: keyvault.NewSecurityStore(), Enclave: enclave}
	return keyvault.NewManager(backend, nil, keyvault.Origin{})
}

func runIssue(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runIssueProfile(args, stdin, stdout, stderr, false)
}

func runIssueProfile(args []string, stdin io.Reader, stdout, stderr io.Writer, local bool) int {
	usageText := issueUsage
	if local {
		usageText = localIssueUsage
	}

	usage := func() int { _, _ = fmt.Fprintln(stderr, usageText); return 2 }
	var payload, public, requester onceString
	flags := flag.NewFlagSet("grants issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configuredOwner := addOwnerFlags(flags)
	flags.Var(&payload, "payload", "complete exact canonical certificate payload, or -")
	flags.Var(&public, "owner-spki-der", "independently expected public owner P-256 DER")
	if local {
		flags.Var(&requester, "requester-spki-der", "independently expected requester P-256 DER")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, usageText)
			return 0
		}
		return usage()
	}
	if (local && (!requester.set || requester.value == "" || requester.value == "-")) || flags.NArg() != 0 || !payload.set || !public.set || payload.value == "" || public.value == "" || public.value == "-" {
		return usage()
	}
	ownerConfig, ownerErr := configuredOwner.config()
	if ownerErr != nil {
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
	var prepared *grantissuer.Prepared
	if local {
		requesterPin, readErr := readInput(requester.value, nil, 1024)
		if readErr != nil {
			_, _ = fmt.Fprintln(stderr, "cannot read bounded requester SPKI DER")
			return 1
		}
		prepared, err = grantissuer.PrepareLocal(ownerConfig, raw, pin, requesterPin)
	} else {
		prepared, err = grantissuer.Prepare(ownerConfig, raw, pin)
	}
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
