package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const recoveryUsage = "mac-keyvault [--json] recovery generate --service S --version G --nostr-version N --namecoin-version M | recovery restore --service S --version G --nostr-version N --namecoin-version M --expected-npub NPUB --expected-namecoin-xpub XPUB --expected-origin ORIGIN | recovery pub S --version G | recovery delete S --version G --expected-group-id ID"

var newRecoveryBackend = func() keyvault.RecoveryBackend { return keyvault.NewNostrSecurityStore() }

type recoveryOperations interface {
	Create(keyvault.RecoveryRequest, keyvault.RecoveryTerminal, bool) (keyvault.RecoveryRecord, error)
	Describe(string, int) (keyvault.RecoveryRecord, error)
	Delete(string, int, string) error
}

var makeRecoveryManager = func(backend keyvault.RecoveryBackend, lock keyvault.Locker) recoveryOperations {
	return keyvault.NewRecoveryManager(backend, lock)
}

func runRecovery(args []string, out output) int {
	if len(args) == 0 {
		return out.fail(usagef("recovery operation required"))
	}
	op := args[0]
	if op != "generate" && op != "restore" && op != "pub" && op != "delete" {
		return out.fail(usagef("unsupported recovery operation; private input and export are refused"))
	}
	fs := flag.NewFlagSet("recovery "+op, flag.ContinueOnError)
	var q keyvault.RecoveryRequest
	var expectedGroup string
	fs.IntVar(&q.Version, "version", 0, "explicit group generation")
	if op == "generate" || op == "restore" {
		fs.StringVar(&q.Service, "service", "", "service")
		fs.IntVar(&q.NostrVersion, "nostr-version", 0, "explicit Nostr generation")
		fs.IntVar(&q.NamecoinVersion, "namecoin-version", 0, "explicit Namecoin generation")
	}
	if op == "restore" {
		fs.StringVar(&q.ExpectedNPub, "expected-npub", "", "retained public Nostr pin")
		fs.StringVar(&q.ExpectedXPub, "expected-namecoin-xpub", "", "retained public Namecoin pin")
		fs.StringVar(&q.ExpectedOrigin, "expected-origin", "", "retained public derivation origin")
	}
	if op == "delete" {
		fs.StringVar(&expectedGroup, "expected-group-id", "", "exact public group pin")
	}
	positional, err := parseFlags(fs, args[1:])
	if err != nil {
		return out.fail(usagef("invalid recovery arguments; no secret argument/file/environment route is supported"))
	}
	if op == "pub" || op == "delete" {
		if len(positional) != 1 {
			return out.fail(usagef("one service is required"))
		}
		q.Service = positional[0]
	} else if len(positional) != 0 {
		return out.fail(usagef("unexpected recovery arguments"))
	}
	if keyvault.ValidateName("service", keyvault.CodeInvalidService, q.Service) != nil || q.Version < 1 || q.Version > 2147483647 {
		return out.fail(usagef("explicit valid service and generation required"))
	}
	if op == "generate" || op == "restore" {
		if q.NostrVersion < 1 || q.NostrVersion > 2147483647 || q.NamecoinVersion < 1 || q.NamecoinVersion > 2147483647 {
			return out.fail(usagef("both explicit purpose generations are required"))
		}
	}
	if op == "restore" && (q.ExpectedNPub == "" || q.ExpectedXPub == "" || q.ExpectedOrigin == "") {
		return out.fail(usagef("all retained public recovery pins are required"))
	}
	if op == "delete" && expectedGroup == "" {
		return out.fail(usagef("exact public group pin required"))
	}
	path, err := lockPath()
	if err != nil {
		return out.fail(err)
	}
	// No store is contacted and no phrase is exposed without a controlling
	// owner terminal. Public-only operations do not open that terminal.
	var terminal ownerRecoveryTerminal
	if op == "generate" || op == "restore" {
		terminal, err = newRecoveryTerminal()
		if err != nil {
			return out.fail(usagef("owner foreground controlling terminal unavailable"))
		}
		defer terminal.Close()
	}
	m := makeRecoveryManager(newRecoveryBackend(), keyvault.FileLock{Path: path})
	if op == "delete" {
		if err := m.Delete(q.Service, q.Version, expectedGroup); err != nil {
			return out.fail(err)
		}
		return out.success(map[string]bool{"deleted": true}, func(w io.Writer) { fmt.Fprintln(w, "deleted: true") })
	}
	var r keyvault.RecoveryRecord
	if op == "pub" {
		r, err = m.Describe(q.Service, q.Version)
	} else {
		r, err = m.Create(q, terminal, op == "restore")
	}
	if err != nil {
		return out.fail(err)
	}
	return out.success(r, func(w io.Writer) {
		fmt.Fprintf(w, "group: %s\nnpub: %s\npublic_key: %s\nnamecoin_xpub: %s\nnamecoin_origin: %s\nnostr_presence: none\nnamecoin_presence: biometry-any\nprivate_export: false\n", r.Account(), r.Nostr.NPub, r.Nostr.PublicKey, r.Namecoin.XPub, r.Namecoin.Origin)
	})
}
