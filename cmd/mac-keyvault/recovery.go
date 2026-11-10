package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const recoveryUsage = "mac-keyvault [--json] recovery plan|generate|restore --nostr-identity A --namecoin-identity B [--version G --nostr-version N --namecoin-version M] | recovery pub A --version G | recovery delete A --namecoin-identity B --version G --expected-group-id ID"

var newRecoveryBackend = func() keyvault.RecoveryBackend { return keyvault.NewNostrSecurityStore() }

type recoveryOperations interface {
	Create(keyvault.RecoveryRequest, keyvault.RecoveryTerminal, bool) (keyvault.RecoveryRecord, error)
	Plan(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error)
	Describe(string, int) (keyvault.RecoveryRecord, error)
	Delete(keyvault.RecoveryDeleteRequest, keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error)
}

var makeRecoveryManager = func(backend keyvault.RecoveryBackend, lock keyvault.Locker) recoveryOperations {
	return keyvault.NewRecoveryManager(backend, lock)
}

func runRecovery(args []string, out output) int {
	if len(args) == 0 {
		return out.fail(usagef("recovery operation required"))
	}
	op := args[0]
	if op != "plan" && op != "generate" && op != "restore" && op != "pub" && op != "delete" {
		return out.fail(usagef("unsupported recovery operation; private input and export are refused"))
	}
	fs := flag.NewFlagSet("recovery "+op, flag.ContinueOnError)
	var q keyvault.RecoveryRequest
	var expectedGroup string
	seen := map[string]bool{}
	stringFlag := func(name string, target *string) {
		fs.Func(name, "explicit public parameter", func(v string) error {
			if seen[name] {
				return errors.New("duplicate parameter")
			}
			seen[name] = true
			*target = v
			return nil
		})
	}
	intFlag := func(name string, target *int) {
		fs.Func(name, "explicit public generation", func(v string) error {
			if seen[name] {
				return errors.New("duplicate parameter")
			}
			seen[name] = true
			n, err := strconv.Atoi(v)
			if err != nil || strconv.Itoa(n) != v {
				return errors.New("invalid generation")
			}
			*target = n
			return nil
		})
	}
	intFlag("version", &q.Version)
	family := op == "plan" || op == "generate" || op == "restore"
	if family {
		stringFlag("service", &q.Service)
		stringFlag("nostr-identity", &q.NostrIdentity)
		stringFlag("namecoin-identity", &q.NamecoinIdentity)
		intFlag("nostr-version", &q.NostrVersion)
		intFlag("namecoin-version", &q.NamecoinVersion)
	}
	if op == "restore" {
		stringFlag("expected-npub", &q.ExpectedNPub)
		stringFlag("expected-namecoin-xpub", &q.ExpectedXPub)
		stringFlag("expected-origin", &q.ExpectedOrigin)
	}
	if op == "delete" {
		stringFlag("namecoin-identity", &q.NamecoinIdentity)
		stringFlag("expected-group-id", &expectedGroup)
	}
	positional, err := parseFlags(fs, args[1:])
	if err != nil {
		return out.fail(usagef("invalid recovery arguments; no secret argument/file/environment route is supported"))
	}
	validName := func(s string) bool { return keyvault.ValidateName("service", keyvault.CodeInvalidService, s) == nil }
	validVersion := func(v int, optional bool) bool { return v >= 1 && v <= 2147483647 || optional && v == 0 }
	if family {
		if len(positional) != 0 {
			return out.fail(usagef("unexpected recovery arguments"))
		}
		if seen["service"] {
			if seen["nostr-identity"] || seen["namecoin-identity"] || !validName(q.Service) {
				return out.fail(usagef("legacy service is exclusive of purpose identities"))
			}
		} else if !validName(q.NostrIdentity) || !validName(q.NamecoinIdentity) {
			return out.fail(usagef("both explicit valid purpose identities are required"))
		}
		if !validVersion(q.NostrVersion, op == "plan" && !seen["nostr-version"]) || !validVersion(q.NamecoinVersion, op == "plan" && !seen["namecoin-version"]) {
			return out.fail(usagef("valid purpose generations are required"))
		}
	} else {
		if len(positional) != 1 || !validName(positional[0]) {
			return out.fail(usagef("one valid Nostr identity is required"))
		}
		q.Service = positional[0]
	}
	if !validVersion(q.Version, op == "plan" && !seen["version"]) {
		return out.fail(usagef("valid group generation required"))
	}
	if op == "restore" && (q.ExpectedNPub == "" || q.ExpectedXPub == "" || q.ExpectedOrigin == "") {
		return out.fail(usagef("all retained public recovery pins are required"))
	}
	if op == "delete" && (!validName(q.NamecoinIdentity) || len(expectedGroup) != 32) {
		return out.fail(usagef("Namecoin identity and exact public group pin required"))
	}
	if op == "delete" {
		for _, c := range expectedGroup {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return out.fail(usagef("canonical public group pin required"))
			}
		}
	}
	path, err := lockPath()
	if err != nil {
		return out.fail(err)
	}
	// A mutation requires the owner's controlling terminal before custody is
	// constructed. Planning and public lookup have no terminal dependency.
	var terminal ownerRecoveryTerminal
	if op == "generate" || op == "restore" || op == "delete" {
		terminal, err = newRecoveryTerminal()
		if err != nil {
			return out.fail(usagef("owner foreground controlling terminal unavailable"))
		}
		defer terminal.Close()
	}
	m := makeRecoveryManager(newRecoveryBackend(), keyvault.FileLock{Path: path})
	if op == "plan" {
		p, err := m.Plan(q)
		if err != nil {
			return out.fail(err)
		}
		return out.success(p, func(w io.Writer) {
			fmt.Fprintf(w, "group: %s\nnostr_record: %s\nnamecoin_record: %s\nadvisory: true\n", p.Group, p.NostrRecord, p.NamecoinRecord)
		})
	}
	var r keyvault.RecoveryRecord
	if op == "delete" {
		r, err = m.Delete(keyvault.RecoveryDeleteRequest{NostrIdentity: q.Service, NamecoinIdentity: q.NamecoinIdentity, Version: q.Version, ExpectedGroupID: expectedGroup}, terminal)
	} else if op == "pub" {
		r, err = m.Describe(q.Service, q.Version)
	} else {
		r, err = m.Create(q, terminal, op == "restore")
	}
	if err != nil {
		return recoveryMutationFailure(out, err)
	}
	text := fmt.Sprintf("group: %s\nnostr_record: %s\nnamecoin_record: %s\nnpub: %s\npublic_key: %s\nnamecoin_xpub: %s\nnamecoin_origin: %s\nnostr_presence: none\nnamecoin_presence: biometry-any\nprivate_export: false\n", r.Account(), r.PurposeAccount(r.Nostr), r.PurposeAccount(r.Namecoin), r.Nostr.NPub, r.Nostr.PublicKey, r.Namecoin.XPub, r.Namecoin.Origin)
	if op == "delete" {
		text += "deleted: true\n"
		return recoveryMutationReceipt(out, op, r, struct {
			Deleted   bool                    `json:"deleted"`
			Reference keyvault.RecoveryRecord `json:"reference"`
		}{true, r}, text, nil)
	}
	if op != "pub" {
		return recoveryMutationReceipt(out, op, r, r, text, nil)
	}
	return out.success(r, func(w io.Writer) { fmt.Fprint(w, text) })
}

// Mutation replies are checked independently of the general CLI emitter. A
// receipt failure cannot turn one completed effect into a reported success.
func recoveryMutationReceipt(out output, operation string, reference keyvault.RecoveryRecord, result any, text string, err error) int {
	code := exitOK
	if err != nil {
		code = exitFailure
	}
	var b []byte
	if out.json {
		reply := response{OK: err == nil, Command: out.command, Result: result}
		if err != nil {
			reply.Error = contractError(err)
		}
		var encodeErr error
		b, encodeErr = json.MarshalIndent(reply, "", "  ")
		if encodeErr != nil {
			return recoveryReceiptLost(out, operation, reference)
		}
		b = append(b, '\n')
	} else {
		b = []byte(text)
	}
	// Go otherwise terminates on SIGPIPE for fd1/fd2 before returning EPIPE.
	// Keep the handler through the fallback diagnostic, then release only our
	// subscription. Preserve an already ignored signal or other subscribers.
	if !signal.Ignored(syscall.SIGPIPE) {
		broken := make(chan os.Signal, 1)
		signal.Notify(broken, syscall.SIGPIPE)
		defer signal.Stop(broken)
	}
	n, writeErr := out.stdout.Write(b)
	if writeErr != nil || n != len(b) {
		return recoveryReceiptLost(out, operation, reference)
	}
	return code
}
func recoveryReceiptLost(out output, operation string, reference keyvault.RecoveryRecord) int {
	// One bounded public diagnostic; never retry stdout or print writer errors.
	var b bytes.Buffer
	fmt.Fprintf(&b, "recovery_outcome_unknown: %s may have completed; UNCONFIRMED reference %s nostr_record=%s namecoin_record=%s group_id=%s; reconcile; do not retry or delete\n", operation, reference.Account(), reference.PurposeAccount(reference.Nostr), reference.PurposeAccount(reference.Namecoin), reference.GroupID)
	_, _ = out.stderr.Write(b.Bytes())
	return exitFailure
}
func recoveryMutationFailure(out output, err error) int {
	var unknown *keyvault.RecoveryOutcomeUnknown
	if !errors.As(err, &unknown) {
		return out.fail(err)
	}
	text := fmt.Sprintf("recovery_outcome_unknown: %s; UNCONFIRMED reference %s nostr_record=%s namecoin_record=%s group_id=%s; reconcile; do not retry or delete\n", unknown.Operation, unknown.Reference.Account(), unknown.Reference.PurposeAccount(unknown.Reference.Nostr), unknown.Reference.PurposeAccount(unknown.Reference.Namecoin), unknown.Reference.GroupID)
	return recoveryMutationReceipt(out, unknown.Operation, unknown.Reference, unknown, text, err)
}
