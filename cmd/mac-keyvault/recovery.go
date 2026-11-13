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

const recoveryUsage = "mac-keyvault [--json] recovery plan|generate|restore --nostr-identity A --namecoin-identity B [--version G --nostr-version N --namecoin-version M] | recovery pub A --version G | recovery delete A --version G --expected-group-id ID | recovery attach-root-grants --nostr-identity A --namecoin-identity B --version G --nostr-version N --namecoin-version M --grants-identity R --grants-version V --expected-group-id ID --expected-pair-metadata-sha256 H --expected-npub NPUB --expected-namecoin-xpub XPUB --expected-origin ORIGIN | recovery root-grants-pub --grants-identity R --grants-version V [--format id-value] | recovery review-sign-grant-v3 --grants-identity R --grants-version V --owner-principal P --grant-file PATH --contract-file PATH"

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
		return recoveryFailureReceipt(out, usagef("recovery operation required"))
	}
	op := args[0]
	// The root-grants operations have their own closed flag sets and never share the
	// pair family's parsing, validation or custody construction.
	switch op {
	case rootGrantsAttachOp:
		return runRecoveryAttachRootGrants(args[1:], out)
	case rootGrantsPubOp:
		return runRecoveryRootGrantsPub(args[1:], out)
	case rootGrantsSignV3Op:
		return runRecoveryReviewSignGrantV3(args[1:], out)
	}
	if op != "plan" && op != "generate" && op != "restore" && op != "pub" && op != "delete" {
		return recoveryFailureReceipt(out, usagef("unsupported recovery operation; private input and export are refused"))
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
	if op == "generate" || op == "restore" {
		stringFlag("service", &q.Service)
	}
	if family {
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
		stringFlag("expected-group-id", &expectedGroup)
	}
	positional, err := parseFlags(fs, args[1:])
	if err != nil {
		return recoveryFailureReceipt(out, usagef("invalid recovery arguments; no secret argument/file/environment route is supported"))
	}
	validName := func(s string) bool { return keyvault.ValidateName("service", keyvault.CodeInvalidService, s) == nil }
	validVersion := func(v int, optional bool) bool { return v >= 1 && v <= 2147483647 || optional && v == 0 }
	if family {
		if len(positional) != 0 {
			return recoveryFailureReceipt(out, usagef("unexpected recovery arguments"))
		}
		if seen["service"] {
			if seen["nostr-identity"] || seen["namecoin-identity"] || !validName(q.Service) {
				return recoveryFailureReceipt(out, usagef("legacy service is exclusive of purpose identities"))
			}
		} else if !validName(q.NostrIdentity) || !validName(q.NamecoinIdentity) {
			return recoveryFailureReceipt(out, usagef("both explicit valid purpose identities are required"))
		}
		if !validVersion(q.NostrVersion, op == "plan" && !seen["nostr-version"]) || !validVersion(q.NamecoinVersion, op == "plan" && !seen["namecoin-version"]) {
			return recoveryFailureReceipt(out, usagef("valid purpose generations are required"))
		}
	} else {
		if len(positional) != 1 || !validName(positional[0]) {
			return recoveryFailureReceipt(out, usagef("one valid Nostr identity is required"))
		}
		q.Service = positional[0]
	}
	if !validVersion(q.Version, op == "plan" && !seen["version"]) {
		return recoveryFailureReceipt(out, usagef("valid group generation required"))
	}
	if op == "restore" && q.ValidateRestorePins() != nil {
		return recoveryFailureReceipt(out, usagef("three canonical retained public recovery pins are required"))
	}
	if op == "delete" && len(expectedGroup) != 32 {
		return recoveryFailureReceipt(out, usagef("exact public group pin required"))
	}
	if op == "delete" {
		for _, c := range expectedGroup {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return recoveryFailureReceipt(out, usagef("canonical public group pin required"))
			}
		}
	}
	lock, err := vaultLock()
	if err != nil {
		return recoveryFailureReceipt(out, &keyvault.Refusal{Code: "recovery_lock_unavailable",
			Message: "Recovery operation refused: lock_unavailable", Hint: "check that the vault lock is available"})
	}
	// A mutation requires the owner's controlling terminal before custody is
	// constructed. Planning and public lookup have no terminal dependency.
	var terminal ownerRecoveryTerminal
	if op == "generate" || op == "restore" || op == "delete" {
		terminal, err = newRecoveryTerminal()
		if err != nil {
			return recoveryFailureReceipt(out, usagef("owner foreground controlling terminal unavailable"))
		}
		defer terminal.Close()
	}
	m := makeRecoveryManager(newRecoveryBackend(), lock)
	if op == "plan" {
		p, err := m.Plan(q)
		if err != nil {
			return recoveryBoundedFailure(out, err)
		}
		return recoveryPublicReceipt(out, p, fmt.Sprintf("group: %s\nnostr_record: %s\nnamecoin_record: %s\nadvisory: true\n",
			p.Group, p.NostrRecord, p.NamecoinRecord))
	}
	var r keyvault.RecoveryRecord
	if op == "delete" {
		r, err = m.Delete(keyvault.RecoveryDeleteRequest{NostrIdentity: q.Service, Version: q.Version, ExpectedGroupID: expectedGroup}, terminal)
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
	// The retained public pins the root-grants attach needs: the group id and the
	// digest of the exact canonical pair metadata, from the attach's own function.
	// A record that function refuses is not described at all.
	digest, err := r.PairMetadataSHA256()
	if err != nil {
		return recoveryBoundedFailure(out, err)
	}
	text += fmt.Sprintf("group_id: %s\npair_metadata_sha256: %s\n", r.GroupID, digest)
	return recoveryPublicReceipt(out, recoveryPublicResult{RecoveryRecord: r, PairDigest: digest}, text)
}

// recoveryPublicResult is the JSON result of `recovery pub`: every member of the
// public record exactly as before, plus the pair metadata digest. The digest is
// not a member of RecoveryRecord, whose canonical bytes it is computed over.
type recoveryPublicResult struct {
	keyvault.RecoveryRecord
	PairDigest string `json:"pair_metadata_sha256"`
}

func recoveryPublicReceipt(out output, result any, text string) int {
	b := []byte(text)
	if out.json {
		raw, err := json.MarshalIndent(response{OK: true, Command: out.command, Result: result}, "", "  ")
		if err != nil {
			return exitFailure
		}
		b = append(raw, '\n')
	}
	if !writeRecoveryReceipt(out.stdout, b) {
		writeRecoveryReceipt(out.stderr, []byte("recovery_public_output_unavailable: could not write public result\n"))
		return exitFailure
	}
	return exitOK
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
	if !writeRecoveryReceipt(out.stdout, b) {
		return recoveryReceiptLost(out, operation, reference)
	}
	return code
}

func writeRecoveryReceipt(w io.Writer, b []byte) bool {
	// Go otherwise terminates on SIGPIPE for fd1/fd2 before returning EPIPE.
	// Preserve an already ignored signal or other subscribers.
	if !signal.Ignored(syscall.SIGPIPE) {
		broken := make(chan os.Signal, 1)
		signal.Notify(broken, syscall.SIGPIPE)
		defer signal.Stop(broken)
	}
	n, err := w.Write(b)
	return err == nil && n == len(b)
}
func recoveryReceiptLost(out output, operation string, reference keyvault.RecoveryRecord) int {
	// One bounded public diagnostic; never retry stdout or print writer errors.
	var b bytes.Buffer
	fmt.Fprintf(&b, "recovery_outcome_unknown: %s may have completed; UNCONFIRMED reference %s nostr_record=%s namecoin_record=%s group_id=%s; reconcile; do not retry or delete\n", operation, reference.Account(), reference.PurposeAccount(reference.Nostr), reference.PurposeAccount(reference.Namecoin), reference.GroupID)
	writeRecoveryReceipt(out.stderr, b.Bytes())
	return exitFailure
}

// Definite refusals retain their contract code only after complete delivery.
// Delivery failure is a separate bounded error and never retries the operation.
func recoveryFailureReceipt(out output, err error) int {
	code, detail := out.classify(err)
	writer := out.stderr
	var b []byte
	if out.json {
		writer = out.stdout
		b, err = json.MarshalIndent(response{OK: false, Command: out.command, Error: detail}, "", "  ")
		if err == nil {
			b = append(b, '\n')
		}
	} else {
		var text bytes.Buffer
		fmt.Fprintf(&text, "error: %s: %s\n", detail.Code, detail.Message)
		if detail.Status != 0 {
			fmt.Fprintf(&text, "os_status: %d (%s)\n", detail.Status, keyvault.OSStatusName(detail.Status))
		}
		fmt.Fprintf(&text, "hint: %s\n", detail.Hint)
		b = text.Bytes()
		err = nil
	}
	if err != nil || !writeRecoveryReceipt(writer, b) {
		writeRecoveryReceipt(out.stderr, []byte("recovery_refusal_output_unavailable: refusal="+detail.Code+"; could not write failure result\n"))
		return exitFailure
	}
	return code
}

func recoveryBoundedFailure(out output, err error) int {
	if errors.Is(err, keyvault.ErrNotFound) {
		return recoveryFailureReceipt(out, keyvault.ErrNotFound)
	}
	if keyvault.ClassifyError(err).Code == keyvault.CodeFailure {
		err = &keyvault.Refusal{Code: "recovery_backend_unavailable",
			Message: "Recovery backend unavailable", Hint: "check the vault without changing existing records", Failure: true}
	}
	return recoveryFailureReceipt(out, err)
}

func recoveryMutationFailure(out output, err error) int {
	var unknown *keyvault.RecoveryOutcomeUnknown
	if !errors.As(err, &unknown) {
		return recoveryBoundedFailure(out, err)
	}
	text := fmt.Sprintf("recovery_outcome_unknown: %s; UNCONFIRMED reference %s nostr_record=%s namecoin_record=%s group_id=%s; reconcile; do not retry or delete\n", unknown.Operation, unknown.Reference.Account(), unknown.Reference.PurposeAccount(unknown.Reference.Nostr), unknown.Reference.PurposeAccount(unknown.Reference.Namecoin), unknown.Reference.GroupID)
	return recoveryMutationReceipt(out, unknown.Operation, unknown.Reference, unknown, text, err)
}
