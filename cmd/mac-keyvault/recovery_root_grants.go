package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// Production routes of the two root-grants operations. Tests replace them; no
// flag, environment variable or file can.
var (
	attachRootGrants = keyvault.AttachRootGrants
	lookupRootGrants = keyvault.RootGrantsPublicLookup
)

const (
	rootGrantsAttachOp = "attach-root-grants"
	rootGrantsPubOp    = "root-grants-pub"
	// One fixed public line, printed after every flag was admitted and before the
	// vault is touched. It carries no value and no input echo.
	rootGrantsAttachNotice = "root grants attach: follow the review window and the terminal prompts\n"
)

// rootGrantsFlags parses a closed set of flags. Every flag is a plain value flag:
// a repeated flag, an unknown flag, a positional argument or a missing required
// flag is a usage error, decided before any custody, lock, helper or Keychain call.
type rootGrantsFlags struct {
	fs       *flag.FlagSet
	seen     map[string]bool
	values   map[string]string
	required []string
}

func newRootGrantsFlags(name string, required []string, optional ...string) *rootGrantsFlags {
	f := &rootGrantsFlags{fs: flag.NewFlagSet(name, flag.ContinueOnError), seen: map[string]bool{}, values: map[string]string{}, required: required}
	for _, flagName := range append(append([]string{}, required...), optional...) {
		flagName := flagName
		f.fs.Func(flagName, "explicit public parameter", func(v string) error {
			if f.seen[flagName] {
				return errors.New("duplicate parameter")
			}
			f.seen[flagName] = true
			f.values[flagName] = v
			return nil
		})
	}
	return f
}

func (f *rootGrantsFlags) parse(args []string) error {
	positional, err := parseFlags(f.fs, args)
	if err != nil {
		return usagef("invalid recovery arguments; no secret argument/file/environment route is supported")
	}
	if len(positional) != 0 {
		return usagef("unexpected recovery arguments")
	}
	for _, name := range f.required {
		if !f.seen[name] {
			return usagef("every public parameter is required: missing --%s", name)
		}
	}
	return nil
}

// generation is a canonical decimal 1..2147483647: no sign, no leading zero.
func (f *rootGrantsFlags) generation(name string) (int, error) {
	v := f.values[name]
	n, err := strconv.Atoi(v)
	if err != nil || strconv.Itoa(n) != v || n < 1 || n > 2147483647 {
		return 0, usagef("--%s must be a canonical generation 1..2147483647", name)
	}
	return n, nil
}

func (f *rootGrantsFlags) identity(name string) (string, error) {
	v := f.values[name]
	if keyvault.ValidateName("service", keyvault.CodeInvalidService, v) != nil {
		return "", usagef("--%s must be 1..40 characters of a-z, 0-9 and hyphen", name)
	}
	return v, nil
}

func runRecoveryAttachRootGrants(args []string, out output) int {
	required := []string{"nostr-identity", "namecoin-identity", "version", "nostr-version", "namecoin-version", "grants-identity", "grants-version",
		"expected-group-id", "expected-pair-metadata-sha256", "expected-npub", "expected-namecoin-xpub", "expected-origin"}
	f := newRootGrantsFlags("recovery "+rootGrantsAttachOp, required)
	if err := f.parse(args); err != nil {
		return recoveryFailureReceipt(out, err)
	}
	var q keyvault.RootGrantsAttachRequest
	// Every identity and generation comes from its own flag through the validators
	// below; the table names the flag and the destination, and the value is only
	// ever the validated argument (never a literal in the assignment).
	for _, identity := range []struct {
		flag   string
		target *string
	}{{"nostr-identity", &q.NostrIdentity}, {"namecoin-identity", &q.NamecoinIdentity}, {"grants-identity", &q.GrantsIdentity}} {
		value, err := f.identity(identity.flag)
		if err != nil {
			return recoveryFailureReceipt(out, err)
		}
		*identity.target = value
	}
	for _, generation := range []struct {
		flag   string
		target *int
	}{{"version", &q.Version}, {"nostr-version", &q.NostrVersion}, {"namecoin-version", &q.NamecoinVersion}, {"grants-version", &q.GrantsVersion}} {
		value, err := f.generation(generation.flag)
		if err != nil {
			return recoveryFailureReceipt(out, err)
		}
		*generation.target = value
	}
	q.ExpectedGroupID, q.ExpectedPairMetadataSHA256 = f.values["expected-group-id"], f.values["expected-pair-metadata-sha256"]
	q.ExpectedNPub, q.ExpectedNamecoinXPub, q.ExpectedOrigin = f.values["expected-npub"], f.values["expected-namecoin-xpub"], f.values["expected-origin"]
	if !canonicalLowerHex(q.ExpectedGroupID, 32) || !canonicalLowerHex(q.ExpectedPairMetadataSHA256, 64) {
		return recoveryFailureReceipt(out, usagef("canonical retained public pins are required"))
	}
	pins := keyvault.RecoveryRequest{ExpectedNPub: q.ExpectedNPub, ExpectedXPub: q.ExpectedNamecoinXPub, ExpectedOrigin: q.ExpectedOrigin}
	if pins.ValidateRestorePins() != nil {
		return recoveryFailureReceipt(out, usagef("three canonical retained public recovery pins are required"))
	}
	// Best effort: the notice is guidance for the owner, not part of the
	// receipt, so an unwritable stderr must not turn a valid attach into a refusal.
	writeRecoveryReceipt(out.stderr, []byte(rootGrantsAttachNotice))
	// The helper owns the terminal and has its own absolute budget. An interrupt
	// cancels this context, which the attach flow maps to canceled / UNKNOWN by the
	// actual effect boundary.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := attachRootGrants(ctx, q)
	if err != nil {
		failure, ok := keyvault.RootGrantsAttachFailureOf(err)
		if !ok {
			// An untyped error after the attach stage may follow a possible add:
			// report UNKNOWN, never a refusal.
			failure = keyvault.RootGrantsAttachFailure{Code: "mutation_unknown", Phase: "commit", Outcome: "unknown",
				Message: "Root grants attachment outcome unknown; do not retry or delete"}
		}
		return rootGrantsAttachFailureReceipt(out, failure)
	}
	receipt, err := keyvault.NewRootGrantsReceipt(result)
	if err != nil {
		return rootGrantsReceiptLost(out, &result.Root)
	}
	text := fmt.Sprintf("outcome: stored\nroot_grants: %s\nnamespace: %s\nprofile: %s\npath: %s\npublic_key: %s\nseal_public_key: %s\nseal_script: %s\nstorage: %s\npresence: %s\nprivate_export: false\npair_unchanged: true\n",
		receipt.Root.Account, receipt.Root.Namespace, receipt.Root.Profile, receipt.Root.Path, receipt.Root.PublicKey, receipt.Root.SealPublicKey, receipt.Root.SealScript, receipt.Storage, receipt.Presence)
	b := []byte(text)
	if out.json {
		raw, err := json.MarshalIndent(response{OK: true, Command: out.command, Result: receipt}, "", "  ")
		if err != nil {
			return rootGrantsReceiptLost(out, &receipt.Root)
		}
		b = append(raw, '\n')
	}
	if !writeRecoveryReceipt(out.stdout, b) {
		return rootGrantsReceiptLost(out, &receipt.Root)
	}
	return exitOK
}

func canonicalLowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type rootGrantsUnknownResult struct {
	Outcome   string                         `json:"outcome"`
	Operation string                         `json:"operation"`
	Reference *keyvault.RootGrantsProjection `json:"reference,omitempty"`
}

// A definite refusal (not_applied) exits 3; a possible effect (unknown) exits 1
// with ok=false and the UNCONFIRMED public reference. Neither prints a value that
// came from the helper or the vault beyond the closed code and fixed text.
func rootGrantsAttachFailureReceipt(out output, failure keyvault.RootGrantsAttachFailure) int {
	unknown := failure.Outcome != "not_applied" // only a closed not_applied is a definite refusal
	detail := &responseError{Code: failure.Code, Message: failure.Message, Hint: "no root item was stored and the retained pair is unchanged; a refusal before the add is safe to repeat once its cause is fixed"}
	code := exitRefused
	if unknown {
		code = exitFailure
		detail.Hint = "reconcile with recovery root-grants-pub; do not retry, delete or select another generation"
	}
	writer := out.stderr
	var b []byte
	if out.json {
		writer = out.stdout
		reply := response{OK: false, Command: out.command, Error: detail}
		if unknown {
			reply.Result = rootGrantsUnknownResult{Outcome: "unknown", Operation: rootGrantsAttachOp, Reference: failure.Reference}
		}
		raw, encodeErr := json.MarshalIndent(reply, "", "  ")
		if encodeErr != nil {
			return rootGrantsDeliveryFailed(out, failure)
		}
		b = append(raw, '\n')
	} else {
		text := fmt.Sprintf("error: %s: %s\nhint: %s\n", detail.Code, detail.Message, detail.Hint)
		if unknown && failure.Reference != nil {
			text += fmt.Sprintf("recovery_outcome_unknown: %s; UNCONFIRMED reference %s public_key=%s\n", rootGrantsAttachOp, failure.Reference.Account, failure.Reference.PublicKey)
		}
		b = []byte(text)
	}
	if !writeRecoveryReceipt(writer, b) {
		return rootGrantsDeliveryFailed(out, failure)
	}
	return code
}

// Delivery failure is its own bounded diagnostic: the closed outcome is repeated
// once on stderr and the effect class decides the exit, never a retry.
func rootGrantsDeliveryFailed(out output, failure keyvault.RootGrantsAttachFailure) int {
	writeRecoveryReceipt(out.stderr, []byte("recovery_refusal_output_unavailable: refusal="+failure.Code+" outcome="+failure.Outcome+"; could not write failure result\n"))
	return exitFailure
}

// The attach is stored but its receipt could not be delivered: that is UNKNOWN to
// the caller (receipt_unavailable), reconciled through the public export, never a
// reason to attach again.
func rootGrantsReceiptLost(out output, reference *keyvault.RootGrantsProjection) int {
	account, key := "", ""
	if reference != nil {
		account, key = reference.Account, reference.PublicKey
	}
	writeRecoveryReceipt(out.stderr, []byte(fmt.Sprintf("receipt_unavailable: %s may have completed; UNCONFIRMED reference %s public_key=%s; reconcile with recovery root-grants-pub; do not retry or delete\n", rootGrantsAttachOp, account, key)))
	return exitFailure
}

func runRecoveryRootGrantsPub(args []string, out output) int {
	f := newRootGrantsFlags("recovery "+rootGrantsPubOp, []string{"grants-identity", "grants-version"}, "format")
	if err := f.parse(args); err != nil {
		return recoveryFailureReceipt(out, err)
	}
	identity, err := f.identity("grants-identity")
	if err != nil {
		return recoveryFailureReceipt(out, err)
	}
	version, err := f.generation("grants-version")
	if err != nil {
		return recoveryFailureReceipt(out, err)
	}
	idValue := false
	if f.seen["format"] {
		if f.values["format"] != "id-value" {
			return recoveryFailureReceipt(out, usagef("--format admits only id-value"))
		}
		if out.json {
			return recoveryFailureReceipt(out, usagef("--format id-value writes raw value bytes and cannot be combined with --json"))
		}
		idValue = true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	receipt, err := lookupRootGrants(ctx, identity, version)
	if err != nil {
		return recoveryBoundedFailure(out, err)
	}
	if idValue {
		// Only the exact compact value bytes, no LF and no status text.
		return recoveryPublicReceipt(out, receipt, receipt.IDValueUTF8)
	}
	text := fmt.Sprintf("root_grants: %s\npublic_key: %s\nseal_public_key: %s\nseal_script: %s\nid_value_byte_length: %d\nid_value_sha256: %s\nid_value_utf8: %s\n",
		receipt.Root.Account, receipt.Root.PublicKey, receipt.Root.SealPublicKey, receipt.Root.SealScript, receipt.IDValueByteLength, receipt.IDValueSHA256, receipt.IDValueUTF8)
	return recoveryPublicReceipt(out, receipt, text)
}
