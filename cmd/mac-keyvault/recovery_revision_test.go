package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type recoveryReceiptOperations struct {
	recoveryCLIOperations
	effects int
}

func (f *recoveryReceiptOperations) Create(q keyvault.RecoveryRequest, _ keyvault.RecoveryTerminal, _ bool) (keyvault.RecoveryRecord, error) {
	f.effects++
	return keyvault.RecoveryRecord{Service: q.Service, Version: q.Version, GroupID: strings.Repeat("1", 32)}, nil
}
func (f *recoveryReceiptOperations) Delete(q keyvault.RecoveryDeleteRequest, _ keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	f.effects++
	return keyvault.RecoveryRecord{Service: q.NostrIdentity, Version: q.Version, GroupID: q.ExpectedGroupID, Nostr: keyvault.RecoveryPurpose{Service: q.NostrIdentity, Purpose: "nostr", Version: 2}, Namecoin: keyvault.RecoveryPurpose{Service: q.NostrIdentity, Purpose: "namecoin", Version: 1}}, nil
}

type recoveryReceiptTerminal struct{}

func (recoveryReceiptTerminal) ConfirmIdentities(keyvault.RecoveryPlan) error { return nil }

func (recoveryReceiptTerminal) ConfirmMnemonic([][]byte) error { return nil }
func (recoveryReceiptTerminal) ReadMnemonic() ([]byte, error)  { return nil, nil }
func (recoveryReceiptTerminal) Close() error                   { return nil }

type recoveryFailedWriter struct{ short bool }

func (w recoveryFailedWriter) Write(b []byte) (int, error) {
	if w.short {
		return len(b) - 1, nil
	}
	return 0, errors.New("synthetic writer detail must not escape")
}

// Public plan and lookup report success only after an entire public receipt
// is written. Lock setup failures never disclose the raw cause.
func TestRecoveryPublicReceipts(t *testing.T) {
	oldB, oldM, oldL := newRecoveryBackend, makeRecoveryManager, vaultLock
	t.Cleanup(func() { newRecoveryBackend, makeRecoveryManager, vaultLock = oldB, oldM, oldL })
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	operations := &recoveryCLIOperations{}
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return operations }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	for _, args := range [][]string{
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south"},
		{"pub", "north", "--version", "1"},
	} {
		for _, jsonMode := range []bool{false, true} {
			argv := append([]string{"recovery"}, args...)
			if jsonMode {
				argv = append([]string{"--json"}, argv...)
			}
			var good, diagnostic bytes.Buffer
			if code := run(argv, &good, &diagnostic); code != 0 || good.Len() == 0 || diagnostic.Len() != 0 {
				t.Fatal("valid public receipt failed", code)
			}
			for _, writer := range []io.Writer{recoveryFailedWriter{}, recoveryFailedWriter{short: true}} {
				diagnostic.Reset()
				if code := run(argv, writer, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), "recovery_public_output_unavailable") {
					t.Fatal("failed public receipt reported success", code)
				}
			}
		}
	}
	const rawCause = "private-lock-path-probe"
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{}, errors.New(rawCause) }
	var out, diagnostic bytes.Buffer
	code := run([]string{"--json", "recovery", "pub", "north", "--version", "1"}, &out, &diagnostic)
	if code != 3 || !strings.Contains(out.String(), "recovery_lock_unavailable") ||
		strings.Contains(out.String()+diagnostic.String(), rawCause) || len(operations.calls) != 12 {
		t.Fatal("lock setup failure was disclosed or reached the backend", code, len(operations.calls))
	}
}

// Successful mutation receipts require a complete write in JSON and text. A
// failed/short writer returns failure after exactly one effect, with no retry.
func TestRecoveryMutationReceiptWrite(t *testing.T) {
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock = oldB, oldM, oldT, oldL
	})
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { return recoveryReceiptTerminal{}, nil }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	for _, jsonMode := range []bool{false, true} {
		for _, op := range []string{"generate", "restore", "delete"} {
			for _, mode := range []string{"ok", "error", "short"} {
				t.Run(op+"/"+map[bool]string{true: "json", false: "text"}[jsonMode]+"/"+mode, func(t *testing.T) {
					f := &recoveryReceiptOperations{}
					makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return f }
					args := []string{"recovery", op}
					if jsonMode {
						args = append([]string{"--json"}, args...)
					}
					if op == "delete" {
						args = append(args, "fixture", "--version", "1", "--expected-group-id", strings.Repeat("1", 32))
					} else {
						args = append(args, "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
						if op == "restore" {
							args = append(args, recoveryPublicFixturePins(t)...)
						}
					}
					var good, diagnostic bytes.Buffer
					var w io.Writer = &good
					if mode != "ok" {
						w = recoveryFailedWriter{short: mode == "short"}
					}
					code := run(args, w, &diagnostic)
					if f.effects != 1 {
						t.Fatal("mutation repeated or skipped")
					}
					if mode == "ok" {
						if code != 0 || good.Len() == 0 || diagnostic.Len() != 0 {
							t.Fatal("valid receipt refused")
						}
						return
					}
					if code != 1 || !strings.Contains(diagnostic.String(), "reconcile") || !strings.Contains(diagnostic.String(), "do not retry or delete") || strings.Contains(diagnostic.String(), "synthetic writer") {
						t.Fatalf("receipt loss silently succeeded or unsafe diagnostic: code=%d diagnostic=%q", code, diagnostic.String())
					}
				})
			}
		}
	}
}

type recoveryUnknownOperations struct {
	recoveryCLIOperations
	effects int
	record  keyvault.RecoveryRecord
}

func (f *recoveryUnknownOperations) Create(q keyvault.RecoveryRequest, _ keyvault.RecoveryTerminal, restore bool) (keyvault.RecoveryRecord, error) {
	f.effects++
	op := "generate"
	if restore {
		op = "restore"
	}
	return f.record, &keyvault.RecoveryOutcomeUnknown{Outcome: "unknown", Operation: op, Reference: f.record}
}
func (f *recoveryUnknownOperations) Describe(string, int) (keyvault.RecoveryRecord, error) {
	return keyvault.RecoveryRecord{}, errors.New("unexpected read")
}
func (f *recoveryUnknownOperations) Delete(keyvault.RecoveryDeleteRequest, keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	f.effects++
	return f.record, &keyvault.RecoveryOutcomeUnknown{Outcome: "unknown", Operation: "delete", Reference: f.record}
}

// Unknown effects use the one explicit result+error class, retain the public
// reference and exit1 in both formats. Failed delivery never repeats a mutation.
func TestRecoveryUnknownMutationReceipt(t *testing.T) {
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock = oldB, oldM, oldT, oldL
	})
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { return recoveryReceiptTerminal{}, nil }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	for _, jsonMode := range []bool{false, true} {
		for _, op := range []string{"generate", "restore", "delete"} {
			for _, failed := range []bool{false, true} {
				f := &recoveryUnknownOperations{record: keyvault.RecoveryRecord{Service: "fixture", Version: 1, GroupID: strings.Repeat("1", 32)}}
				makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return f }
				args := []string{"recovery", op}
				if jsonMode {
					args = append([]string{"--json"}, args...)
				}
				if op == "delete" {
					args = append(args, "fixture", "--version", "1", "--expected-group-id", f.record.GroupID)
				} else {
					args = append(args, "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
					if op == "restore" {
						args = append(args, recoveryPublicFixturePins(t)...)
					}
				}
				var stdout, stderr bytes.Buffer
				var w io.Writer = &stdout
				if failed {
					w = recoveryFailedWriter{}
				}
				if code := run(args, w, &stderr); code != 1 || f.effects != 1 {
					t.Fatal("unknown result succeeded or repeated effect")
				}
				raw := stdout.String() + stderr.String()
				if !strings.Contains(raw, "UNCONFIRMED") || !strings.Contains(raw, "do not retry or delete") || !strings.Contains(raw, f.record.GroupID) {
					t.Fatal("unknown reference/guidance missing")
				}
				if jsonMode && !failed {
					var reply struct {
						OK     bool                            `json:"ok"`
						Error  *responseError                  `json:"error"`
						Result keyvault.RecoveryOutcomeUnknown `json:"result"`
					}
					if json.Unmarshal(stdout.Bytes(), &reply) != nil || reply.OK || reply.Error == nil || reply.Error.Code != keyvault.RecoveryOutcomeUnknownCode || reply.Result.Operation != op || reply.Result.Outcome != "unknown" || reply.Result.Reference.GroupID != f.record.GroupID {
						t.Fatal("unknown wire contract differs")
					}
				}
			}
		}
	}
}

// No-effect refusal receipts preserve each code on complete JSON/text writes.
// Broken/short sinks return delivery failure and never reach a mutation.
func TestRecoveryRefusalReceiptWrite(t *testing.T) {
	for _, code := range []string{"recovery_duplicate", "recovery_generation_exhausted", "recovery_identity_confirmation_refused"} {
		for _, jsonMode := range []bool{false, true} {
			var delivered, diagnostic bytes.Buffer
			out := output{json: jsonMode, command: "recovery plan", stdout: &delivered, stderr: &diagnostic}
			refusal := &keyvault.Refusal{Code: code, Message: "Recovery operation refused", Hint: "check public inputs"}
			if got := recoveryFailureReceipt(out, refusal); got != 3 {
				t.Fatal("valid refusal delivery changed classification", got)
			}
			receipt := diagnostic.String()
			if jsonMode {
				receipt = delivered.String()
			}
			if !strings.Contains(receipt, code) {
				t.Fatal("refusal code lost")
			}
			for _, short := range []bool{false, true} {
				diagnostic.Reset()
				if jsonMode {
					out.stdout = recoveryFailedWriter{short: short}
				} else {
					out.stderr = recoveryFailedWriter{short: short}
				}
				if got := recoveryFailureReceipt(out, refusal); got != 1 {
					t.Fatal("broken refusal delivery preserved ordinary code", got)
				}
				if jsonMode && (!strings.Contains(diagnostic.String(), "refusal="+code) || strings.Contains(diagnostic.String(), "synthetic writer")) {
					t.Fatal("lost bounded classification", diagnostic.String())
				}
			}
		}
	}
}
