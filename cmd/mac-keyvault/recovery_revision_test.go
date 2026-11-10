package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"io"
	"strings"
	"testing"
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
	return keyvault.RecoveryRecord{Service: q.NostrIdentity, Version: q.Version, GroupID: q.ExpectedGroupID, Nostr: keyvault.RecoveryPurpose{Service: q.NostrIdentity, Purpose: "nostr", Version: 2}, Namecoin: keyvault.RecoveryPurpose{Service: q.NamecoinIdentity, Purpose: "namecoin", Version: 1}}, nil
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

// Successful mutation receipts require a complete write in JSON and text. A
// failed/short writer returns failure after exactly one effect, with no retry.
func TestRecoveryMutationReceiptWrite(t *testing.T) {
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath = oldB, oldM, oldT, oldL
	})
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { return recoveryReceiptTerminal{}, nil }
	lockPath = func() (string, error) { return t.TempDir() + "/lock", nil }
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
						args = append(args, "fixture", "--namecoin-identity", "fixture", "--version", "1", "--expected-group-id", strings.Repeat("1", 32))
					} else {
						args = append(args, "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
						if op == "restore" {
							args = append(args, "--expected-npub", "public", "--expected-namecoin-xpub", "public", "--expected-origin", "public")
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
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath = oldB, oldM, oldT, oldL
	})
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { return recoveryReceiptTerminal{}, nil }
	lockPath = func() (string, error) { return t.TempDir() + "/lock", nil }
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
					args = append(args, "fixture", "--namecoin-identity", "fixture", "--version", "1", "--expected-group-id", f.record.GroupID)
				} else {
					args = append(args, "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
					if op == "restore" {
						args = append(args, "--expected-npub", "public", "--expected-namecoin-xpub", "public", "--expected-origin", "public")
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
