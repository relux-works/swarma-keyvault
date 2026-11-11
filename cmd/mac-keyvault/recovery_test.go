package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type recoveryCLIOperations struct{ calls []string }

func (f *recoveryCLIOperations) Create(keyvault.RecoveryRequest, keyvault.RecoveryTerminal, bool) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "create")
	return keyvault.RecoveryRecord{}, errors.New("fixture requires the real terminal control")
}
func (f *recoveryCLIOperations) Describe(service string, version int) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "public")
	return keyvault.RecoveryRecord{Service: service, Version: version}, nil
}
func (f *recoveryCLIOperations) Plan(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
	f.calls = append(f.calls, "plan")
	return keyvault.RecoveryPlan{}, nil
}
func (f *recoveryCLIOperations) Delete(q keyvault.RecoveryDeleteRequest, _ keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	f.calls = append(f.calls, "delete")
	return keyvault.RecoveryRecord{Service: q.NostrIdentity, Version: q.Version, GroupID: q.ExpectedGroupID}, nil
}

// Public lookup requires no terminal. Mutations refuse before constructing
// custody when the controlling owner terminal is unavailable; malformed input
// never reaches either route. PTY tests cover the actual terminal frontend.
func TestRecoveryCLIAdmissionBeforeCustody(t *testing.T) {
	oldBackend, oldManager, oldTerminal, oldLock := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, vaultLock = oldBackend, oldManager, oldTerminal, oldLock
	})
	constructed, opened, lockReads := 0, 0, 0
	operations := &recoveryCLIOperations{}
	newRecoveryBackend = func() keyvault.RecoveryBackend { constructed++; return nil }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return operations }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) {
		opened++
		return nil, errors.New("fixture has no controlling terminal")
	}
	vaultLock = func() (keyvault.FileLock, error) {
		lockReads++
		return keyvault.FileLock{Path: t.TempDir() + "/recovery.lock"}, nil
	}
	invoke := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"--json", "recovery"}, args...), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	for _, args := range [][]string{{"pub", "fixture", "--version", "1"}} {
		if code, _ := invoke(args...); code != 0 {
			t.Fatal("valid public operation refused")
		}
	}
	if constructed != 1 || opened != 0 || strings.Join(operations.calls, ",") != "public" {
		t.Fatal("public operation crossed its terminal/effect boundary")
	}
	const inputPlant = "synthetic-sensitive-input"
	for _, args := range [][]string{
		{}, {"export", inputPlant}, {"import", inputPlant}, {"seed", inputPlant},
		{"generate", "--service", "fixture", "--version", "1", "--nostr-version", "2"},
		{"generate", "--service", "fixture", "--version", "0", "--nostr-version", "2", "--namecoin-version", "1"},
		{"generate", "--service", "../foreign", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1"},
		{"generate", "--seed", inputPlant}, {"restore", "--stdin"}, {"restore", "--data-file", inputPlant},
		{"restore", "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1"},
		{"pub", "fixture"}, {"pub", "fixture", "--version", "1", "--format", "private"},
		{"pub", "fixture", "--version", "1", "--out", inputPlant},
		{"delete", "fixture", "--version", "1"}, {"delete", "fixture", "--expected-group-id", "public"},
		{"delete", "fixture", "--version", "1", "--namecoin-identity", "fixture", "--expected-group-id", strings.Repeat("1", 32)},
	} {
		beforeConstructed, beforeOpened, beforeCalls := constructed, opened, len(operations.calls)
		code, raw := invoke(args...)
		if code != 2 || !strings.Contains(raw, `"ok": false`) || constructed != beforeConstructed || opened != beforeOpened || len(operations.calls) != beforeCalls {
			t.Fatal("forbidden argument reached custody/terminal or returned the wrong refusal")
		}
		if strings.Contains(raw, inputPlant) {
			t.Fatal("rejected input echoed to public output")
		}
	}
	before := constructed
	code, raw := invoke("generate", "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
	if code != 2 || !strings.Contains(raw, "owner foreground controlling terminal unavailable") || constructed != before || opened != 1 {
		t.Fatal("missing terminal reached custody or refused for an unrelated reason")
	}

	// Replace each pin independently so the refusal is attributable to that
	// public input. The untouched tuple reaches the existing terminal gate.
	args := []string{"restore", "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1"}
	args = append(args, recoveryPublicFixturePins(t)...)
	for _, index := range []int{10, 12, 14} {
		malformed := append([]string(nil), args...)
		malformed[index] = inputPlant
		beforeLock, beforeTTY := lockReads, opened
		if code, raw := invoke(malformed...); code != 2 || !strings.Contains(raw, "canonical retained public recovery pins") ||
			strings.Contains(raw, inputPlant) || constructed != before || lockReads != beforeLock || opened != beforeTTY {
			t.Fatal("malformed pin crossed admission or was disclosed")
		}
	}
	if code, raw := invoke(args...); code != 2 || !strings.Contains(raw, "owner foreground controlling terminal unavailable") ||
		constructed != before || opened != 2 {
		t.Fatal("canonical pins did not reach the terminal gate")
	}
}

func recoveryPublicFixturePins(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../internal/seedsetup/testdata/public-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		NPub   string `json:"npub"`
		XPub   string `json:"namecoin_xpub"`
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatal(err)
	}
	return []string{"--expected-npub", pins.NPub, "--expected-namecoin-xpub", pins.XPub, "--expected-origin", pins.Origin}
}

// A correctly addressed deletion still refuses before backend construction if
// the owner cannot confirm both identities on a controlling terminal.
func TestRecoveryDeleteRequiresOwnerTerminal(t *testing.T) {
	oldB, oldT, oldL := newRecoveryBackend, newRecoveryTerminal, vaultLock
	t.Cleanup(func() { newRecoveryBackend, newRecoveryTerminal, vaultLock = oldB, oldT, oldL })
	constructed, opened := 0, 0
	newRecoveryBackend = func() keyvault.RecoveryBackend { constructed++; return nil }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { opened++; return nil, errors.New("no terminal") }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	var out, diagnostic bytes.Buffer
	code := run([]string{"recovery", "delete", "north", "--version", "1", "--expected-group-id", strings.Repeat("1", 32)}, &out, &diagnostic)
	if code != 2 || constructed != 0 || opened != 1 || !strings.Contains(diagnostic.String(), "controlling terminal unavailable") {
		t.Fatal("deletion bypassed owner terminal admission")
	}
}
