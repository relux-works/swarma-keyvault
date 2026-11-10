package main

import (
	"bytes"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type identityCLIProbe struct {
	recoveryCLIOperations
	requests []keyvault.RecoveryRequest
}

func (f *identityCLIProbe) Create(q keyvault.RecoveryRequest, _ keyvault.RecoveryTerminal, _ bool) (keyvault.RecoveryRecord, error) {
	f.requests = append(f.requests, q)
	return keyvault.RecoveryRecord{Service: q.NostrIdentity, Version: q.Version, Nostr: keyvault.RecoveryPurpose{Service: q.NostrIdentity, Purpose: "nostr", Version: q.NostrVersion}, Namecoin: keyvault.RecoveryPurpose{Service: q.NamecoinIdentity, Purpose: "namecoin", Version: q.NamecoinVersion}}, nil
}

func (f *identityCLIProbe) Plan(q keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
	f.requests = append(f.requests, q)
	return keyvault.RecoveryPlan{Schema: "keyvault-recovery-plan/1", NostrIdentity: q.NostrIdentity, NamecoinIdentity: q.NamecoinIdentity}, nil
}

// Both explicit identity flags reach the typed request unchanged. Missing,
// mixed, duplicate and malformed identities must stop before factory/TTY use.
func TestRecoveryIdentityCLIFlags(t *testing.T) {
	oldB, oldM, oldT, oldL := newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath
	t.Cleanup(func() {
		newRecoveryBackend, makeRecoveryManager, newRecoveryTerminal, lockPath = oldB, oldM, oldT, oldL
	})
	f := &identityCLIProbe{}
	constructed, opened := 0, 0
	newRecoveryBackend = func() keyvault.RecoveryBackend { constructed++; return nil }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return f }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { opened++; return recoveryReceiptTerminal{}, nil }
	lockPath = func() (string, error) { return t.TempDir() + "/lock", nil }
	invoke := func(args ...string) int {
		var out, diagnostic bytes.Buffer
		return run(append([]string{"--json", "recovery"}, args...), &out, &diagnostic)
	}
	common := []string{"--version", "1", "--nostr-version", "2", "--namecoin-version", "3"}
	args := append([]string{"generate", "--nostr-identity", "north", "--namecoin-identity", "south"}, common...)
	if code := invoke(args...); code != 0 || len(f.requests) != 1 || f.requests[0].NostrIdentity != "north" || f.requests[0].NamecoinIdentity != "south" || f.requests[0].Service != "" {
		t.Fatalf("dual flags not propagated: code%d", code)
	}
	for _, bad := range [][]string{
		{"generate", "--nostr-identity", "north"},
		{"generate", "--namecoin-identity", "south"},
		{"generate", "--nostr-identity", "north", "--namecoin-identity", "bad/name"},
		{"generate", "--nostr-identity", "north", "--namecoin-identity", "south", "--service", "legacy"},
		{"generate", "--nostr-identity", "north", "--nostr-identity", "other", "--namecoin-identity", "south"},
	} {
		beforeC, beforeO, beforeR := constructed, opened, len(f.requests)
		if code := invoke(append(bad, common...)...); code != 2 || constructed != beforeC || opened != beforeO || len(f.requests) != beforeR {
			t.Fatal("invalid identity flags reached custody/TTY")
		}
	}
	// Planning is read-only and permits omitted generations. It must not open
	// the owner terminal. An explicitly supplied zero is invalid.
	beforeO := opened
	if code := invoke("plan", "--nostr-identity", "north", "--namecoin-identity", "south"); code != 0 || opened != beforeO || len(f.requests) != 2 || f.requests[1].Version != 0 {
		t.Fatal("planning required owner presence or invented a generation")
	}
	for _, bad := range [][]string{
		{"plan", "--nostr-identity", "north"},
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south", "--version", "-1"},
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south", "--version", "0"},
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south", "--nostr-version", "0"},
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south", "--namecoin-version", "01"},
		{"plan", "--nostr-identity", "north", "--namecoin-identity", "south", "--version", "1", "--version", "2"},
		{"plan", "--service", "", "--nostr-identity", "north", "--namecoin-identity", "south"},
	} {
		beforeC, beforeO, beforeR := constructed, opened, len(f.requests)
		if code := invoke(bad...); code != 2 || constructed != beforeC || opened != beforeO || len(f.requests) != beforeR {
			t.Fatal("invalid plan reached custody/TTY")
		}
	}
}
