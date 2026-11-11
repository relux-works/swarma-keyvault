package keyvault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func planRequest(p RecoveryPlan) RecoveryRequest {
	return RecoveryRequest{NostrIdentity: p.NostrIdentity, NamecoinIdentity: p.NamecoinIdentity, Version: p.Version, NostrVersion: p.NostrVersion, NamecoinVersion: p.NamecoinVersion}
}

// A first-user advisory inventory leaves even absent lock parents untouched.
// Mismatched identity confirmation also leaves them absent; the valid positive
// permits initialization and one locked fake pair write after confirmation.
func TestRecoveryPlanNoWrites(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	root := t.TempDir()
	parent := filepath.Join(root, "absent", "locks")
	m.lock = FileLock{Path: filepath.Join(parent, "init.lock"), BootstrapDir: root}
	p, err := m.Plan(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"})
	if err != nil || p.Group != "north/recovery@1" || p.NostrRecord != "north/nostr@1" || p.NamecoinRecord != "south/namecoin@1" || !p.Advisory {
		t.Fatal("valid first-user inventory refused", err)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatal("advisory plan created lock prerequisites")
	}
	term := &recoveryFakeTerminal{identityRefuse: true}
	_, err = m.Create(planRequest(p), term, false)
	recoveryCode(t, err, "identity_confirmation_failed")
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatal("mismatch created lock prerequisites")
	}
	if f.stores != 0 || h.calls != 0 || term.confirmation != 0 || term.read != 0 {
		t.Fatal("mismatch reached words/hardware/write")
	}
	term = &recoveryFakeTerminal{}
	r, err := m.Create(planRequest(p), term, false)
	if err != nil || f.stores != 1 || h.calls != 2 || term.identityConfirmation != 1 || len(term.plans) != 1 || term.plans[0] != p || r.PurposeAccount(r.Namecoin) != p.NamecoinRecord {
		t.Fatal("confirmed first-user positive failed", err)
	}
	if st, err := os.Stat(filepath.Join(parent, "init.lock")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("confirmed mutation failed to initialize lock")
	}
}

type planInventoryProbe struct {
	RecoveryBackend
	firstRead func()
}

func (p *planInventoryProbe) RecoveryList() ([]RecoveryRecord, error) {
	if p.firstRead != nil {
		probe := p.firstRead
		p.firstRead = nil
		probe()
	}
	return p.RecoveryBackend.RecoveryList()
}

// The first inventory read holds the same existing-directory lock that a
// first writer needs. The writer cannot create prerequisites mid-inventory.
func TestRecoveryPlanSerializesFirstWriter(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	root := t.TempDir()
	lock := FileLock{Path: filepath.Join(root, "absent", "init.lock"), BootstrapDir: root}
	m.lock = lock
	probed := false
	m.backend = &planInventoryProbe{RecoveryBackend: f, firstRead: func() {
		probed = true
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		release, err := lock.LockContext(ctx)
		if release != nil {
			release()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("first writer passed the advisory inventory lock", err)
		}
		if _, err := os.Lstat(filepath.Dir(lock.Path)); !os.IsNotExist(err) {
			t.Fatal("contending writer created lock prerequisites", err)
		}
	}}
	q := RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"}
	plan, err := m.Plan(q)
	if err != nil || !probed || plan.Version != 1 {
		t.Fatal("first-use inventory did not complete under lock", err)
	}
	if _, err := m.Create(planRequest(plan), &recoveryFakeTerminal{}, false); err != nil || f.stores != 1 {
		t.Fatal("writer was not admitted after the read completed", err)
	}
	m.lock = NoLock{}
	m.backend = &planInventoryProbe{RecoveryBackend: f, firstRead: func() { t.Fatal("unlocked plan read the inventory") }}
	_, err = m.Plan(q)
	recoveryCode(t, err, "lock_unavailable")
}

// Each family advances independently. A stale confirmed plan cannot reselect
// a version, expose words, create a wrap or overwrite the colliding record.
func TestRecoveryPlanGenerationsAndStaleRefusal(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	legacy, _ := recoveryIdentityLegacy(t)
	old := legacy.NostrRecord()
	old.Service, old.Version, old.Storage = "north", 7, "keychain-acl"
	unrelated := old
	unrelated.Service, unrelated.Version = "south", 20
	f.keys = []NostrRecord{old, unrelated}
	p, err := m.Plan(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"})
	if err != nil || p.Version != 1 || p.NostrVersion != 8 || p.NamecoinVersion != 1 {
		t.Fatal("family generations conflated", err)
	}
	collision := old
	collision.Service, collision.Purpose, collision.Version = "south", "namecoin", 1
	f.keys = append(f.keys, collision)
	term := &recoveryFakeTerminal{}
	_, err = m.Create(planRequest(p), term, false)
	recoveryCode(t, err, "duplicate")
	if f.stores != 0 || h.calls != 0 || term.confirmation != 0 || len(f.keys) != 3 {
		t.Fatal("stale plan selected a different write")
	}
	old.Version = 2147483647
	f.keys = []NostrRecord{old}
	_, err = m.Plan(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"})
	recoveryCode(t, err, "generation_exhausted")
	p, err = m.Plan(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", NostrVersion: 12})
	if err != nil || p.NostrVersion != 12 {
		t.Fatal("valid explicit generation refused", err)
	}
}

// An existing no-create lock is reusable, but unsafe mode or symlink cannot
// be silently repaired. Plan reads no private material and leaves bytes alone.
func TestRecoveryPlanExistingLockAdmission(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	p := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(p, []byte("public-lock-witness"), 0600); err != nil {
		t.Fatal(err)
	}
	m.lock = FileLock{Path: p}
	q := RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"}
	if _, err := m.Plan(q); err != nil {
		t.Fatal("existing lock positive refused", err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := m.Plan(q)
	recoveryCode(t, err, "lock_unavailable")
	b, _ := os.ReadFile(p)
	if string(b) != "public-lock-witness" {
		t.Fatal("plan changed lock contents")
	}
	link := p + "-link"
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	m.lock = FileLock{Path: link}
	_, err = m.Plan(q)
	recoveryCode(t, err, "lock_unavailable")
	if f.stores != 0 || h.calls != 0 {
		t.Fatal("lock refusal reached mutation")
	}
}

// The utility-facing concrete inventory exposes only two metadata methods.
// Mutation/private-read assertions refuse structurally, without invoking native
// code. This does not establish native Keychain or UI behavior.
func TestRecoveryInventoryCapabilityBoundary(t *testing.T) {
	inventory := NewRecoveryInventory()
	methods := reflect.TypeOf(inventory)
	if methods.NumMethod() != 2 || methods.Method(0).Name != "List" || methods.Method(1).Name != "RecoveryList" {
		t.Fatal("metadata capability widened")
	}
	if _, ok := inventory.(RecoveryBackend); ok {
		t.Fatal("mutation backend exposed")
	}
	if _, ok := inventory.(NostrBackend); ok {
		t.Fatal("private signer exposed")
	}
	planner := NewRecoveryPlanner(inventory, nil)
	if _, ok := any(planner).(interface {
		Create(RecoveryRequest, RecoveryTerminal, bool) (RecoveryRecord, error)
	}); ok {
		t.Fatal("planner exposes create")
	}
	_, err := planner.Plan(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south"})
	recoveryCode(t, err, "lock_unavailable")
}

func attributesOnlyQuery(source string) bool {
	start := strings.Index(source, "int MacKeyVaultNostrList(")
	if start < 0 {
		return false
	}
	end := strings.Index(source[start:], "\nint MacKeyVaultNostrRead(")
	if end < 0 {
		return false
	}
	body := source[start : start+end]
	return strings.Contains(body, "MacKeyVaultNostrQuery(&query, &keychain, 0)") &&
		strings.Contains(body, "kSecReturnAttributes, kCFBooleanTrue") &&
		!strings.Contains(body, "kSecReturnData") && !strings.Contains(body, "MacKeyVaultNostrRead(")
}

// This source-level guard binds the native inventory entry to attributes only.
// A planted data-return request must fail the guard. Live native qualification
// remains separate from this static check.
func TestRecoveryInventoryAttributesOnlySource(t *testing.T) {
	raw, err := os.ReadFile("security_darwin.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if !attributesOnlyQuery(source) {
		t.Fatal("metadata query no longer attributes-only")
	}
	start := strings.Index(source, "int MacKeyVaultNostrList(")
	plant := source[:start] + strings.Replace(source[start:], "kSecReturnAttributes, kCFBooleanTrue", "kSecReturnAttributes, kCFBooleanTrue); CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue", 1)
	if attributesOnlyQuery(plant) {
		t.Fatal("data-return plant escaped guard")
	}
}
