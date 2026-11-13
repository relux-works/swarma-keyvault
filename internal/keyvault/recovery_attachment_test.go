package keyvault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// recoveryAttachedStore adds the attachment inventory to the recovery fake. The
// plain fake has none, which is the unchanged pre-attachment behavior.
type recoveryAttachedStore struct {
	*recoveryFakeStore
	answer func(call int) (bool, error)
	calls  int
}

func (s *recoveryAttachedStore) RootGrantsAttached(RecoveryRecord) (bool, error) {
	s.calls++
	return s.answer(s.calls)
}

func recoveryAttachmentCode(t *testing.T, err error, want string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != want {
		t.Fatalf("wanted %s, got %v", want, err)
	}
}

// Claim: deleting a pair is refused with the definite attachment_exists code when
// a root item references it, BEFORE the owner prompt and any lock effect, and the
// pair, its ciphertext and the root are untouched. An unattached pair still
// deletes exactly as before (positive control), so refusing everything fails.
// Also: an inventory that cannot be read, or an attachment that appears between
// the prompt and the lock, refuses too. Limit: fake store; no real Keychain.
func TestRecoveryDeleteRefusesAttachedPair(t *testing.T) {
	for _, c := range []struct {
		name       string
		answer     func(int) (bool, error)
		wantCode   string
		wantPrompt int
		wantLock   bool // lock prerequisites created
	}{
		{"unattached-deletes", func(int) (bool, error) { return false, nil }, "", 1, true},
		{"attached-refuses-before-prompt", func(int) (bool, error) { return true, nil }, "attachment_exists", 0, false},
		{"unreadable-inventory-refuses-before-prompt", func(int) (bool, error) { return false, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL") }, "recovery_inventory_changed", 0, false},
		{"unadmitted-executable-refuses-before-prompt", func(int) (bool, error) { return false, recoveryRefuse("code_not_admitted") }, "recovery_code_not_admitted", 0, false},
		{"appears-after-prompt-refuses-under-lock", func(call int) (bool, error) { return call > 1, nil }, "attachment_exists", 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, f, _ := recoveryTestManager(t)
			r, err := m.Create(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 1, NostrVersion: 2, NamecoinVersion: 3}, &recoveryFakeTerminal{}, false)
			if err != nil {
				t.Fatal(err)
			}
			store := &recoveryAttachedStore{recoveryFakeStore: f, answer: c.answer}
			m.backend = store
			parent := filepath.Join(t.TempDir(), "absent")
			m.lock = FileLock{Path: filepath.Join(parent, "lock")}
			term := &recoveryDeleteTerminal{}
			got, err := m.Delete(RecoveryDeleteRequest{NostrIdentity: "north", Version: 1, ExpectedGroupID: r.GroupID}, term)
			_, statErr := os.Stat(parent)
			created := !os.IsNotExist(statErr)
			if term.identityConfirmation != c.wantPrompt || created != c.wantLock {
				t.Fatalf("prompt=%d lockPrerequisites=%v", term.identityConfirmation, created)
			}
			if c.wantCode == "" {
				if err != nil || got.GroupID != r.GroupID || f.deletes != 1 || len(f.groups) != 0 {
					t.Fatalf("unattached pair was not deleted: %v", err)
				}
				return
			}
			recoveryAttachmentCode(t, err, c.wantCode)
			if f.deletes != 0 || len(f.groups) != 1 || len(f.data) != 1 {
				t.Fatal("refusal deleted or lost the pair")
			}
		})
	}
}

// Claim: a backend without an attachment inventory (the pre-existing fakes) keeps
// the old behavior, and the production store implements the inventory, so the
// refusal cannot be skipped by the real binary. Limit: a type check, not a native run.
func TestRecoveryDeleteAttachmentInventoryIsImplementedByProductionStore(t *testing.T) {
	var backend RecoveryBackend = NewNostrSecurityStore()
	if _, ok := backend.(RootGrantsAttachmentInventory); !ok {
		t.Fatal("the production recovery backend does not expose the attachment inventory")
	}
	m, f, _ := recoveryTestManager(t)
	r, err := m.Create(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 1, NostrVersion: 2, NamecoinVersion: 3}, &recoveryFakeTerminal{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Delete(RecoveryDeleteRequest{NostrIdentity: "north", Version: 1, ExpectedGroupID: r.GroupID}, &recoveryDeleteTerminal{}); err != nil || f.deletes != 1 {
		t.Fatalf("plain backend delete changed: %v", err)
	}
}
