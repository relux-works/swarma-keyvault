//go:build darwin && cgo

package keyvault

import (
	"os"
	"path/filepath"
	"testing"
)

// recoveryRealInventoryStore keeps the pair data in the fake and takes the
// attachment inventory from the REAL production store.
type recoveryRealInventoryStore struct {
	*recoveryFakeStore
	real *NostrSecurityStore
}

func (s *recoveryRealInventoryStore) RootGrantsAttached(r RecoveryRecord) (bool, error) {
	return s.real.RootGrantsAttached(r)
}

// Claim: through the real production store, an executable that is not the admitted
// vault identity (this unsigned test executable) makes recovery delete refuse with
// exactly recovery_code_not_admitted: before the owner prompt, before any lock
// effect, with the pair and its ciphertext untouched, and without a Keychain
// query (the native entry stops at the running-code check). The positive control is
// the fake-backend test TestRecoveryDeleteRefusesAttachedPair: an unattached pair
// deletes. Limit: shows the fail-closed behavior for the unadmitted executable;
// it does not show that the admitted vault reads the inventory.
func TestRecoveryDeleteRefusesUnadmittedExecutableThroughRealStore(t *testing.T) {
	direct := NewNostrSecurityStore()
	if attached, err := direct.RootGrantsAttached(RecoveryRecord{}); attached {
		t.Fatal("the unadmitted executable read an attachment")
	} else {
		recoveryAttachmentCode(t, err, "recovery_code_not_admitted")
	}
	m, f, _ := recoveryTestManager(t)
	r, err := m.Create(RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 1, NostrVersion: 2, NamecoinVersion: 3}, &recoveryFakeTerminal{}, false)
	if err != nil {
		t.Fatal(err)
	}
	m.backend = &recoveryRealInventoryStore{recoveryFakeStore: f, real: direct}
	parent := filepath.Join(t.TempDir(), "absent")
	m.lock = FileLock{Path: filepath.Join(parent, "lock")}
	term := &recoveryDeleteTerminal{}
	_, err = m.Delete(RecoveryDeleteRequest{NostrIdentity: "north", Version: 1, ExpectedGroupID: r.GroupID}, term)
	recoveryAttachmentCode(t, err, "recovery_code_not_admitted")
	if _, statErr := os.Stat(parent); !os.IsNotExist(statErr) || term.identityConfirmation != 0 || f.deletes != 0 || len(f.groups) != 1 || len(f.data) != 1 {
		t.Fatal("the refusal prompted, created lock prerequisites or changed the pair")
	}
}
