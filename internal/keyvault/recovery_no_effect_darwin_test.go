//go:build darwin && cgo

package keyvault

import (
	"errors"
	"testing"
)

type recoveryCodeRefusedStore struct{ *recoveryFakeStore }

func (s *recoveryCodeRefusedStore) RecoveryStore(r RecoveryRecord, b []byte) error {
	return NewNostrSecurityStore().RecoveryStore(r, b)
}

// The actual test executable must fail the native hardened-code prerequisite
// before this fixture calls the add bridge. The bridge repeats that same gate
// before any Keychain query; run this control in the confined lane. All other
// manager dependencies are software/public fakes, so no hardware is contacted.
func TestRecoveryNativePreQueryNoEffect(t *testing.T) {
	gate := verifyRecoveryCode(0, nil)
	var refused *Refusal
	if !errors.As(gate, &refused) || refused.Status != -25293 {
		t.Fatal("code-refusal prerequisite absent; native bridge not called")
	}
	m, f, _ := recoveryTestManager(t)
	m.backend = &recoveryCodeRefusedStore{f}
	r, err := m.Create(recoveryTestRequest(), &recoveryFakeTerminal{}, false)
	var unknown *RecoveryOutcomeUnknown
	var noEffect *RecoveryNotAppliedError
	c := ClassifyError(err)
	if errors.As(err, &unknown) || !errors.As(err, &noEffect) || c.Code != CodeSecurity || c.Status != -25293 || r.GroupID != "" || f.stores != 0 || f.deletes != 0 || len(f.groups) != 0 {
		t.Fatalf("pre-query refusal became uncertain: code=%s status=%d reference=%v", c.Code, c.Status, r.GroupID != "")
	}
}
