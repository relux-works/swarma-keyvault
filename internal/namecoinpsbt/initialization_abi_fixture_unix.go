//go:build (darwin || linux) && keyvault_abi_tests

package namecoinpsbt

import "github.com/relux-works/swarma-keyvault/internal/namecoinjournal"

// OpenInitializationABIFixture keeps the real validation, kernel gate, private
// account checks and create-only journal lifecycle while selecting a disposable
// public home for cross-package ABI tests. Normal product builds omit this file;
// no environment, caller path or test-home selector enters production custody.
func OpenInitializationABIFixture(c NativeSelection, pin []byte, home string) (*InitializationSession, error) {
	account, err := initializationAccount(c, pin)
	if err != nil {
		return nil, err
	}
	held, err := namecoinjournal.ReserveInitializationABIFixture(home, c.Sidecar)
	if err != nil {
		return nil, err
	}
	return finishInitializationOpen(c, account, held)
}
