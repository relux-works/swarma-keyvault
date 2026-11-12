//go:build (darwin || linux) && keyvault_abi_tests

package namecoinjournal

// ReserveInitializationABIFixture changes only the public storage home for
// cross-package ABI tests. It uses the actual kernel gate and create-only
// storage implementation. Normal product builds omit this entire file.
func ReserveInitializationABIFixture(home string, sidecar Sidecar) (*InitializationReservation, error) {
	return reserveInitializationAt(home, sidecar)
}
