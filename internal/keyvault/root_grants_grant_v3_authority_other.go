//go:build !darwin && !linux

package keyvault

func LoadRootGrantsAuthority(RootGrantsAddress) ([]byte, error) {
	return nil, recoveryRefuse("operation_unavailable")
}
