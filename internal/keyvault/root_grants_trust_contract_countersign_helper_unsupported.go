//go:build !darwin || !cgo

package keyvault

func newRootGrantsTrustContractCountersignHelper() RootGrantsTrustContractCountersignHelper {
	return unavailableRootGrantsTrustContractCountersignHelper{}
}
