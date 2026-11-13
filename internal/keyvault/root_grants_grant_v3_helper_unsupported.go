//go:build !darwin || !cgo

package keyvault

func newRootGrantsGrantV3SigningHelper() RootGrantsGrantV3SigningHelper {
	return unavailableRootGrantsGrantV3Helper{}
}
