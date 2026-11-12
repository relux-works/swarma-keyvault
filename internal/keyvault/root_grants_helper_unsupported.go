//go:build !darwin || !cgo

package keyvault

import "context"

func invokeRootGrantsHelper(context.Context, []byte) (*rootGrantsHelperResult, error) {
	return nil, recoveryRefuse("operation_unavailable")
}
