//go:build !darwin || !cgo

package keyvault

import "context"

func recoveryNativeProcess2Pair(context.Context, string, [32]byte) ([]byte, []byte, error) {
	return nil, nil, errUnsupported
}
