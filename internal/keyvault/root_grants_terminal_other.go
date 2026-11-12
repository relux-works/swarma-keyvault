//go:build !darwin

package keyvault

import "context"

// Custody input is admitted only in the qualified Mac helper. Portable pure
// grammar tests do not enable a file/stdin/reader fallback on another platform.
func readRootGrantsTTY(context.Context) ([]byte, error) {
	return nil, recoveryRefuse("terminal_required")
}
