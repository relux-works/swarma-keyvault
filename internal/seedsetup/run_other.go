//go:build !darwin

package seedsetup

import "io"

func Run(_ []string, _ Release, _, diag io.Writer) int {
	_ = writePublic(diag, "keyvault-seed: this operation requires macOS\n")
	return 1
}
