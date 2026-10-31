//go:build unix && !darwin

package keyvault

import "golang.org/x/sys/unix"

// publishNoReplace has no exclusive rename here: link, then unlink the
// temporary name. The Secure Enclave store is only served on darwin; an
// interruption between the two steps leaves a file the reader refuses.
func publishNoReplace(dir int, tmp, name string) error {
	if err := unix.Linkat(dir, tmp, dir, name, 0); err != nil {
		return err
	}
	return unix.Unlinkat(dir, tmp, 0)
}
