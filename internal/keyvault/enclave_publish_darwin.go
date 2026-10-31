//go:build darwin

package keyvault

import "golang.org/x/sys/unix"

// publishNoReplace renames tmp to name in dir atomically and fails with
// EEXIST if name exists, so a published key file always has one link and an
// interruption leaves either the old state or the finished file.
func publishNoReplace(dir int, tmp, name string) error {
	return unix.RenameatxNp(dir, tmp, dir, name, unix.RENAME_EXCL)
}
