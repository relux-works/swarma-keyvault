//go:build darwin || linux

package keyvault

import (
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// LoadRootGrantsAuthority uses the OS account database, not HOME or a request
// path, to select independently installed authority. It never enrolls/writes.
func LoadRootGrantsAuthority(address RootGrantsAddress) ([]byte, error) {
	if _, err := address.Account(); err != nil {
		return nil, recoveryRefuse("invalid_arguments")
	}
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		return nil, recoveryRefuse("operation_unavailable")
	}
	path := filepath.Join(account.HomeDir, "Library", "Application Support", "works.relux.mac-keyvault", "root-grants-authority",
		address.Service+"@"+strconv.Itoa(address.Version)+".json")
	return rootGrantsLoadAuthorityFile(path, address)
}

// Private path seam for isolated public-file tests; production has one fixed
// account/address-derived path. O_NONBLOCK prevents a FIFO from blocking before
// fstat can reject it; O_NOFOLLOW rejects the final symlink at the actual open.
func rootGrantsLoadAuthorityFile(path string, address RootGrantsAddress) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, recoveryRefuse("operation_unavailable") }
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	f := os.NewFile(uintptr(fd), "root-grants-authority")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 1 || info.Size() > 32768 {
		return fail()
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(raw) != int(info.Size()) {
		return fail()
	}
	after, err := f.Stat()
	var current unix.Stat_t
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.Mode() != info.Mode() ||
		!after.ModTime().Equal(info.ModTime()) || unix.Fstat(fd, &current) != nil || current.Uid != stat.Uid {
		return nil, recoveryRefuse("review_changed")
	}
	p, err := ParseRootGrantsAuthority(raw)
	if err != nil {
		return nil, err
	}
	if p.Record.Service != address.Service || p.Record.Version != address.Version {
		return nil, recoveryRefuse("authority_mismatch")
	}
	return raw, nil
}
