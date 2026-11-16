//go:build linux

package namecoinprocess

import "golang.org/x/sys/unix"

func setProcess2PipeCapacity(fd uintptr, size int) error {
	_, err := unix.FcntlInt(fd, unix.F_SETPIPE_SZ, size)
	return err
}
