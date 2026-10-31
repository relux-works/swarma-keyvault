//go:build darwin

package keyvault

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
)

// sshPeerUID obtains credentials from the kernel, not from client traffic or
// filesystem modes. Named/inherited macOS ACLs cannot bypass this check.
func sshPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		// macOS sys/ucred.h specifies XUCRED_VERSION as zero.
		if credential == nil || credential.Version != 0 {
			credentialErr = errors.New("unsupported Unix peer credential version")
			return
		}
		uid = credential.Uid
	})
	if err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return uid, nil
}

// sshPeerPID is the client pid for the audit only; 0 when unavailable.
func sshPeerPID(conn *net.UnixConn) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	raw.Control(func(fd uintptr) {
		if value, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil && value > 0 {
			pid = value
		}
	})
	return pid
}
