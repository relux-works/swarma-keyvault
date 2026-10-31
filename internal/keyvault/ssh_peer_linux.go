//go:build linux

package keyvault

import (
	"golang.org/x/sys/unix"
	"net"
)

func sshPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credentialErr = err
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
		if credential, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil && credential.Pid > 0 {
			pid = int(credential.Pid)
		}
	})
	return pid
}
