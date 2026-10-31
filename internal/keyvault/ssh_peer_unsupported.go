//go:build !darwin && !linux

package keyvault

import (
	"errors"
	"net"
)

func sshPeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("Unix peer credential verification unavailable")
}

func sshPeerPID(*net.UnixConn) int { return 0 }
