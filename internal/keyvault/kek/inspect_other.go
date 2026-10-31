//go:build !darwin || !cgo

package kek

import (
	"errors"
	"net"
)

var errNoCodeSigning = errors.New("code identity needs macOS with cgo")

// CodeInspector refuses off macOS: there is no code identity to check.
type CodeInspector struct{}

func (CodeInspector) Peer(*net.UnixConn) (CodeIdentity, error) {
	return CodeIdentity{}, errNoCodeSigning
}

func (CodeInspector) File(string) (CodeIdentity, error) { return CodeIdentity{}, errNoCodeSigning }
