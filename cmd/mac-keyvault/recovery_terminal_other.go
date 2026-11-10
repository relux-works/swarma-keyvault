//go:build !darwin && !linux

package main

import "errors"

type ownerRecoveryTerminal interface {
	ConfirmMnemonic([][]byte) error
	ReadMnemonic() ([]byte, error)
	Close() error
}

var newRecoveryTerminal = func() (ownerRecoveryTerminal, error) {
	return nil, errors.New("owner terminal unavailable on this platform")
}
