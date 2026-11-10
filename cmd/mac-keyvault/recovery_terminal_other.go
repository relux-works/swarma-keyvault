//go:build !darwin && !linux

package main

import (
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type ownerRecoveryTerminal interface {
	ConfirmIdentities(keyvault.RecoveryPlan) error
	ConfirmMnemonic([][]byte) error
	ReadMnemonic() ([]byte, error)
	Close() error
}

var newRecoveryTerminal = func() (ownerRecoveryTerminal, error) {
	return nil, errors.New("owner terminal unavailable on this platform")
}
