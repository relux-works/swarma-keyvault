package kekclient

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
)

// ErrSocketPathTooLong identifies an options preflight failure: the generated
// pathname would exceed the macOS broker's 103-byte Unix-socket limit.
var ErrSocketPathTooLong = errors.New("mac-keyvault-kek socket path exceeds the 103-byte limit")

const maxSocketPathBytes = 103

// Preflight checks options against the macOS broker's path and private-directory
// contract. It reads metadata only: no random nonce, file, socket, child process
// or Keychain operation. Call it before changing provisioning state.
// This is a metadata observation, not a filesystem lock or caller admission;
// Unwrap and Rebind repeat it immediately before preparing their broker exchange.
func Preflight(opts Options) error {
	if !filepath.IsAbs(opts.Broker) {
		return fmt.Errorf("broker path %q is not absolute", opts.Broker)
	}
	if err := checkSocketDir(opts.SocketDir); err != nil {
		return err
	}
	if len(socketPath(opts.SocketDir, [8]byte{})) > maxSocketPathBytes {
		return ErrSocketPathTooLong
	}
	return nil
}

// One formatter keeps the preflight budget and actual nonce framing identical.
func socketPath(dir string, nonce [8]byte) string {
	return filepath.Join(dir, "kek-"+hex.EncodeToString(nonce[:])+".sock")
}
