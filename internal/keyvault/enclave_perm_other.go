//go:build !unix

package keyvault

import (
	"errors"
	"os"
)

var errEnclaveUnsupported = errors.New("the Secure Enclave store requires a unix host")

func openEnclaveDir(string) (*os.File, error) { return nil, errEnclaveUnsupported }

func readEnclaveFileAt(*os.File, string, int) ([]byte, error) { return nil, errEnclaveUnsupported }

func writeEnclaveFileAt(*os.File, string, []byte, bool) error { return errEnclaveUnsupported }

func removeEnclaveFileAt(*os.File, string) error { return errEnclaveUnsupported }

func enclaveFileExistsAt(*os.File, string) (bool, error) { return false, errEnclaveUnsupported }

func requireOwnedFile(string) error { return errEnclaveUnsupported }
