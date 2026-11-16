//go:build darwin

package namecoinprocess

import "errors"

func setProcess2PipeCapacity(uintptr, int) error {
	return errors.New("custody pipe resizing is unavailable on darwin")
}
