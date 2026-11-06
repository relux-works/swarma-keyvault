//go:build !darwin && !linux

package ownerdocument

import "os"

func openRegular(string) (*os.File, error) { return nil, ErrNativeUnavailable }
