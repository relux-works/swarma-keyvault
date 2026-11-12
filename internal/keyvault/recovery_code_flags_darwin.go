//go:build darwin && cgo

package keyvault

/*
#include "security_darwin.h"
*/
import "C"

func recoveryCodeFlags(flags uint32) bool { return C.MacKeyVaultRecoveryCodeFlags(C.uint(flags)) == 1 }
