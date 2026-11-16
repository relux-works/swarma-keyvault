//go:build darwin && cgo

package keyvault

/*
#include <stdlib.h>
#include <string.h>
#include "security_darwin.h"
*/
import "C"

import (
	"context"
	"unsafe"
)

func recoveryNativeProcess2Pair(ctx context.Context, group string, metadataHash [32]byte) ([]byte, []byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, recoveryRefuse("auth_refused")
	}
	account := C.CString(group)
	defer C.free(unsafe.Pointer(account))
	var record, pair *C.uchar
	var recordLength, pairLength C.size_t
	status := C.MacKeyVaultRecoveryReadSelected(account, (*C.uchar)(unsafe.Pointer(&metadataHash[0])), &record, &recordLength, &pair, &pairLength)
	if record != nil {
		defer C.free(unsafe.Pointer(record))
	}
	if pair != nil {
		defer func() {
			C.memset_s(unsafe.Pointer(pair), pairLength, 0, pairLength)
			C.free(unsafe.Pointer(pair))
		}()
	}
	if status != 0 || record == nil || pair == nil || recordLength < 1 || recordLength > recoveryMaxMetadata || pairLength < 1 || pairLength > recoveryMaxCiphertext {
		return nil, nil, recoveryRefuse("account_mismatch")
	}
	if ctx.Err() != nil {
		return nil, nil, recoveryRefuse("auth_refused")
	}
	return C.GoBytes(unsafe.Pointer(record), C.int(recordLength)), C.GoBytes(unsafe.Pointer(pair), C.int(pairLength)), nil
}
