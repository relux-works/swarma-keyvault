//go:build darwin && cgo

package keyvault

/*
#include <stdlib.h>
#include "root_grants_store_darwin.h"
*/
import "C"

import "unsafe"

// rootGrantsDarwinNative binds the private native seam to the cgo store. Each C
// function re-verifies the running vault before any Keychain query; the Go
// Startup call only lets the adapter refuse earlier with a precise reason.
type rootGrantsDarwinNative struct{}

func newRootGrantsNative() rootGrantsNative { return rootGrantsDarwinNative{} }

// rootGrantsNativeNamespace exposes the C namespace literal so a test can pin its
// agreement with RootGrantsNamespace without touching the Keychain.
func rootGrantsNativeNamespace() string { return C.GoString(C.MacKeyVaultRootGrantsNamespace()) }

func (rootGrantsDarwinNative) Startup() error {
	if C.MacKeyVaultRootGrantsStartup() != 0 {
		return errRootGrantsNativeCode
	}
	return nil
}

func rootGrantsNativeRows(call func(**C.char, *C.size_t) C.int, op string) ([]byte, error) {
	var raw *C.char
	var length C.size_t
	status := int(call(&raw, &length))
	if raw != nil {
		defer C.free(unsafe.Pointer(raw))
	}
	if status != 0 {
		return nil, &StatusError{Op: op, Status: status}
	}
	if length > 4*1024*1024 || (length > 0 && raw == nil) {
		return nil, recoveryRefuse("invalid_record")
	}
	if length == 0 {
		return nil, nil
	}
	return C.GoBytes(unsafe.Pointer(raw), C.int(length)), nil
}

func (rootGrantsDarwinNative) PairRows() ([]byte, error) {
	return rootGrantsNativeRows(func(out **C.char, length *C.size_t) C.int { return C.MacKeyVaultRootGrantsPairList(out, length) }, "root grants pair inventory")
}

func (rootGrantsDarwinNative) RootRows() ([]byte, error) {
	return rootGrantsNativeRows(func(out **C.char, length *C.size_t) C.int { return C.MacKeyVaultRootGrantsList(out, length) }, "root grants inventory")
}

type rootGrantsDarwinAdd struct {
	plan  *C.MacKeyVaultRootGrantsAdd
	frame []byte
}

func (rootGrantsDarwinNative) PrepareAdd() (rootGrantsNativeAdd, error) {
	var plan *C.MacKeyVaultRootGrantsAdd
	var raw *C.uchar
	var length C.size_t
	status := int(C.MacKeyVaultRootGrantsAddPrepare(&plan, &raw, &length))
	if raw != nil {
		defer C.free(unsafe.Pointer(raw))
	}
	if status != 0 || plan == nil || raw == nil || length < 1 || length > 1048576 {
		if plan != nil {
			C.MacKeyVaultRootGrantsAddClose(plan)
		}
		switch status {
		case 1:
			return nil, errRootGrantsNativeCode
		case 2:
			return nil, errRootGrantsNativeACL
		}
		return nil, &StatusError{Op: "root grants prepare", Status: status}
	}
	return &rootGrantsDarwinAdd{plan: plan, frame: C.GoBytes(unsafe.Pointer(raw), C.int(length))}, nil
}

func (a *rootGrantsDarwinAdd) ACLFrame() []byte { return a.frame }

func (a *rootGrantsDarwinAdd) Commit(account, metadata string, envelope []byte) (bool, int) {
	if a.plan == nil || len(envelope) == 0 {
		return false, -50 // errSecParam
	}
	cAccount := C.CString(account)
	cMetadata := C.CString(metadata)
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cMetadata))
	var attempted C.int
	status := int(C.MacKeyVaultRootGrantsAddCommit(a.plan, cAccount, cMetadata, (*C.uchar)(unsafe.Pointer(&envelope[0])), C.size_t(len(envelope)), &attempted))
	return attempted != 0, status
}

func (a *rootGrantsDarwinAdd) Close() {
	if a.plan != nil {
		C.MacKeyVaultRootGrantsAddClose(a.plan)
		a.plan = nil
	}
}

func (rootGrantsDarwinNative) Readback(account string) ([]byte, []byte, error) {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	var metadata, frame *C.uchar
	var metadataLength, frameLength C.size_t
	status := int(C.MacKeyVaultRootGrantsReadback(cAccount, &metadata, &metadataLength, &frame, &frameLength))
	for _, p := range []*C.uchar{metadata, frame} {
		if p != nil {
			defer C.free(unsafe.Pointer(p))
		}
	}
	if status != 0 {
		return nil, nil, &StatusError{Op: "root grants readback", Status: status}
	}
	if metadata == nil || frame == nil || metadataLength < 1 || metadataLength > 32768 || frameLength < 1 || frameLength > 1048576 {
		return nil, nil, recoveryRefuse("invalid_record")
	}
	return C.GoBytes(unsafe.Pointer(metadata), C.int(metadataLength)), C.GoBytes(unsafe.Pointer(frame), C.int(frameLength)), nil
}

type rootGrantsDarwinRead struct {
	plan     *C.MacKeyVaultRootGrantsRead
	metadata []byte
	frame    []byte
	consumed bool
}

func (rootGrantsDarwinNative) PrepareRead(account string) (rootGrantsNativeRead, error) {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	var plan *C.MacKeyVaultRootGrantsRead
	var metadata, frame *C.uchar
	var metadataLength, frameLength C.size_t
	status := int(C.MacKeyVaultRootGrantsReadPrepare(cAccount, &plan, &metadata, &metadataLength, &frame, &frameLength))
	for _, p := range []*C.uchar{metadata, frame} {
		if p != nil {
			defer C.free(unsafe.Pointer(p))
		}
	}
	if status != 0 || plan == nil || metadata == nil || frame == nil || metadataLength < 1 || metadataLength > 32768 || frameLength < 1 || frameLength > 1048576 {
		if plan != nil {
			C.MacKeyVaultRootGrantsReadClose(plan)
		}
		if status == 1 {
			return nil, errRootGrantsNativeCode
		}
		if status == -25300 {
			return nil, errRootGrantsNativeItemMissing
		}
		if status == 0 {
			return nil, recoveryRefuse("invalid_record")
		}
		return nil, &StatusError{Op: "root grants read prepare", Status: status}
	}
	return &rootGrantsDarwinRead{plan: plan,
		metadata: C.GoBytes(unsafe.Pointer(metadata), C.int(metadataLength)),
		frame:    C.GoBytes(unsafe.Pointer(frame), C.int(frameLength))}, nil
}

func (r *rootGrantsDarwinRead) Metadata() []byte {
	if r == nil {
		return nil
	}
	return append([]byte(nil), r.metadata...)
}

func (r *rootGrantsDarwinRead) ACLFrame() []byte {
	if r == nil {
		return nil
	}
	return append([]byte(nil), r.frame...)
}

func (r *rootGrantsDarwinRead) ReadValue() ([]byte, error) {
	if r == nil || r.plan == nil || r.consumed {
		return nil, recoveryRefuse("operation_unavailable")
	}
	r.consumed = true
	var value *C.uchar
	var length C.size_t
	status := int(C.MacKeyVaultRootGrantsReadValue(r.plan, &value, &length))
	if value != nil {
		defer C.free(unsafe.Pointer(value))
	}
	if status != 0 {
		if status == 1 {
			return nil, errRootGrantsNativeCode
		}
		if status == -25300 {
			return nil, errRootGrantsNativeItemMissing
		}
		return nil, &StatusError{Op: "root grants read value", Status: status}
	}
	if value == nil || length < 1 || length > recoveryMaxCiphertext {
		return nil, recoveryRefuse("invalid_envelope")
	}
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

func (r *rootGrantsDarwinRead) Close() {
	if r == nil {
		return
	}
	clear(r.metadata)
	clear(r.frame)
	r.metadata, r.frame = nil, nil
	if r.plan != nil {
		C.MacKeyVaultRootGrantsReadClose(r.plan)
		r.plan = nil
	}
}
