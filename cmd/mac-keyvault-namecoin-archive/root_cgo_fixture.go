//go:build darwin && cgo && keyvault_abi_tests

package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// Go test files cannot import C. This explicitly tagged fixture exercises the
// actual exported wrappers with PUBLIC buffers; normal archives omit it.
// It proves wrapper behavior, not an external Swift/C caller or native policy.
func rootFixturePointer(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func rootFixtureOpen(raw []byte) (uint64, int32) {
	h := C.uint64_t(999999)
	code := kv_rg_open_v1(rootFixturePointer(raw), C.size_t(len(raw)), &h)
	return uint64(h), int32(code)
}

func rootFixturePrepare(h uint64) int32 { return int32(kv_rg_prepare_v1(C.uint64_t(h))) }
func rootFixtureClose(h uint64) int32   { return int32(kv_rg_close_v1(C.uint64_t(h))) }
func rootFixtureSeal(h uint64, point, blob []byte) int32 {
	return int32(kv_rg_seal_v1(C.uint64_t(h), rootFixturePointer(point), C.size_t(len(point)), rootFixturePointer(blob), C.size_t(len(blob))))
}

func rootFixtureCopy(h uint64, sealed bool, dst []byte, capacity int, omitWritten bool) (int, int32) {
	if dst != nil && capacity > len(dst) {
		panic("public fixture would claim unowned memory")
	}
	w := C.size_t(999999)
	wp := &w
	if omitWritten {
		wp = nil
	}
	if sealed {
		code := kv_rg_copy_sealed_v1(C.uint64_t(h), rootFixturePointer(dst), C.size_t(capacity), wp)
		return int(w), int32(code)
	}
	code := kv_rg_copy_public_v1(C.uint64_t(h), rootFixturePointer(dst), C.size_t(capacity), wp)
	return int(w), int32(code)
}

func rootFixtureTrustContextOpen(budget time.Duration) (uint64, int32) {
	h := C.uint64_t(999999)
	code := kv_rg_sign_trust_contract_countersign_context_open_v1(C.uint64_t(budget), &h)
	return uint64(h), int32(code)
}

func rootFixtureTrustContextCancel(h uint64) int32 {
	return int32(kv_rg_sign_trust_contract_countersign_context_cancel_v1(C.uint64_t(h)))
}

func rootFixtureTrustContextClose(h uint64) int32 {
	return int32(kv_rg_sign_trust_contract_countersign_context_close_v1(C.uint64_t(h)))
}

func rootFixtureTrustPolicy(h uint64, request []byte) int32 {
	return int32(kv_rg_sign_trust_contract_countersign_policy_check_v1(
		C.uint64_t(h), rootFixturePointer(request), C.size_t(len(request))))
}

func rootFixtureTrustSign(h uint64, request, plaintext, output []byte, capacity int,
	omitWritten bool) (int, int32) {
	if output != nil && capacity > len(output) {
		panic("public fixture would claim unowned signature memory")
	}
	written := C.size_t(999999)
	var writtenPointer *C.size_t = &written
	if omitWritten {
		writtenPointer = nil
	}
	code := kv_rg_sign_trust_contract_countersign_v1(
		C.uint64_t(h), rootFixturePointer(request), C.size_t(len(request)),
		rootFixturePointer(plaintext), C.size_t(len(plaintext)),
		rootFixturePointer(output), C.size_t(capacity), writtenPointer)
	return int(written), int32(code)
}
