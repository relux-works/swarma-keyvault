//go:build darwin && cgo

package keyvault

/*
#include <stdlib.h>
#include "security_darwin.h"
*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

// This private handle is not wired to any CLI, facade or archive export. Its
// future owner must hold the account gate before prepare through Close, freeze
// and completely display reviewDocument, and obtain genuine owner admission.
// Neither this constructor nor an apply call supplies that consent.
type pendingRecoveryAdoption struct {
	mu     sync.Mutex
	native *C.MacKeyVaultRecoveryAdoption
	plan   *recoveryAdoptionPlan
}

func (*pendingRecoveryAdoption) String() string   { return "<pending recovery adoption>" }
func (*pendingRecoveryAdoption) GoString() string { return "<pending recovery adoption>" }

func adoptionCBytes(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func prepareRecoveryAdoption(s *recoveryAdoptionSelection) (_ *pendingRecoveryAdoption, err error) {
	if s == nil {
		return nil, errRecoveryAdoptionInvalid
	}
	owned, err := newRecoveryAdoptionSelection(s.account, s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash)
	if err != nil {
		return nil, err
	}
	defer owned.clear()
	account := C.CString(owned.account)
	oldPath := C.CString(owned.old.path)
	nextPath := C.CString(owned.next.path)
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(oldPath))
	defer C.free(unsafe.Pointer(nextPath))
	var handle *C.MacKeyVaultRecoveryAdoption
	var frame *C.uchar
	var length C.size_t
	keep := false
	defer func() {
		if frame != nil {
			C.free(unsafe.Pointer(frame))
		}
		if !keep && handle != nil {
			C.MacKeyVaultRecoveryAdoptionClose(handle)
		}
	}()
	status := C.MacKeyVaultRecoveryAdoptionInspect(account, adoptionCBytes(owned.metadata), C.size_t(len(owned.metadata)),
		adoptionCBytes(owned.sealed), C.size_t(len(owned.sealed)), adoptionCBytes(owned.persistent), C.size_t(len(owned.persistent)),
		oldPath, adoptionCBytes(owned.old.hash), C.size_t(len(owned.old.hash)), nextPath, adoptionCBytes(owned.next.hash), C.size_t(len(owned.next.hash)), &handle, &frame, &length)
	runtime.KeepAlive(owned) // C copies inputs synchronously; no Go pointer survives.
	if status != 0 || handle == nil || frame == nil || length == 0 || length > recoveryAdoptionMaxFrame {
		return nil, errRecoveryAdoptionNative
	}
	raw := C.GoBytes(unsafe.Pointer(frame), C.int(length))
	defer clear(raw)
	plan, err := newRecoveryAdoptionPlan(owned, raw)
	if err != nil {
		return nil, errRecoveryAdoptionNative
	}
	keep = true
	return &pendingRecoveryAdoption{native: handle, plan: plan}, nil
}

func (p *pendingRecoveryAdoption) reviewDocument() ([]byte, string, error) {
	if p == nil {
		return nil, "", errRecoveryAdoptionInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil || p.plan == nil {
		return nil, "", errRecoveryAdoptionInvalid
	}
	frame, digest := p.plan.reviewDocument()
	return frame, digest, nil
}

func (p *pendingRecoveryAdoption) closeLocked() {
	if p.native != nil {
		C.MacKeyVaultRecoveryAdoptionClose(p.native)
		p.native = nil
	}
	if p.plan != nil {
		p.plan.clear()
		p.plan = nil
	}
}
func (p *pendingRecoveryAdoption) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

// One shot. Native completion is not a public adoption receipt. No raw status,
// sealed value or metadata enters an error. No new account is unsealed here.
func (p *pendingRecoveryAdoption) apply() (err error) {
	if p == nil {
		return errRecoveryAdoptionInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil || p.plan == nil {
		return errRecoveryAdoptionInvalid
	}
	defer p.closeLocked()
	var attempted C.int
	// Preserve uncertainty if a Go panic interrupts a synchronous mutation.
	defer func() {
		if recover() != nil {
			err = recoveryAdoptionResult(1, attempted != 0)
		}
	}()
	status := C.MacKeyVaultRecoveryAdoptionApply(p.native, adoptionCBytes(p.plan.native), C.size_t(len(p.plan.native)), &attempted)
	runtime.KeepAlive(p.plan)
	return recoveryAdoptionResult(int(status), attempted != 0)
}
