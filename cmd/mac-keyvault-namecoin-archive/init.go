//go:build darwin && cgo

package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#ifndef KEYVAULT_NMC_INIT_CALLBACKS_V1
#define KEYVAULT_NMC_INIT_CALLBACKS_V1
// All pointers are call-scoped. Protected anchors are SECRET and remain inside
// the qualified helper; create is create-only, never update or replacement.
typedef struct kv_nmc_init_callbacks_v1 {
 void *context;
 int (*require_absent)(void *);
 int (*create_initialized_anchor)(void *, const unsigned char *, size_t);
 int (*load_protected)(void *, unsigned char *, size_t, size_t *);
} kv_nmc_init_callbacks_v1;
#endif
static int kv_nmc_init_absent(kv_nmc_init_callbacks_v1 c) {
 return c.require_absent ? c.require_absent(c.context) : -1;
}
static int kv_nmc_init_create(kv_nmc_init_callbacks_v1 c,const unsigned char *b,size_t n) {
 return c.create_initialized_anchor ? c.create_initialized_anchor(c.context,b,n) : -1;
}
static int kv_nmc_init_load(kv_nmc_init_callbacks_v1 c,unsigned char *b,size_t n,size_t *w) {
 return c.load_protected ? c.load_protected(c.context,b,n,w) : -1;
}
static void kv_nmc_init_clear_free(void *p,size_t n) {
 volatile unsigned char *b=(volatile unsigned char *)p;
 while(n--) { *b++=0; }
 free(p);
}
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
)

const initializationHandleLimit = 64
const initializationAnchorLimit = 32768

type initializationSession interface {
	CheckPublicAbsent() error
	CompleteReviewed([]byte, namecoinpsbt.ProtectedInitializer) error
	Close() error
}

type initializationEntry struct {
	mu               sync.Mutex
	session          initializationSession
	consumed, closed bool
	closeCode        int32
}

type initializationRegistry struct {
	entries sync.Map
	count   atomic.Uint64
	open    func(namecoinpsbt.NativeSelection, []byte) (initializationSession, error)
}

// The production constructor is fixed. There is no exported factory, private
// input getter or callback/pointer retained by a registry entry.
var initializationHandles = &initializationRegistry{open: func(c namecoinpsbt.NativeSelection, pin []byte) (initializationSession, error) {
	session, err := namecoinpsbt.OpenInitialization(c, pin)
	if err != nil {
		return nil, err
	}
	return session, nil
}}

func (r *initializationRegistry) entry(h uint64) *initializationEntry {
	if h == 0 || h&rootHandleBit != 0 {
		return nil
	}
	v, ok := r.entries.Load(h)
	if !ok {
		return nil
	}
	return v.(*initializationEntry)
}

func (r *initializationRegistry) start(c namecoinpsbt.NativeSelection, pin []byte) (h uint64, code int32) {
	if r.count.Load() >= initializationHandleLimit {
		return 0, 13
	}
	session, err := r.open(c, pin)
	transferred := false
	defer func() {
		if session != nil && !transferred {
			_ = session.Close()
		}
	}()
	if err != nil {
		return 0, int32(codeFor(err))
	}
	if session == nil {
		return 0, 19
	}
	if r.count.Add(1) > initializationHandleLimit {
		return 0, 13
	}
	// Share the existing low-domain allocator with sign/reconcile. Separate maps
	// reject cross-operation handles without interpreting another domain's state.
	h = allocateNativeHandle()
	if h == 0 || h&rootHandleBit != 0 {
		return 0, 19
	}
	r.entries.Store(h, &initializationEntry{session: session})
	transferred = true
	return h, 0
}

func (r *initializationRegistry) close(h uint64) int32 {
	e := r.entry(h)
	if e == nil {
		return 1
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return e.closeCode
	}
	e.closed, e.closeCode = true, 19
	session := e.session
	e.session = nil
	if session != nil && session.Close() != nil {
		return 19
	}
	e.closeCode = 0
	return 0
}

type initializationNativeAdapter struct{ callbacks C.kv_nmc_init_callbacks_v1 }

func (a initializationNativeAdapter) RequireAbsentForExplicitInitialization() error {
	if C.kv_nmc_init_absent(a.callbacks) != 0 {
		return adapterUnavailable
	}
	return nil
}
func (a initializationNativeAdapter) CreateInitializedAnchor(raw []byte) error {
	if len(raw) == 0 || len(raw) > initializationAnchorLimit {
		return adapterUnavailable
	}
	if C.kv_nmc_init_create(a.callbacks, (*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw))) != 0 {
		return adapterUnavailable
	}
	return nil
}
func (a initializationNativeAdapter) LoadProtected() ([]byte, error) {
	var size C.size_t
	if C.kv_nmc_init_load(a.callbacks, nil, 0, &size) != 0 || size == 0 || size > initializationAnchorLimit {
		return nil, adapterUnavailable
	}
	buffer := C.malloc(size)
	if buffer == nil {
		return nil, adapterUnavailable
	}
	defer C.kv_nmc_init_clear_free(buffer, size)
	var written C.size_t
	if C.kv_nmc_init_load(a.callbacks, (*C.uchar)(buffer), size, &written) != 0 || written != size {
		return nil, adapterUnavailable
	}
	return C.GoBytes(buffer, C.int(size)), nil
}

// Open validates public selection/pin and reserves the real initialization gate.
// It creates neither a public journal nor a protected item. Out-handle remains
// zero on every refusal or recoverable Go panic.
//
//export kv_nmc_init_open_v1
func kv_nmc_init_open_v1(pin *C.uchar, pinSize C.size_t, config *C.uchar, configSize C.size_t, outHandle *C.uint64_t) (verdict C.int32_t) {
	verdict = 19
	defer func() {
		if recover() != nil {
			if outHandle != nil {
				*outHandle = 0
			}
			verdict = 19
		}
	}()
	if outHandle == nil {
		return 1
	}
	*outHandle = 0
	cfgRaw, ok := publicInput(config, configSize, 4<<20)
	if !ok {
		return 18
	}
	cfg, err := namecoinpsbt.DecodeNativeSelection(cfgRaw)
	if err != nil {
		return C.int32_t(codeFor(err))
	}
	selectedPin, ok := publicInput(pin, pinSize, 32768)
	if !ok {
		return 5
	}
	h, code := initializationHandles.start(cfg, selectedPin)
	if code != 0 {
		return C.int32_t(code)
	}
	*outHandle = C.uint64_t(h)
	return 0
}

// Check absence is public-only and must run before native withAccount.
// Failed/unknown/panicking queries consume the operation but retain its gate
// until explicit Close outside any native borrow. No native callback is used.
//
//export kv_nmc_init_check_absent_v1
func kv_nmc_init_check_absent_v1(handle C.uint64_t) (verdict C.int32_t) {
	verdict = 19
	var e *initializationEntry
	locked := false
	defer func() {
		if recover() != nil {
			verdict = 19
			if locked {
				e.consumed = true
			}
		}
		if locked {
			e.mu.Unlock()
		}
	}()
	e = initializationHandles.entry(uint64(handle))
	if e == nil {
		return 1
	}
	e.mu.Lock()
	locked = true
	if e.closed {
		return 1
	}
	if e.consumed || e.session == nil {
		return 19
	}
	err := e.session.CheckPublicAbsent()
	if err != nil {
		e.consumed = true
	}
	return C.int32_t(codeFor(err))
}

// Complete borrows actual account material only after native review/presence.
// A caught panic consumes the operation and clears owned Go material, but keeps
// the SAME gate until the native borrow has cleared and explicitly calls Close.
//
//export kv_nmc_init_complete_v1
func kv_nmc_init_complete_v1(handle C.uint64_t, material *C.uchar, materialSize C.size_t, callbacks *C.kv_nmc_init_callbacks_v1) (verdict C.int32_t) {
	verdict = 19
	defer func() {
		if recover() != nil {
			verdict = 19
		}
	}()
	e := initializationHandles.entry(uint64(handle))
	if e == nil {
		return 1
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.consumed || e.session == nil {
		return 19
	}
	e.consumed = true
	if material == nil || materialSize != 64 || callbacks == nil {
		return 1
	}
	c := *callbacks
	if c.require_absent == nil || c.create_initialized_anchor == nil || c.load_protected == nil {
		return 1
	}
	owned := C.GoBytes(unsafe.Pointer(material), 64)
	defer clear(owned)
	return C.int32_t(codeFor(e.session.CompleteReviewed(owned, initializationNativeAdapter{callbacks: c})))
}

// Close belongs AFTER all native private buffers have been cleared. A failed or
// panicking close is retained as UNKNOWN; repetition does not retry the release.
//
//export kv_nmc_init_close_v1
func kv_nmc_init_close_v1(handle C.uint64_t) (verdict C.int32_t) {
	verdict = 19
	defer func() {
		if recover() != nil {
			verdict = 19
		}
	}()
	return C.int32_t(initializationHandles.close(uint64(handle)))
}
