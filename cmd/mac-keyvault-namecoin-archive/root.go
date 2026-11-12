//go:build darwin && cgo

package main

/*
#include <stdint.h>
#include <stddef.h>
enum {
 KV_RG_OK=0, KV_RG_INVALID_ARGUMENTS=1, KV_RG_TERMINAL_REQUIRED=2,
 KV_RG_INVALID_WORD_NUMBER=3, KV_RG_INVALID_WORD_COUNT=4,
 KV_RG_INVALID_MNEMONIC=5, KV_RG_INVALID_CHECKSUM=6,
 KV_RG_INVALID_DERIVATION=7, KV_RG_RETAINED_RECORD_MISMATCH=8,
 KV_RG_PUBLIC_PIN_MISMATCH=9, KV_RG_OPERATION_UNAVAILABLE=10,
 KV_RG_WRAPPING_POLICY_REFUSED=11, KV_RG_INVALID_ENVELOPE=12,
 KV_RG_BINDING_MISMATCH=13, KV_RG_CANCELED=14, KV_RG_TIMEOUT=15,
 KV_RG_PRIVATE_PROTOCOL_ERROR=16, KV_RG_LIMIT_EXCEEDED=17,
 KV_RG_UNSUPPORTED_VERSION=18, KV_RG_UNSUPPORTED_OPERATION=19,
 KV_RG_INPUT_CANCELED=20
};
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const rootHandleBit uint64 = 1 << 63
const rootRequestLimit = 262144
const rootResponseLimit = 131072
const rootAttemptLimit = 900 * time.Second
const rootHandleLimit = 64 // Closed handles remain bounded tombstones.

type rootFacade interface {
	Prepare() (keyvault.RootGrantsPreparationPublic, error)
	Seal([]byte, []byte) (keyvault.RootGrantsPrivateSealed, error)
	Close()
}

type rootPhase uint8

const (
	rootNew rootPhase = iota
	rootPrepared
	rootSealed
	rootClosed
)

type rootEntry struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	session rootFacade
	phase   rootPhase
	public  []byte
	sealed  []byte
}

type rootRegistry struct {
	entries sync.Map
	next    atomic.Uint64
	open    func(context.Context, []byte) (*keyvault.RootGrantsPrivateSession, error)
}

// This registry has no external factory, reader or callback selection. Its
// production constructor is the fixed public-request-only vault facade.
var rootHandles = &rootRegistry{open: keyvault.OpenRootGrantsPrivate}

var rootCodes = map[string]int32{
	"recovery_invalid_arguments": 1, "recovery_terminal_required": 2,
	"recovery_invalid_word_number": 3, "recovery_invalid_word_count": 4,
	"recovery_invalid_mnemonic": 5, "recovery_invalid_checksum": 6,
	"recovery_checksum_or_pin_mismatch": 6, "recovery_invalid_derivation": 7,
	"recovery_retained_record_mismatch": 8, "recovery_public_pin_mismatch": 9,
	"recovery_operation_unavailable": 10, "recovery_wrapping_policy_refused": 11,
	"recovery_invalid_envelope": 12, "recovery_binding_mismatch": 13,
	"recovery_canceled": 14, "recovery_timeout": 15,
	"recovery_private_protocol_error": 16, "recovery_limit_exceeded": 17,
	"recovery_unsupported_version": 18, "recovery_unsupported_operation": 19,
	"recovery_input_canceled": 20,
}

func rootCode(err error) int32 {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 15
	}
	if errors.Is(err, context.Canceled) {
		return 14
	}
	var refusal *keyvault.Refusal
	if errors.As(err, &refusal) && refusal != nil {
		if code, ok := rootCodes[refusal.Code]; ok {
			return code
		}
	}
	return 16
}

func (r *rootRegistry) entry(handle uint64) *rootEntry {
	if handle&rootHandleBit == 0 {
		return nil
	}
	v, ok := r.entries.Load(handle)
	if !ok {
		return nil
	}
	return v.(*rootEntry) // Every exported caller has a direct panic boundary.
}

// clearLocked removes owned output and private ownership before invoking Close,
// so even an unexpected Close panic cannot retain accessible session state.
func (s *rootEntry) clearLocked() {
	clear(s.public)
	clear(s.sealed)
	s.public, s.sealed = nil, nil
	s.phase = rootClosed
	session := s.session
	s.session = nil
	if session != nil {
		session.Close()
	}
}

func (s *rootEntry) checkLocked() int32 {
	if errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
		s.clearLocked()
		return 15
	}
	if s.phase == rootClosed {
		return 10
	}
	if s.ctx.Err() != nil {
		s.clearLocked()
		return 14
	}
	return 0
}

// Panic cleanup must itself stay within the C boundary. Clear state first and
// suppress only a second cleanup panic; no raw diagnostic crosses the ABI.
func (r *rootRegistry) abort(handle uint64) {
	defer func() { _ = recover() }()
	v, ok := r.entries.Load(handle)
	s, typed := v.(*rootEntry)
	if !ok || !typed || s == nil {
		return
	}
	s.cancel() // Cancel before waiting for a live terminal operation.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
}

func (r *rootRegistry) start(ctx context.Context, cancel context.CancelFunc, raw []byte) (uint64, int32) {
	if r.next.Load() >= rootHandleLimit {
		return 0, 17
	}
	session, err := r.open(ctx, raw)
	if err != nil {
		return 0, rootCode(err)
	}
	if session == nil {
		return 0, 16
	}
	n := r.next.Add(1)
	if n > rootHandleLimit {
		session.Close()
		return 0, 17
	}
	handle := rootHandleBit | n
	s := &rootEntry{ctx: ctx, cancel: cancel, session: session}
	r.entries.Store(handle, s)
	context.AfterFunc(ctx, func() { r.abort(handle) })
	return handle, 0
}

func (r *rootRegistry) prepare(handle uint64) int32 {
	s := r.entry(handle)
	if s == nil {
		return 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if code := s.checkLocked(); code != 0 {
		return code
	}
	if s.phase != rootNew {
		s.clearLocked()
		return 10
	}
	view, err := s.session.Prepare()
	if err != nil {
		s.clearLocked()
		return rootCode(err)
	}
	if code := s.checkLocked(); code != 0 {
		return code
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw) == 0 || len(raw) > rootResponseLimit {
		s.clearLocked()
		return 16
	}
	s.public = raw
	s.phase = rootPrepared
	return 0
}

func (r *rootRegistry) seal(handle uint64, point, blob []byte) int32 {
	s := r.entry(handle)
	if s == nil {
		return 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if code := s.checkLocked(); code != 0 {
		return code
	}
	if s.phase != rootPrepared {
		s.clearLocked()
		return 10
	}
	sealed, err := s.session.Seal(point, blob)
	if err != nil {
		s.clearLocked()
		return rootCode(err)
	}
	if code := s.checkLocked(); code != 0 {
		return code
	}
	// The fixed facade returns already-canonical PUBLIC/sealed RawMessages.
	// There is no scalar or private callback in this representation.
	raw, err := json.Marshal(struct {
		Record   json.RawMessage `json:"record"`
		Envelope json.RawMessage `json:"envelope"`
	}{sealed.Record, sealed.Envelope})
	if err != nil || len(raw) == 0 || len(raw) > rootResponseLimit {
		s.clearLocked()
		return 16
	}
	s.sealed = raw
	s.phase = rootSealed
	return 0
}

func (r *rootRegistry) copy(handle uint64, sealed bool, dst []byte, query bool) (int, int32) {
	s := r.entry(handle)
	if s == nil {
		return 0, 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if code := s.checkLocked(); code != 0 {
		return 0, code
	}
	data := s.public
	if sealed {
		if s.phase != rootSealed {
			return 0, 10
		}
		data = s.sealed
	} else if s.phase != rootPrepared {
		return 0, 10
	}
	if query {
		return len(data), 0
	}
	if len(dst) < len(data) {
		return len(data), 1
	}
	copy(dst, data)
	return len(data), 0
}

func (r *rootRegistry) close(handle uint64) int32 {
	s := r.entry(handle)
	if s == nil {
		return 1
	}
	code := int32(0)
	if errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
		code = 15
	}
	s.cancel() // Must precede the mutex: Prepare may be reading the tty.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
	return code
}

func rootCopyC(handle uint64, sealed bool, out *C.uchar, capacity C.size_t, written *C.size_t) int32 {
	// Resolve first so corruption is handled by the exported recover boundary.
	if rootHandles.entry(handle) == nil {
		if written != nil {
			*written = 0
		}
		return 1
	}
	if written == nil {
		return 1
	}
	*written = 0
	if uint64(capacity) > rootResponseLimit {
		return 17
	}
	query := out == nil && capacity == 0
	if out == nil && !query {
		return 1
	}
	var dst []byte
	if out != nil && capacity != 0 {
		dst = unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capacity))
	}
	n, code := rootHandles.copy(handle, sealed, dst, query)
	*written = C.size_t(n)
	return code
}

//export kv_rg_open_v1
func kv_rg_open_v1(raw *C.uchar, size C.size_t, outHandle *C.uint64_t) (verdict C.int32_t) {
	verdict = 16
	var handle uint64
	ctx, cancel := context.WithTimeout(context.Background(), rootAttemptLimit)
	defer func() {
		if recover() != nil {
			rootHandles.abort(handle)
			if outHandle != nil {
				*outHandle = 0
			}
			verdict = 16
		}
		if handle == 0 || verdict != 0 {
			cancel()
		}
	}()
	if outHandle == nil {
		return 1
	}
	*outHandle = 0
	if raw == nil || size == 0 {
		return 1
	}
	if uint64(size) > rootRequestLimit {
		return 17
	}
	owned := C.GoBytes(unsafe.Pointer(raw), C.int(size))
	defer clear(owned)
	var code int32
	handle, code = rootHandles.start(ctx, cancel, owned)
	if code == 0 {
		*outHandle = C.uint64_t(handle)
	}
	return C.int32_t(code)
}

//export kv_rg_prepare_v1
func kv_rg_prepare_v1(handle C.uint64_t) (verdict C.int32_t) {
	verdict = 16
	defer func() {
		if recover() != nil {
			rootHandles.abort(uint64(handle))
			verdict = 16
		}
	}()
	return C.int32_t(rootHandles.prepare(uint64(handle)))
}

//export kv_rg_copy_public_v1
func kv_rg_copy_public_v1(handle C.uint64_t, out *C.uchar, capacity C.size_t, written *C.size_t) (verdict C.int32_t) {
	verdict = 16
	defer func() {
		if recover() != nil {
			rootHandles.abort(uint64(handle))
			if written != nil {
				*written = 0
			}
			verdict = 16
		}
	}()
	return C.int32_t(rootCopyC(uint64(handle), false, out, capacity, written))
}

//export kv_rg_seal_v1
func kv_rg_seal_v1(handle C.uint64_t, point *C.uchar, pointSize C.size_t, blob *C.uchar, blobSize C.size_t) (verdict C.int32_t) {
	verdict = 16
	defer func() {
		if recover() != nil {
			rootHandles.abort(uint64(handle))
			verdict = 16
		}
	}()
	if point == nil || pointSize != 65 || blob == nil || blobSize == 0 || uint64(blobSize) > 16384 {
		rootHandles.abort(uint64(handle))
		return 1
	}
	p := C.GoBytes(unsafe.Pointer(point), 65)
	b := C.GoBytes(unsafe.Pointer(blob), C.int(blobSize))
	defer clear(p)
	defer clear(b)
	return C.int32_t(rootHandles.seal(uint64(handle), p, b))
}

//export kv_rg_copy_sealed_v1
func kv_rg_copy_sealed_v1(handle C.uint64_t, out *C.uchar, capacity C.size_t, written *C.size_t) (verdict C.int32_t) {
	verdict = 16
	defer func() {
		if recover() != nil {
			rootHandles.abort(uint64(handle))
			if written != nil {
				*written = 0
			}
			verdict = 16
		}
	}()
	return C.int32_t(rootCopyC(uint64(handle), true, out, capacity, written))
}

//export kv_rg_close_v1
func kv_rg_close_v1(handle C.uint64_t) (verdict C.int32_t) {
	verdict = 16
	defer func() {
		if recover() != nil {
			rootHandles.abort(uint64(handle))
			verdict = 16
		}
	}()
	return C.int32_t(rootHandles.close(uint64(handle)))
}
