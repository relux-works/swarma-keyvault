//go:build darwin && cgo

// Command mac-keyvault-namecoin-archive is linked only into the qualified native
// custody helper. It has no executable command, IPC dispatcher or generic signer.
package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
// Buffers are borrowed for the call only. Never retain a pointer. Protected
// buffers are SECRET and may reach only the exact native protected item.
static void kv_nmc_clear_free(void *p,size_t n) {
 volatile unsigned char *b=(volatile unsigned char *)p;
 while(n--) { *b++=0; }
 free(p);
}
typedef int (*kv_nmc_load_fn)(void *, unsigned char *, size_t, size_t *);
typedef int (*kv_nmc_replace_fn)(void *, const unsigned char *, size_t);
typedef int (*kv_nmc_output_fn)(void *, const unsigned char *, size_t, const unsigned char *);
typedef struct {
 void *context;
 kv_nmc_load_fn load_protected;
 kv_nmc_replace_fn replace_protected;
 kv_nmc_output_fn write_public_result;
} kv_nmc_callbacks_v1;
enum {
 KV_NMC_OK=0, KV_NMC_INVALID_REQUEST=1, KV_NMC_UNSUPPORTED_PSBT=2,
 KV_NMC_UNSUPPORTED_SCRIPT=3, KV_NMC_DISPLAY_REFUSED=4,
 KV_NMC_ACCOUNT_MISMATCH=5, KV_NMC_PATH_REFUSED=6,
 KV_NMC_PREVOUT_MISMATCH=7, KV_NMC_INTENT_MISMATCH=8,
 KV_NMC_SIGHASH_REFUSED=9, KV_NMC_FEE_REFUSED=10,
 KV_NMC_REQUEST_EXPIRED=11, KV_NMC_REPLAY_REFUSED=12,
 KV_NMC_ACCOUNT_BUSY=13, KV_NMC_AUTH_REFUSED=14,
 KV_NMC_PRESENCE_UNAVAILABLE=15, KV_NMC_ADOPTION_REQUIRED=16,
 KV_NMC_HELPER_NOT_ADMITTED=17, KV_NMC_POLICY_REFUSED=18,
 KV_NMC_OUTCOME_UNKNOWN=19, KV_NMC_JOURNAL_UNAVAILABLE=20,
 KV_NMC_OUTPUT_UNAVAILABLE=21
};
static int kv_nmc_call_load(kv_nmc_callbacks_v1 c,unsigned char *b,size_t n,size_t *w) {
 return c.load_protected ? c.load_protected(c.context,b,n,w) : -1;
}
static int kv_nmc_call_replace(kv_nmc_callbacks_v1 c,const unsigned char *b,size_t n) {
 return c.replace_protected ? c.replace_protected(c.context,b,n) : -1;
}
static int kv_nmc_call_output(kv_nmc_callbacks_v1 c,const unsigned char *b,size_t n,const unsigned char *h) {
 return c.write_public_result ? c.write_public_result(c.context,b,n,h) : -1;
}
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type nativeEntry struct {
	mu          sync.Mutex
	session     *namecoinpsbt.Session
	review, ack []byte
	reconcile   bool
}

var nativeEntries sync.Map
var nextNativeID atomic.Uint64

// Both Namecoin operations share one low-domain allocator. Exhaustion never
// enters the root-handle domain or wraps back to a reusable identifier.
func allocateNativeHandle() uint64 {
	if nextNativeID.Load() >= rootHandleBit-1 {
		return 0
	}
	h := nextNativeID.Add(1)
	if h == 0 || h >= rootHandleBit {
		return 0
	}
	return h
}

var adapterUnavailable = errors.New("native adapter unavailable")
var nativeCodes = []namecoinwire.Code{"", namecoinwire.InvalidRequest, namecoinwire.UnsupportedPSBT, namecoinwire.UnsupportedScript, namecoinwire.DisplayRefused, namecoinwire.AccountMismatch, namecoinwire.PathRefused, namecoinwire.PrevoutMismatch, namecoinwire.IntentMismatch, namecoinwire.SighashRefused, namecoinwire.FeeRefused, namecoinwire.RequestExpired, namecoinwire.ReplayRefused, namecoinwire.AccountBusy, namecoinwire.AuthRefused, namecoinwire.PresenceUnavailable, namecoinwire.AdoptionRequired, namecoinwire.HelperNotAdmitted, namecoinwire.PolicyRefused, namecoinwire.OutcomeUnknown, namecoinwire.JournalUnavailable, namecoinwire.OutputUnavailable}

func codeFor(err error) C.int {
	if err == nil {
		return C.KV_NMC_OK
	}
	var f namecoinwire.Failure
	if errors.As(err, &f) {
		for i, c := range nativeCodes {
			if c == f.Code() {
				return C.int(i)
			}
		}
	}
	return C.KV_NMC_OUTCOME_UNKNOWN
}
func publicInput(ptr *C.uchar, size C.size_t, limit int) ([]byte, bool) {
	if ptr == nil || size == 0 || uint64(size) > uint64(limit) {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(size)), true
}

// kv_nmc_open_v1 acquires/retains the real gate before any protected load.
// mode1 is fresh sign, mode2 is historical reconciliation using an exact stored
// public descriptor. Config and pin are independently selected native authority;
// arbitrary request data must never be used to select them. No private input.
//
//export kv_nmc_open_v1
func kv_nmc_open_v1(mode C.int, request *C.uchar, requestSize C.size_t, pin *C.uchar, pinSize C.size_t, config *C.uchar, configSize C.size_t, outHandle *C.uint64_t) (verdict C.int) {
	verdict = C.KV_NMC_OUTCOME_UNKNOWN
	defer func() {
		if recover() != nil {
			verdict = C.KV_NMC_OUTCOME_UNKNOWN
		}
	}()
	if outHandle == nil {
		return C.KV_NMC_INVALID_REQUEST
	}
	*outHandle = 0
	cfgRaw, ok := publicInput(config, configSize, 4<<20)
	if !ok {
		return C.KV_NMC_POLICY_REFUSED
	}
	cfg, err := namecoinpsbt.DecodeNativeSelection(cfgRaw)
	if err != nil {
		return codeFor(err)
	}
	raw, ok := publicInput(request, requestSize, 12<<20)
	if !ok {
		return C.KV_NMC_INVALID_REQUEST
	}
	var attempt namecoinpsbt.PublicAttempt
	switch mode {
	case 1:
		selectedPin, ok := publicInput(pin, pinSize, 32768)
		if !ok {
			return C.KV_NMC_ACCOUNT_MISMATCH
		}
		attempt, err = namecoinpsbt.PrepareAttempt(raw, selectedPin, cfg.Selection, time.Now())
	case 2:
		attempt, err = namecoinpsbt.DecodeAttempt(raw)
		if err == nil {
			actual, _ := json.Marshal(attempt.Selection())
			expected, _ := json.Marshal(cfg.Selection)
			if !bytes.Equal(actual, expected) {
				return C.KV_NMC_POLICY_REFUSED
			}
		}
	default:
		return C.KV_NMC_INVALID_REQUEST
	}
	if err != nil {
		return codeFor(err)
	}
	review, err := attempt.ReviewDocument()
	if err != nil {
		return codeFor(err)
	}
	if mode == 2 {
		var document namecoinpsbt.ReviewDocument
		if json.Unmarshal(review, &document) != nil {
			return C.KV_NMC_DISPLAY_REFUSED
		}
		document.Operation = "reconcile journal"
		document.FeeAtoms = 0
		review, err = json.Marshal(document)
		if err != nil {
			return C.KV_NMC_DISPLAY_REFUSED
		}
	}
	session, err := namecoinpsbt.OpenSession(attempt, cfg.Sidecar)
	if err != nil {
		return codeFor(err)
	}
	id := allocateNativeHandle()
	if id == 0 {
		_ = session.Close()
		return C.KV_NMC_OUTCOME_UNKNOWN
	}
	nativeEntries.Store(id, &nativeEntry{session: session, review: review, reconcile: mode == 2})
	*outHandle = C.uint64_t(id)
	return C.KV_NMC_OK
}

func copyPublic(raw []byte, out *C.uchar, capacity C.size_t, written *C.size_t) C.int {
	if written == nil {
		return C.KV_NMC_INVALID_REQUEST
	}
	*written = C.size_t(len(raw))
	if out == nil && capacity == 0 {
		return C.KV_NMC_OK
	}
	if out == nil || uint64(capacity) < uint64(len(raw)) {
		return C.KV_NMC_OUTPUT_UNAVAILABLE
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(raw)), raw)
	return C.KV_NMC_OK
}

//export kv_nmc_copy_review_v1
func kv_nmc_copy_review_v1(handle C.uint64_t, out *C.uchar, capacity C.size_t, written *C.size_t) (verdict C.int) {
	verdict = C.KV_NMC_OUTCOME_UNKNOWN
	defer func() {
		if recover() != nil {
			verdict = C.KV_NMC_OUTCOME_UNKNOWN
		}
	}()
	value, ok := nativeEntries.Load(uint64(handle))
	if !ok {
		return C.KV_NMC_INVALID_REQUEST
	}
	entry := value.(*nativeEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return copyPublic(entry.review, out, capacity, written)
}

type nativeAdapter struct{ callbacks C.kv_nmc_callbacks_v1 }

func (a nativeAdapter) LoadProtected() ([]byte, error) {
	buffer := C.malloc(512)
	if buffer == nil {
		return nil, adapterUnavailable
	}
	defer C.kv_nmc_clear_free(buffer, 512)
	var written C.size_t
	if C.kv_nmc_call_load(a.callbacks, (*C.uchar)(buffer), 512, &written) != 0 || written == 0 || written > 512 {
		return nil, adapterUnavailable
	}
	return C.GoBytes(buffer, C.int(written)), nil
}
func (a nativeAdapter) ReplaceProtected(raw []byte) error {
	if len(raw) == 0 || len(raw) > 512 || C.kv_nmc_call_replace(a.callbacks, (*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw))) != 0 {
		return adapterUnavailable
	}
	return nil
}
func (a nativeAdapter) WriteVerifiedResult(raw []byte) error {
	if len(raw) == 0 || len(raw) > namecoinwire.MaxResultBytes {
		return adapterUnavailable
	}
	hash := sha256.Sum256(raw)
	if C.kv_nmc_call_output(a.callbacks, (*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)), (*C.uchar)(unsafe.Pointer(&hash[0]))) != 0 {
		return adapterUnavailable
	}
	return nil
}

// kv_nmc_run_v1 is callable only within the linked qualified helper AFTER its
// complete immutable native review and fresh Touch-ID account unseal. The64
// borrowed bytes stay in this process and are never returned. The native caller
// clears its source before closing the handle. There is no approval flag or
// generic digest operation. Callbacks must not retain SECRET buffer pointers.
//
//export kv_nmc_run_v1
func kv_nmc_run_v1(handle C.uint64_t, material *C.uchar, materialSize C.size_t, callbacks *C.kv_nmc_callbacks_v1) (verdict C.int) {
	verdict = C.KV_NMC_OUTCOME_UNKNOWN
	defer func() {
		if recover() != nil {
			verdict = C.KV_NMC_OUTCOME_UNKNOWN
		}
	}()
	value, ok := nativeEntries.Load(uint64(handle))
	if !ok {
		return C.KV_NMC_INVALID_REQUEST
	}
	entry := value.(*nativeEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if material == nil || materialSize != 64 || callbacks == nil || callbacks.load_protected == nil || callbacks.replace_protected == nil || callbacks.write_public_result == nil {
		return C.KV_NMC_HELPER_NOT_ADMITTED
	}
	adapter := nativeAdapter{*callbacks}
	borrowed := unsafe.Slice((*byte)(unsafe.Pointer(material)), 64)
	var result []byte
	var err error
	if entry.reconcile {
		result, err = entry.session.ReconcileReviewed(borrowed, adapter, adapter)
	} else {
		result, err = entry.session.CompleteReviewed(borrowed, adapter, adapter)
	}
	if err != nil {
		return codeFor(err)
	}
	entry.ack = namecoinwire.Acknowledgement(sha256.Sum256(result))
	return C.KV_NMC_OK
}

//export kv_nmc_copy_ack_v1
func kv_nmc_copy_ack_v1(handle C.uint64_t, out *C.uchar, capacity C.size_t, written *C.size_t) (verdict C.int) {
	verdict = C.KV_NMC_OUTCOME_UNKNOWN
	defer func() {
		if recover() != nil {
			verdict = C.KV_NMC_OUTCOME_UNKNOWN
		}
	}()
	value, ok := nativeEntries.Load(uint64(handle))
	if !ok {
		return C.KV_NMC_INVALID_REQUEST
	}
	entry := value.(*nativeEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if len(entry.ack) == 0 {
		return C.KV_NMC_OUTCOME_UNKNOWN
	}
	return copyPublic(entry.ack, out, capacity, written)
}

//export kv_nmc_close_v1
func kv_nmc_close_v1(handle C.uint64_t) (verdict C.int) {
	verdict = C.KV_NMC_OUTCOME_UNKNOWN
	defer func() {
		if recover() != nil {
			verdict = C.KV_NMC_OUTCOME_UNKNOWN
		}
	}()
	value, ok := nativeEntries.LoadAndDelete(uint64(handle))
	if !ok {
		return C.KV_NMC_INVALID_REQUEST
	}
	entry := value.(*nativeEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.session.Close() != nil {
		return C.KV_NMC_OUTCOME_UNKNOWN
	}
	return C.KV_NMC_OK
}
func main() {}
