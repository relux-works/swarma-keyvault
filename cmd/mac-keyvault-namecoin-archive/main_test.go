//go:build darwin && cgo

package main

import "testing"

// A recoverable Go panic at each public-handle export returns only UNKNOWN,
// rather than unwinding through the C caller. The corrupt map entry is a bounded
// internal fault injection; this does not cover invalid C memory or native traps.
func TestNativeExportsCloseRecoverablePanics(t *testing.T) {
	const handle = 9223372036854775000
	for _, name := range []string{"review", "ack", "run", "close"} {
		t.Run(name, func(t *testing.T) {
			nativeEntries.Store(uint64(handle), struct{}{})
			defer nativeEntries.Delete(uint64(handle))
			verdict := -1
			switch name {
			case "review":
				verdict = int(kv_nmc_copy_review_v1(handle, nil, 0, nil))
			case "ack":
				verdict = int(kv_nmc_copy_ack_v1(handle, nil, 0, nil))
			case "run":
				verdict = int(kv_nmc_run_v1(handle, nil, 0, nil))
			case "close":
				verdict = int(kv_nmc_close_v1(handle))
			}
			if verdict != 19 {
				t.Fatalf("panic verdict %d", verdict)
			}
		})
	}
}

// Ordinary missing-handle and invalid-buffer/helper refusals preserve their
// distinct closed codes, and an uncompleted entry exposes no acknowledgement.
// No protected callback, real session or native UI is exercised here.
func TestNativeExportsPreserveOrdinaryRefusals(t *testing.T) {
	const handle = 9223372036854775001
	nativeEntries.Delete(uint64(handle))
	if int(kv_nmc_copy_review_v1(handle, nil, 0, nil)) != 1 || int(kv_nmc_copy_ack_v1(handle, nil, 0, nil)) != 1 || int(kv_nmc_close_v1(handle)) != 1 {
		t.Fatal("missing handle code")
	}
	nativeEntries.Store(uint64(handle), &nativeEntry{review: []byte("public review")})
	defer nativeEntries.Delete(uint64(handle))
	if int(kv_nmc_copy_review_v1(handle, nil, 0, nil)) != 1 {
		t.Fatal("invalid output was admitted")
	}
	if int(kv_nmc_copy_ack_v1(handle, nil, 0, nil)) != 19 {
		t.Fatal("acknowledgement exposed before completion")
	}
	if int(kv_nmc_run_v1(handle, nil, 0, nil)) != 17 {
		t.Fatal("missing private adapter was admitted")
	}
}
