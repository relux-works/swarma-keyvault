//go:build darwin && cgo

package main

import (
	"context"
	"testing"
	"time"
)

// Claim: the helper's Swift-owned deadline/cancel handle reaches the Go signing
// context and is closed once; this tests the registry, not C ABI linkage.
func TestRootGrantsSigningContextCancellationAndDeadline(t *testing.T) {
	registry := &rootSignContextRegistry{entries: make(map[uint64]rootSignContextEntry)}
	handle, code := registry.open(time.Second)
	if code != 0 || registry.context(handle) == nil {
		t.Fatal("eligible signing context was not opened")
	}
	if _, code := registry.open(900 * time.Second); code != 15 {
		t.Fatalf("attach-sized budget got status %d, want timeout refusal", code)
	}
	if registry.cancel(handle, false) != 0 {
		t.Fatal("open signing context did not accept cancellation")
	}
	if err := registry.context(handle).Err(); err != context.Canceled {
		t.Fatalf("cancel was not visible to Go signing: %v", err)
	}
	if registry.cancel(handle, true) != 0 || registry.context(handle) != nil {
		t.Fatal("closed signing context remained available")
	}
	if _, code := registry.open(0); code != 15 {
		t.Fatalf("empty deadline got status %d, want timeout", code)
	}
	deadline, code := registry.open(time.Nanosecond)
	if code != 0 {
		t.Fatal("short bounded deadline refused")
	}
	ctx := registry.context(deadline)
	select {
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatalf("deadline context ended with %v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("helper deadline did not reach Go context")
	}
	registry.cancel(deadline, true)
}
