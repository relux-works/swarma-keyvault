//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The actual isolated receipt reservation permits one consume, retaining the
// immutable pending audit. A changed reservation latches refusal permanently;
// restoring bytes cannot revive the capability. No native item is touched.
func TestCreationReservationOnceAndTamperLatch(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		r, dir := receiptFixture(t)
		if err := r.reservePending(); err != nil {
			t.Fatal(err)
		}
		capability := &CreationReservation{files: r}
		path := filepath.Join(dir, pendingName)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if tamper {
			if err := os.WriteFile(path, []byte("truncated"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		err = capability.ConsumeForNativeCreate()
		if tamper {
			if !errors.Is(err, ErrProtocol) {
				t.Fatal("changed pending consumed")
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(capability.ConsumeForNativeCreate(), ErrProtocol) {
			t.Fatal("reservation revived")
		}
		if err := capability.Close(); err != nil {
			t.Fatal(err)
		}
		if err := capability.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(capability.ConsumeForNativeCreate(), ErrProtocol) {
			t.Fatal("closed reservation consumed")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("pending audit removed/changed")
		}
		if _, err := os.Lstat(filepath.Join(dir, createdName)); !os.IsNotExist(err) {
			t.Fatal("consume published receipt")
		}
	}
	var nilReservation *CreationReservation
	if !errors.Is(nilReservation.ConsumeForNativeCreate(), ErrProtocol) {
		t.Fatal("nil reservation admitted")
	}
	if !errors.Is((&CreationReservation{}).ConsumeForNativeCreate(), ErrProtocol) {
		t.Fatal("fabricated zero reservation admitted")
	}
	r, _ := receiptFixture(t)
	if err := r.reservePending(); err != nil {
		t.Fatal(err)
	}
	c := &CreationReservation{files: r}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.ConsumeForNativeCreate(), ErrProtocol) {
		t.Fatal("closed-before-use reservation admitted")
	}
}

// Clear erases the owned byte backing, invalidates copied handles, preserves
// independent caller buffers and refuses serialization after release. This
// does not assert erasure of Go's immutable/runtime JSON string copies.
func TestRequestClearOwnership(t *testing.T) {
	input := []byte{1, 2, 3}
	r, err := NewRequest(input, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := r
	backing := r.data.reference
	clone := r.Reference()
	r.Clear()
	r.Clear()
	if !bytes.Equal(backing, []byte{0, 0, 0}) {
		t.Fatal("owned bytes not cleared")
	}
	if copyHandle.Reference() != nil || copyHandle.ReceiptSHA256() != "" {
		t.Fatal("copied handle retained released data")
	}
	if !bytes.Equal(input, []byte{1, 2, 3}) || !bytes.Equal(clone, input) {
		t.Fatal("independent input/clone changed")
	}
	var output bytes.Buffer
	if !errors.Is(WriteRequest(&output, copyHandle), ErrProtocol) || output.Len() != 0 {
		t.Fatal("released handle serialized")
	}
	var absent *Request
	absent.Clear()
	var zero Request
	zero.Clear()
	if zero.Reference() != nil || zero.ReceiptSHA256() != "" {
		t.Fatal("zero request has data")
	}
}
