package secp256k1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The actual fast table traversal consumes and clears the named encoding while
// retaining the known public generator result. No new multiplication algorithm.
func TestBaseMultiplyEncodingCleanup(t *testing.T) {
	var raw [32]byte
	raw[31] = 1
	var got, want JacobianPoint
	scalarBaseMultFastWithBytes(&raw, &got)
	if raw != ([32]byte{}) {
		t.Fatal("base multiply scalar encoding remains after return")
	}
	encoded, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	public, err := ParsePubKey(encoded)
	if err != nil {
		t.Fatal("invalid public generator fixture")
	}
	public.AsJacobian(&want)
	if !got.EquivalentNonConst(&want) {
		t.Fatal("base multiply positive control changed")
	}
}

// Both retained RFC6979 retry paths clear their named key, V/K and HMAC pad
// buffers; the returned nonce remains usable and transfers to the caller.
func TestNonceBufferLifecycle(t *testing.T) {
	for _, retry := range []uint32{0, 1, 5} {
		var b nonceBuffers
		key := make([]byte, 32)
		key[31] = 3
		nonce := nonceRFC6979WithBuffers(key, make([]byte, 32), nil, nil, retry, &b)
		if nonce.IsZero() {
			t.Fatal("valid nonce control failed")
		}
		nonce.Zero()
		if b.hasher == nil || len(b.v) != 32 || len(b.k) != 32 {
			t.Fatal("nonce buffers were not exercised")
		}
		if b.key != ([112]byte{}) {
			t.Fatal("RFC6979 key encoding remains after return")
		}
		for _, raw := range [][]byte{b.v, b.k, b.hasher.ipad[:], b.hasher.opad[:]} {
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("RFC6979 reconstructible buffer remains after return")
			}
		}
	}
}

// Replaced HMAC outputs are erased before losing ownership of their storage.
func TestNonceBufferReplacement(t *testing.T) {
	oldV, oldK := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	b := nonceBuffers{v: oldV, k: oldK}
	b.replaceV(make([]byte, 32))
	b.replaceK(make([]byte, 32))
	if !bytes.Equal(oldV, make([]byte, 32)) || !bytes.Equal(oldK, make([]byte, 32)) {
		t.Fatal("replaced nonce buffer was not cleared")
	}
	b.clear()
}

// Serialization transfers its byte buffer while erasing the value-receiver's
// full private-key copy. The borrowed original key retains its caller ownership.
func TestPrivateSerializationCopyCleanup(t *testing.T) {
	key := PrivKeyFromBytes([]byte{3})
	defer key.Zero()
	working := *key
	encoded := serializePrivateCopy(&working)
	if !working.Key.IsZero() {
		t.Fatal("serialization receiver copy remains after return")
	}
	if len(encoded) != 32 || encoded[31] != 3 || key.Key.IsZero() {
		t.Fatal("serialization positive control or caller ownership changed")
	}
	zeroBytes(encoded)
}
