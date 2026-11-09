package chainhash

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The actual TaggedHash h.Sum slice is zero after its copied output returns.
// Independent pinned BIP-340 reference outputs use public synthetic messages,
// covering cached and uncached tags; they are not live signing material.
func TestTaggedHashOwnedDigestCleanup(t *testing.T) {
	for _, fixture := range []struct{ tag, want string }{
		{"BIP0340/nonce", "c42f0d87958bdf3420005b274fff883e533de97e34a42e1a252884e14fa53dee"},
		{"BIP0340/aux", "d3c7826b9711c8979958cf4d07d332eaf5b31dbe74aa43c6ac32dd3ad617fcb1"},
		{"public-fixture", "5a7b244777625696416f9b7ca8bd75dd37d8969aee9bbec0f54969f61e6860eb"},
	} {
		t.Run(fixture.tag, func(t *testing.T) {
			var buffers taggedHashBuffers
			got := taggedHashWithBuffers(&buffers, []byte(fixture.tag), []byte("public"), nil, []byte("-fixture"))
			if got == nil || hex.EncodeToString(got[:]) != fixture.want {
				t.Fatal("independent tagged-hash positive control changed")
			}
			if len(buffers.digest) != 32 || !bytes.Equal(buffers.digest, make([]byte, 32)) {
				t.Fatal("actual helper-owned completed digest remains after return")
			}
		})
	}
}

// The same owning conversion clears its real input on NewHash's size refusal,
// returns no partial Hash, and preserves a valid neighbor. Standard SHA-256
// always supplies 32 bytes; the short conversion is not claimed as a naturally
// reachable TaggedHash refusal.
func TestTaggedHashCopyRefusalCleanup(t *testing.T) {
	for _, length := range []int{31, 32, 33} {
		buffers := taggedHashBuffers{digest: bytes.Repeat([]byte{1}, length)}
		got, err := buffers.copyHash()
		if length == 32 {
			if err != nil || got == nil || got[0] != 1 || got[31] != 1 {
				t.Fatal("owned hash copy positive control failed")
			}
		} else if err == nil || got != nil || !strings.Contains(err.Error(), "invalid hash length") {
			t.Fatal("owned hash copy returned wrong size refusal or partial output")
		}
		if !bytes.Equal(buffers.digest, make([]byte, length)) {
			t.Fatal("helper-owned conversion digest remains after return")
		}
	}
}
