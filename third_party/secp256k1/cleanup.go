// Use of this source code is governed by the ISC license in LICENSE.

package secp256k1

// nonceBuffers owns the RFC6979 byte encodings and reconstructible HMAC state.
// Hash implementation internals and compiler temporaries remain outside this
// explicit-buffer guarantee. A returned scalar transfers to its caller.
type nonceBuffers struct {
	key    [112]byte
	v, k   []byte
	hasher *hmacsha256
}

func (b *nonceBuffers) replaceV(next []byte) { zeroBytes(b.v); b.v = next }
func (b *nonceBuffers) replaceK(next []byte) { zeroBytes(b.k); b.k = next }

func (b *nonceBuffers) clear() {
	zeroBytes(b.key[:])
	zeroBytes(b.v)
	zeroBytes(b.k)
	if b.hasher != nil {
		zeroBytes(b.hasher.ipad[:])
		zeroBytes(b.hasher.opad[:])
		b.hasher.inner.Reset()
		b.hasher.outer.Reset()
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
