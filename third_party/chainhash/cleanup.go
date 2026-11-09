// Use of this source code is governed by the ISC license in LICENSE.

package chainhash

// This owner retains the actual completed h.Sum allocation until its copy is
// made. The returned Hash transfers to the caller; SHA internals are outside
// this explicit mutable-buffer contract.
type taggedHashBuffers struct {
	digest []byte
}

func (b *taggedHashBuffers) copyHash() (*Hash, error) {
	defer clear(b.digest)
	return NewHash(b.digest)
}
