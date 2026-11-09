// Use of this source code is governed by the ISC license in ../LICENSE.

package schnorr

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
)

// signingBuffers owns the named mutable secrets used by Sign. Keeping their
// storage explicit permits lifecycle tests without a production observer hook.
// This does not erase compiler copies or arithmetic/hash implementation state.
type signingBuffers struct {
	private, nonce, effectiveNonce, response btcec.ModNScalar
	privateBytes, rfcPrivateBytes            [32]byte
	t, rand                                  *chainhash.Hash
	aux                                      *[32]byte
	rfcNonce                                 *btcec.ModNScalar
}

func (b *signingBuffers) clear() {
	b.private.Zero()
	b.nonce.Zero()
	b.effectiveNonce.Zero()
	b.response.Zero()
	clear(b.privateBytes[:])
	clear(b.rfcPrivateBytes[:])
	if b.t != nil {
		clear(b.t[:])
	}
	if b.rand != nil {
		clear(b.rand[:])
	}
	if b.aux != nil {
		clear(b.aux[:])
	}
	if b.rfcNonce != nil {
		b.rfcNonce.Zero()
	}
}
