package schnorr

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	secpSchnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

func assertSigningBuffersCleared(t *testing.T, b *signingBuffers) {
	t.Helper()
	for _, s := range []*btcec.ModNScalar{&b.private, &b.nonce, &b.effectiveNonce, &b.response} {
		if !s.IsZero() {
			t.Fatal("owned signer scalar remains after return")
		}
	}
	for _, raw := range [][]byte{b.privateBytes[:], b.rfcPrivateBytes[:]} {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("owned signer bytes remain after return")
		}
	}
	for _, raw := range []*[32]byte{(*[32]byte)(b.t), (*[32]byte)(b.rand), b.aux} {
		if raw != nil && *raw != ([32]byte{}) {
			t.Fatal("owned nonce or auxiliary bytes remain after return")
		}
	}
	if b.rfcNonce != nil && !b.rfcNonce.IsZero() {
		t.Fatal("owned RFC6979 scalar remains after return")
	}
}

// These inspect the actual storage consumed by both production signing paths,
// including successful signing and early refusals. They do not inspect stacks,
// registers or internal hash arithmetic. Scalar 3 is a public test input.
func TestSigningBufferLifecycle(t *testing.T) {
	for _, nonce := range []bool{false, true} {
		for _, bad := range []string{"", "digest", "private"} {
			t.Run(map[bool]string{false: "rfc6979", true: "aux"}[nonce]+"/"+bad, func(t *testing.T) {
				key, _ := btcec.PrivKeyFromBytes([]byte{3})
				defer key.Zero()
				if bad == "private" {
					key.Zero()
				}
				msg := make([]byte, 32)
				if bad == "digest" {
					msg = msg[:31]
				}
				var options []SignOption
				if nonce {
					options = append(options, CustomNonce([32]byte{1}))
				}
				var b signingBuffers
				sig, err := signWithBuffers(key, msg, &b, options...)
				if bad == "" {
					if err != nil || !sig.Verify(msg, key.PubKey()) {
						t.Fatal("valid signing control failed")
					}
					if nonce && (b.t == nil || b.rand == nil || b.aux == nil) {
						t.Fatal("aux path did not exercise owned buffers")
					}
					if !nonce && b.rfcNonce == nil {
						t.Fatal("RFC6979 path did not exercise owned nonce")
					}
				} else if err == nil || sig != nil {
					t.Fatal("invalid signing input accepted")
				} else if bad == "digest" && !errors.Is(err, secpSchnorr.ErrInvalidHashLen) {
					t.Fatal("malformed digest returned the wrong refusal")
				} else if bad == "private" && !errors.Is(err, secpSchnorr.ErrPrivateKeyIsZero) {
					t.Fatal("zero private scalar returned the wrong refusal")
				}
				assertSigningBuffersCleared(t, &b)
			})
		}
	}
}

// Fresh options work; reuse explicitly refuses instead of silently using erased
// auxiliary input. Concurrent reuse grants one invocation and has no data race.
func TestCustomNonceConsumption(t *testing.T) {
	key, _ := btcec.PrivKeyFromBytes([]byte{3})
	defer key.Zero()
	option := CustomNonce([32]byte{1})
	var wg sync.WaitGroup
	type result struct {
		sig *Signature
		err error
	}
	verdicts := make(chan result, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := Sign(key, make([]byte, 32), option)
			verdicts <- result{sig, err}
		}()
	}
	wg.Wait()
	close(verdicts)
	accepted := 0
	for r := range verdicts {
		if r.err == nil && r.sig != nil && r.sig.Verify(make([]byte, 32), key.PubKey()) {
			accepted++
		} else if r.err == nil || r.err.Error() != "auxiliary nonce option already consumed" || r.sig != nil {
			t.Fatal("concurrent reuse returned the wrong refusal or signature")
		}
	}
	if accepted != 1 {
		t.Fatal("auxiliary option did not admit exactly one call")
	}
	if sig, err := Sign(key, make([]byte, 32), option); err == nil || err.Error() != "auxiliary nonce option already consumed" || sig != nil {
		t.Fatal("consumed auxiliary option accepted")
	}
	if sig, err := Sign(key, make([]byte, 32), CustomNonce([32]byte{1})); err != nil || sig == nil {
		t.Fatal("fresh auxiliary option refused")
	}
}

// Selecting the last fresh option erases the overwritten option's actual
// captured storage. The signature remains the official zero-aux vector.
func TestCustomNonceOverwriteCleanup(t *testing.T) {
	key, _ := btcec.PrivKeyFromBytes([]byte{3})
	defer key.Zero()
	var overwritten *[32]byte
	capture := func(o *signOptions) { overwritten = o.authNonce }
	sig, err := Sign(key, make([]byte, 32), CustomNonce([32]byte{1}), capture, CustomNonce([32]byte{}))
	if err != nil || sig == nil || !sig.Verify(make([]byte, 32), key.PubKey()) {
		t.Fatal("last fresh auxiliary option control failed")
	}
	if hex.EncodeToString(sig.Serialize()) != "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0" {
		t.Fatal("last auxiliary option did not select official zero-aux vector")
	}
	if overwritten == nil || *overwritten != ([32]byte{}) {
		t.Fatal("overwritten auxiliary option not cleared")
	}
}
