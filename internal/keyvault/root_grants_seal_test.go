package keyvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"
)

// Public synthetic P256 exponents3 (recipient) and4 (ephemeral). Captures the
// primitive's owned random buffer so tests can check logical clearing only.
type rootGrantsRandom28 struct {
	calls    int
	observed []byte
	fail     bool
	zero     bool
	cancel   context.CancelFunc
}

func (r *rootGrantsRandom28) Read(out []byte) (int, error) {
	r.calls++
	r.observed = out
	clear(out)
	if len(out) != 32 {
		return 0, errors.New("SYNTHETIC_DIAGNOSTIC_28")
	}
	if !r.zero {
		out[31] = 4
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.fail {
		return 0, errors.New("SYNTHETIC_DIAGNOSTIC_28")
	}
	return len(out), nil
}

// Independent TEST ONLY ECIES primitive, not a product unwrap/export endpoint.
// Standard AES-GCM, SHA256 and P256 still share libraries with production; the
// protected published/qualified primitive fixtures remain independent anchors.
func rootGrantsOpen28(e RootGrantsEnvelope, r RootGrantsRecord, recipient byte) (*rootGrantsPlaintext, error) {
	if _, err := CanonicalRootGrantsEnvelope(e, r); err != nil {
		return nil, err
	}
	var scalar [32]byte
	scalar[31] = recipient
	defer clear(scalar[:])
	private, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(e.Ciphertext[:65])
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	input := make([]byte, 0, len(shared)+4+65)
	input = append(input, shared...)
	input = append(input, 0, 0, 0, 1)
	input = append(input, e.Ciphertext[:65]...)
	defer clear(input)
	key := sha256.Sum256(input)
	defer clear(key[:])
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	opened, err := gcm.Open(nil, key[16:], e.Ciphertext[65:], nil)
	defer clear(opened)
	if err != nil || len(opened) != 68 {
		return nil, errors.New("synthetic envelope refused")
	}
	plain := &rootGrantsPlaintext{buffer: new([68]byte)}
	copy(plain.buffer[:], opened)
	if err := plain.validate(r); err != nil {
		plain.clear()
		return nil, err
	}
	return plain, nil
}

func rootGrantsSealFrame28(t *testing.T, frame []byte, r RootGrantsRecord) RootGrantsEnvelope {
	t.Helper()
	var scalar [32]byte
	scalar[31] = 4
	private, err := ecdh.P256().NewPrivateKey(scalar[:])
	clear(scalar[:])
	if err != nil {
		t.Fatal("synthetic ephemeral fixture invalid")
	}
	peer, err := ecdh.P256().NewPublicKey(r.WrappingPoint)
	if err != nil {
		t.Fatal("synthetic recipient fixture invalid")
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		t.Fatal("synthetic agreement invalid")
	}
	defer clear(shared)
	point := private.PublicKey().Bytes()
	input := make([]byte, 0, len(shared)+4+len(point))
	input = append(input, shared...)
	input = append(input, 0, 0, 0, 1)
	input = append(input, point...)
	defer clear(input)
	key := sha256.Sum256(input)
	defer clear(key[:])
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		t.Fatal("synthetic AES unavailable")
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal("synthetic GCM unavailable")
	}
	return RootGrantsEnvelope{Schema: "keyvault-root-grants-ciphertext/1", Algorithm: recoveryAlgorithm, EnclaveBlob: []byte{1},
		Point: bytes.Clone(r.WrappingPoint), Fingerprint: r.WrappingFingerprint, Ciphertext: gcm.Seal(bytes.Clone(point), key[16:], frame, nil)}
}

// Claim: real software seal of published scalar3 to public synthetic P2563
// opens independently to exact KVG1/full-metadata hash/scalar,149-byte wire and
// existing algorithm. All owned preparation/random input is logically cleared.
// Limits: shared crypto libraries, no native wrap/TouchID/ACL or custody claim.
func TestRootGrantsSeal28RoundTrip(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	p := rootGrantsPrivateFixture13(t, r)
	alias := *p
	random := &rootGrantsRandom28{}
	e, err := sealRootGrantsWithRandom(context.Background(), p, r, []byte{1}, random)
	if err != nil || random.calls != 1 || len(e.Ciphertext) != 149 || e.Algorithm != recoveryAlgorithm {
		t.Fatal("synthetic software seal failed")
	}
	defer clear(e.Ciphertext)
	if *alias.state.scalar != [32]byte{} || alias.state.ready || !bytes.Equal(random.observed, make([]byte, 32)) {
		t.Fatal("seal retained owned preparation/random bytes")
	}
	plain, err := rootGrantsOpen28(e, r, 3)
	if err != nil {
		t.Fatal("independent synthetic open failed")
	}
	defer plain.clear()
	metadata := rootGrantsRaw13(t, r)
	hash := sha256.Sum256(append([]byte("keyvault-root-grants/plaintext/1\x00"), metadata...))
	var expected [68]byte
	defer clear(expected[:])
	copy(expected[:4], "KVG1")
	copy(expected[4:36], hash[:])
	expected[67] = 3
	if *plain.buffer != expected {
		t.Fatal("independent KVG1/public metadata binding mismatch")
	}
}

// Claim: invalid record/pins/parity/blob and cancellation refuse before random;
// random failure/invalid exponent/cancel during entropy return no envelope and
// clear preparation/random buffer. No caller/OS diagnostic is propagated.
// Limits: no native wrap effect exists here; actual runtime erasure unproven.
func TestRootGrantsSeal28Refusals(t *testing.T) {
	for _, mode := range []string{"nil-prepared", "path", "pair", "point", "parity", "private-parity", "private-zero", "blob", "canceled", "random-error", "random-zero", "random-cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/1")
			p := rootGrantsPrivateFixture13(t, r)
			owned := p
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			random, blob := &rootGrantsRandom28{}, []byte{1}
			wantCalls := 0
			switch mode {
			case "nil-prepared":
				p.clear()
				p = nil
			case "path":
				r.Path = "m/83696968h/2h/0h"
			case "pair":
				r.Pair.Version++
			case "point":
				r.WrappingPoint = make([]byte, 65)
			case "parity":
				r.SealPublicKey = "03" + r.PublicKey
			case "private-parity":
				n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
				new(big.Int).Sub(n, big.NewInt(3)).FillBytes(p.state.scalar[:])
			case "private-zero":
				clear(p.state.scalar[:])
			case "blob":
				blob = nil
			case "canceled":
				cancel()
			case "random-error":
				random.fail, wantCalls = true, 1
			case "random-zero":
				random.zero, wantCalls = true, 1
			case "random-cancel":
				random.cancel, wantCalls = cancel, 1
			}
			e, err := sealRootGrantsWithRandom(ctx, p, r, blob, random)
			if err == nil || !reflect.DeepEqual(e, RootGrantsEnvelope{}) || random.calls != wantCalls || *owned.state.scalar != [32]byte{} || owned.state.ready {
				t.Fatal("seal refusal produced output/random effect or retained private state")
			}
			for _, b := range random.observed {
				if b != 0 {
					t.Fatal("random input survived refusal")
				}
			}
			encoded, _ := json.Marshal(err)
			if bytes.Contains(encoded, []byte("SYNTHETIC_DIAGNOSTIC_28")) {
				t.Fatal("raw random diagnostic escaped")
			}
		})
	}
}

// Claim: paired valid envelope opens, while wrong recipient, record/domain,
// ciphertext/tag, scalar range or odd/even-but-wrong K refuse in the relevant
// parser/GCM/private checker. Limits: test-only open, no product decrypt API.
func TestRootGrantsSeal28Tampering(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	p := rootGrantsPrivateFixture13(t, r)
	e, err := sealRootGrantsWithRandom(context.Background(), p, r, []byte{1}, &rootGrantsRandom28{})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := rootGrantsOpen28(e, r, 3)
	if err != nil {
		t.Fatal("paired valid envelope failed")
	}
	defer valid.clear()
	for _, mode := range []string{"recipient", "record", "point", "ciphertext", "tag"} {
		bad := rootGrantsCloneEnvelope13(t, e)
		record := rootGrantsCloneRecord13(t, r)
		recipient := byte(3)
		switch mode {
		case "recipient":
			recipient = 2
		case "record":
			record.Version++
		case "point":
			clear(bad.Ciphertext[:65])
		case "ciphertext":
			bad.Ciphertext[65] ^= 1
		case "tag":
			bad.Ciphertext[148] ^= 1
		}
		opened, err := rootGrantsOpen28(bad, record, recipient)
		if err == nil || opened != nil {
			t.Fatal("tampered envelope opened")
		}
	}
	n := new(big.Int).SetBytes(rootGrantsTestHex(t, rootGrantsCurveOrder))
	for _, scalar := range []*big.Int{big.NewInt(0), n, new(big.Int).Sub(n, big.NewInt(3)), big.NewInt(1)} {
		var frame [68]byte
		frame = *valid.buffer
		scalar.FillBytes(frame[36:])
		bad := rootGrantsSealFrame28(t, frame[:], r)
		clear(frame[:])
		opened, err := rootGrantsOpen28(bad, r, 3)
		if err == nil || opened != nil {
			t.Fatal("wrong range/parity/public correspondence opened")
		}
	}
}
