package keyvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func rootGrantsContextError(ctx context.Context) error {
	if ctx == nil {
		return recoveryRefuse("invalid_arguments")
	}
	if ctx.Err() == context.DeadlineExceeded {
		return recoveryRefuse("timeout")
	}
	if ctx.Err() != nil {
		return recoveryRefuse("canceled")
	}
	return nil
}

// sealRootGrantsPrepared is PRIVATE helper/linked-engine code. It consumes the
// opaque preparation on every exit and returns sealed representation only.
// Public point/blob shape does NOT establish enclave, presence, code admission
// or wrapping-key qualification. Those remain required native dependencies.
func sealRootGrantsPrepared(ctx context.Context, prepared *rootGrantsPrepared, r RootGrantsRecord, blob []byte) (RootGrantsEnvelope, error) {
	return sealRootGrantsWithRandom(ctx, prepared, r, blob, rand.Reader)
}

// Random injection is private primitive-test scope, never a public/production
// option or a software custody fallback. No secret callback/getter is exposed.
func sealRootGrantsWithRandom(ctx context.Context, prepared *rootGrantsPrepared, r RootGrantsRecord, blob []byte, random io.Reader) (RootGrantsEnvelope, error) {
	var empty RootGrantsEnvelope
	defer prepared.clear()
	if err := rootGrantsContextError(ctx); err != nil {
		return empty, err
	}
	if len(blob) < 1 || len(blob) > 16384 || random == nil {
		return empty, recoveryRefuse("invalid_envelope")
	}
	blob = bytes.Clone(blob)
	defer clear(blob)
	r.WrappingPoint = bytes.Clone(r.WrappingPoint)
	if _, err := CanonicalRootGrantsRecord(r); err != nil {
		return empty, recoveryRefuse("invalid_arguments")
	}
	view, err := prepared.publicView()
	if err != nil || view.Root != r.publicRoot() || view.Pair != r.Pair {
		return empty, recoveryRefuse("public_pin_mismatch")
	}
	plain, err := prepared.rootGrantsPlaintext(r)
	if err != nil {
		return empty, err
	}
	defer plain.clear()
	peer, err := ecdh.P256().NewPublicKey(r.WrappingPoint)
	if err != nil {
		return empty, recoveryRefuse("invalid_envelope")
	}
	if err := rootGrantsContextError(ctx); err != nil {
		return empty, err
	}
	var ephemeralScalar [32]byte
	defer clear(ephemeralScalar[:])
	if _, err := io.ReadFull(random, ephemeralScalar[:]); err != nil {
		return empty, recoveryRefuse("private_protocol_error")
	}
	if err := rootGrantsContextError(ctx); err != nil {
		return empty, err
	}
	// Uniform random bytes; an invalid P256 exponent refuses without retry.
	// The opaque ecdh object has no universal explicit clearing guarantee.
	ephemeral, err := ecdh.P256().NewPrivateKey(ephemeralScalar[:])
	clear(ephemeralScalar[:])
	if err != nil {
		return empty, recoveryRefuse("invalid_derivation")
	}
	shared, err := ephemeral.ECDH(peer)
	if err != nil {
		return empty, recoveryRefuse("invalid_envelope")
	}
	defer clear(shared)
	point := ephemeral.PublicKey().Bytes()
	// The existing recovery ECIES primitive's single X9.63 block, not HKDF:
	// SHA256(Z || big-endian counter1 || ephemeral uncompressed point).
	material := make([]byte, 0, len(shared)+4+len(point))
	defer func() { clear(material) }()
	material = append(material, shared...)
	material = append(material, 0, 0, 0, 1)
	material = append(material, point...)
	derived := sha256.Sum256(material)
	defer clear(derived[:])
	clear(shared)
	clear(material)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return empty, recoveryRefuse("private_protocol_error")
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return empty, recoveryRefuse("private_protocol_error")
	}
	if err := rootGrantsContextError(ctx); err != nil {
		return empty, err
	}
	wire := gcm.Seal(bytes.Clone(point), derived[16:], plain.buffer[:], nil)
	defer clear(wire)
	plain.clear()
	prepared.clear()
	if err := rootGrantsContextError(ctx); err != nil {
		return empty, err
	}
	e := RootGrantsEnvelope{Schema: "keyvault-root-grants-ciphertext/1", Algorithm: recoveryAlgorithm,
		EnclaveBlob: bytes.Clone(blob), Point: bytes.Clone(r.WrappingPoint), Fingerprint: r.WrappingFingerprint, Ciphertext: bytes.Clone(wire)}
	if _, err := CanonicalRootGrantsEnvelope(e, r); err != nil {
		clear(e.EnclaveBlob)
		clear(e.Ciphertext)
		return empty, recoveryRefuse("invalid_envelope")
	}
	if err := rootGrantsContextError(ctx); err != nil {
		clear(e.EnclaveBlob)
		clear(e.Ciphertext)
		return empty, err
	}
	return e, nil
}
