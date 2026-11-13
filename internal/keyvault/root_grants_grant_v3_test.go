package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const grantV3TestK = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
const grantV3TestBytes = `{"version":3}`
const grantV3TestSignature = "bd588351823cfd8a881dc6557f0bef11715ed855db56a744c74db9085793555bde216774c8498cd264b80f8d83e58947cf4d0dc993d2749c5dbd8ac5daaa62a7"

// Byte vectors are deliberately NOT valid complete grants. Python hashlib and
// shasum independently pin the ordinary prefixed SHA-256 construction. They do
// not qualify the still unavailable canonical grant/contract/consent parser.
func TestRootGrantsGrantV3DigestVectors(t *testing.T) {
	vectors := []struct {
		name, input, digest string
	}{
		{"empty-object-bytes", `{}`, "409cc307b8478263778672c811a843b368a91cc140fadce822d4f12d1cfbc5e8"},
		{"version-bytes", grantV3TestBytes, "67bce1d8e931e588627810b64d4eb847e2af55fc4291483c495b74f3ad85935e"},
		{"nul-byte-is-not-dropped", "\x00", "1f91884d4ca9219a0c55fc09641eeb13fd6ac1fec156f36de26ed300ed34753e"},
		{"lf-byte-is-not-trimmed", grantV3TestBytes + "\n", "d1c7fdc68d0fb88d6c2fe78ce625eb489eac68b0f5fee7e7430f93473ed174a0"},
		{"inclusive-byte-limit", strings.Repeat("x", 65536), "6165d60229d5e35dca5aaa97089030bd2d6a054d99cc8f3d9c2e8c17d2fb307c"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			input := []byte(v.input)
			before := bytes.Clone(input)
			got, err := rootGrantsGrantV3Digest(input)
			if err != nil || hex.EncodeToString(got[:]) != v.digest || !bytes.Equal(input, before) {
				t.Fatalf("wrong digest or input changed: digest=%x err=%v", got, err)
			}
		})
	}
	// Refusals return no digest and preserve caller-owned input.
	for _, input := range [][]byte{nil, {}, bytes.Repeat([]byte{'x'}, 65537)} {
		before := bytes.Clone(input)
		got, err := rootGrantsGrantV3Digest(input)
		code := "invalid_arguments"
		if len(input) > 65536 {
			code = "limit_exceeded"
		}
		rootGrantsWantRefusal(t, err, code)
		if got != ([32]byte{}) || !bytes.Equal(input, before) {
			t.Fatal("refusal returned a digest or changed input")
		}
	}
}

// This independently calculated BIP-340 signature uses PUBLIC test scalar 3,
// zero auxiliary randomness and the pinned message above. The one-off arithmetic
// was first checked against official vector 0 in testdata/nostr/bip340.csv.
// That grounds the primitive; it is not a canonical-grant interoperability vector.
func TestRootGrantsGrantV3VerifyVector(t *testing.T) {
	input := []byte(grantV3TestBytes)
	sig := nostrTestHex(t, grantV3TestSignature)
	before, signatureBefore := bytes.Clone(input), bytes.Clone(sig)
	if err := rootGrantsVerifyGrantV3(input, grantV3TestK, sig); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, before) || !bytes.Equal(sig, signatureBefore) {
		t.Fatal("verification changed public input")
	}
	// A changed grant, appended LF/NUL, whitespace or trailing document must not
	// verify as the original bytes. Semantic/canonical parsing is a separate gate.
	for _, changed := range []string{`{"version":4}`, grantV3TestBytes + "\n", grantV3TestBytes + "\x00", " " + grantV3TestBytes, grantV3TestBytes + `{}`} {
		rootGrantsWantRefusal(t, rootGrantsVerifyGrantV3([]byte(changed), grantV3TestK, sig), "signature_verification_failed")
	}
}

// Each wrong-domain signature is valid BIP-340 for its OWN message, yet refuses
// the grant scheme. This kills omission, separators, tagged/double outer hash
// and hex-text-as-message shortcuts without relying on a damaged signature.
func TestRootGrantsGrantV3WrongDomains(t *testing.T) {
	input := []byte(grantV3TestBytes)
	exact, err := rootGrantsGrantV3Digest(input)
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte(rootGrantsGrantV3Domain)
	joined := append(bytes.Clone(prefix), input...)
	tag := sha256.Sum256(prefix)
	tagged := append(append(bytes.Clone(tag[:]), tag[:]...), input...)
	// A 32-byte SHA-256 of ASCII hex models a signer that hashes a digest's
	// textual spelling. The proper operation passes the raw 32-byte digest once.
	messages := []struct {
		name   string
		digest [32]byte
	}{
		{"unprefixed", sha256.Sum256(input)},
		{"double-outer-hash", sha256.Sum256(exact[:])},
		{"lf-separator", sha256.Sum256(append(append(bytes.Clone(prefix), '\n'), input...))},
		{"nul-separator", sha256.Sum256(append(append(bytes.Clone(prefix), 0), input...))},
		{"length-separator", sha256.Sum256(append(append(bytes.Clone(prefix), byte(len(input))), input...))},
		{"trailing-lf", sha256.Sum256(append(bytes.Clone(joined), '\n'))},
		{"tagged-outer-hash", sha256.Sum256(tagged)},
		{"hash-of-hex-text", sha256.Sum256([]byte(hex.EncodeToString(exact[:])))},
		{"wrong-version-domain", sha256.Sum256([]byte("swarma-grant-v4" + grantV3TestBytes))},
	}
	for _, m := range messages {
		t.Run(m.name, func(t *testing.T) {
			secret := make([]byte, 32)
			secret[31] = 3 // Published fixture only; never a product scalar source.
			defer clear(secret)
			sig, err := signNostrWithAux(secret, m.digest[:], [32]byte{})
			if err != nil || VerifyNostr(nostrTestHex(t, grantV3TestK), m.digest[:], sig) != nil {
				t.Fatal("wrong-domain negative control is not independently valid")
			}
			rootGrantsWantRefusal(t, rootGrantsVerifyGrantV3(input, grantV3TestK, sig), "signature_verification_failed")
		})
	}
}

// Wrong or malformed pins, non-raw signatures, altered signatures and bad size
// return only closed refusal codes and leave the public caller buffers intact.
func TestRootGrantsGrantV3VerificationRefusals(t *testing.T) {
	valid := nostrTestHex(t, grantV3TestSignature)
	broken := bytes.Clone(valid)
	broken[0] ^= 1
	cases := []struct {
		name, key, code string
		input, sig      []byte
	}{
		{"missing-key", "", "public_pin_mismatch", []byte(grantV3TestBytes), valid},
		{"uppercase-key", strings.ToUpper(grantV3TestK), "public_pin_mismatch", []byte(grantV3TestBytes), valid},
		{"compressed-key", "02" + grantV3TestK, "public_pin_mismatch", []byte(grantV3TestBytes), valid},
		{"invalid-point", strings.Repeat("f", 64), "public_pin_mismatch", []byte(grantV3TestBytes), valid},
		{"wrong-valid-key", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "signature_verification_failed", []byte(grantV3TestBytes), valid},
		{"missing-signature", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), nil},
		{"short-signature", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), valid[:63]},
		{"sighash-byte", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), append(bytes.Clone(valid), 1)},
		{"hex-as-bytes", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), []byte(grantV3TestSignature)},
		{"altered-signature", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), broken},
		{"scalar-overflow", grantV3TestK, "signature_verification_failed", []byte(grantV3TestBytes), bytes.Repeat([]byte{255}, 64)},
		{"empty-input", grantV3TestK, "invalid_arguments", nil, valid},
		{"over-limit", grantV3TestK, "limit_exceeded", bytes.Repeat([]byte{'x'}, 65537), valid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inputBefore, sigBefore := bytes.Clone(c.input), bytes.Clone(c.sig)
			rootGrantsWantRefusal(t, rootGrantsVerifyGrantV3(c.input, c.key, c.sig), c.code)
			if !bytes.Equal(inputBefore, c.input) || !bytes.Equal(sigBefore, c.sig) {
				t.Fatal("refusal changed public input")
			}
		})
	}
}
