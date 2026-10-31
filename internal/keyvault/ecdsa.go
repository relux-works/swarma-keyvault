package keyvault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"math/big"
)

// DigestSize is the only digest length ecdsa-sha256-sign and -verify take:
// the caller supplies a SHA-256 digest; the vault hashes bytes itself only
// when it is asked to (--data-file / --stdin), and then says so.
const DigestSize = 32

// RawSignatureSize is r||s of a P-256 signature, 32 bytes each.
const RawSignatureSize = 64

// Error-contract codes of the sign/verify paths.
const (
	CodeInvalidDigest    = signerclient.CodeInvalidDigest
	CodeInvalidSignature = signerclient.CodeInvalidSignature
	CodeSignatureInvalid = signerclient.CodeSignatureInvalid
	CodeHighSRefused     = signerclient.CodeHighSRefused
	CodeUsageRefused     = signerclient.CodeUsageRefused
	CodeExpired          = signerclient.CodeExpired
	CodeInvalidPublicKey = signerclient.CodeInvalidPublicKey
)

// ValidateDigest refuses anything but exactly DigestSize bytes. It is the
// first gate of sign and verify and runs before the address is resolved, so
// no Security call happens for a mis-sized digest.
func ValidateDigest(digest []byte) error {
	if len(digest) != DigestSize {
		return &Refusal{Code: CodeInvalidDigest, Message: fmt.Sprintf("digest is %d bytes; ecdsa-sha256 takes exactly a %d-byte SHA-256 digest", len(digest), DigestSize), Hint: "pass --digest <64 hex chars|@file with 32 bytes>, or let the tool hash with --data-file FILE / --stdin; nothing was signed"}
	}
	return nil
}

// Signature is one ECDSA signature as its two integers.
type Signature struct {
	R, S *big.Int
}

// ecdsaSignatureASN1 is the X9.62 SEQUENCE { r INTEGER, s INTEGER }.
type ecdsaSignatureASN1 struct {
	R, S *big.Int
}

var p256Order = elliptic.P256().Params().N
var p256HalfOrder = new(big.Int).Rsh(p256Order, 1)

// ParseSignature decodes DER (ecdsa-der-low-s) or raw r||s (ecdsa-raw). DER
// is strict: the bytes must re-encode to themselves (no non-minimal
// lengths or integers, no trailing bytes, no negative values). Both
// integers must lie in [1, n-1]. Low-S is not judged here; see IsLowS.
func ParseSignature(data []byte, format string) (Signature, error) {
	var sig Signature
	switch format {
	case FormatSignatureRaw:
		if len(data) != RawSignatureSize {
			return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: fmt.Sprintf("raw signature is %d bytes; ecdsa-raw is exactly %d bytes (r||s)", len(data), RawSignatureSize), Hint: "pass the 64-byte r||s signature, or drop --raw for DER; nothing was verified"}
		}
		sig = Signature{R: new(big.Int).SetBytes(data[:32]), S: new(big.Int).SetBytes(data[32:])}
	case FormatSignatureDERLowS:
		var decoded ecdsaSignatureASN1
		rest, err := asn1.Unmarshal(data, &decoded)
		if err != nil {
			return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: "signature is not a DER ECDSA-Sig-Value: " + err.Error(), Hint: "pass the DER SEQUENCE {r, s} the sign command produced, or --raw for r||s; nothing was verified"}
		}
		if len(rest) != 0 {
			return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: fmt.Sprintf("signature carries %d trailing bytes after the DER SEQUENCE", len(rest)), Hint: "strict DER has nothing after the SEQUENCE; nothing was verified"}
		}
		if decoded.R == nil || decoded.S == nil {
			return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: "signature DER lacks r or s", Hint: "pass the DER SEQUENCE {r, s} the sign command produced; nothing was verified"}
		}
		sig = Signature{R: decoded.R, S: decoded.S}
		canonical, err := asn1.Marshal(ecdsaSignatureASN1{R: sig.R, S: sig.S})
		if err != nil || !bytes.Equal(canonical, data) {
			return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: "signature DER is not strict (non-minimal length or integer encoding)", Hint: "strict DER re-encodes to the same bytes; re-issue the signature; nothing was verified"}
		}
	default:
		return Signature{}, &Refusal{Code: CodeInvalidFormat, Message: fmt.Sprintf("signature format %q is not one of %s, %s", format, FormatSignatureDERLowS, FormatSignatureRaw), Hint: hintFixInputNoSecurityCal}
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.Cmp(p256Order) >= 0 || sig.S.Cmp(p256Order) >= 0 {
		return Signature{}, &Refusal{Code: CodeInvalidSignature, Message: "signature r or s is outside [1, n-1] of P-256", Hint: "the value is not a P-256 ECDSA signature; nothing was verified"}
	}
	return sig, nil
}

// IsLowS reports whether s <= n/2 (the non-malleable half).
func (s Signature) IsLowS() bool {
	return s.S.Cmp(p256HalfOrder) <= 0
}

// LowS returns the signature with s replaced by n-s when it is in the high
// half; (r, n-s) verifies for the same digest and key.
func (s Signature) LowS() Signature {
	if s.IsLowS() {
		return s
	}
	return Signature{R: s.R, S: new(big.Int).Sub(p256Order, s.S)}
}

// Encode renders the signature as strict DER or raw r||s.
func (s Signature) Encode(format string) ([]byte, error) {
	switch format {
	case FormatSignatureRaw:
		out := make([]byte, RawSignatureSize)
		s.R.FillBytes(out[:32])
		s.S.FillBytes(out[32:])
		return out, nil
	case FormatSignatureDERLowS:
		return asn1.Marshal(ecdsaSignatureASN1{R: s.R, S: s.S})
	default:
		return nil, &Refusal{Code: CodeInvalidFormat, Message: fmt.Sprintf("signature format %q is not one of %s, %s", format, FormatSignatureDERLowS, FormatSignatureRaw), Hint: hintFixInputNoSecurityCal}
	}
}

// ParseSPKI reads a P-256 public key from DER or PEM SubjectPublicKeyInfo
// and returns its DER form (the fingerprint input) with the parsed key.
func ParseSPKI(data []byte) ([]byte, *ecdsa.PublicKey, error) {
	der := data
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, nil, &Refusal{Code: CodeInvalidPublicKey, Message: fmt.Sprintf("PEM block is %q, not PUBLIC KEY", block.Type), Hint: "pass the SPKI DER or PEM that pub produced; nothing was verified"}
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, &Refusal{Code: CodeInvalidPublicKey, Message: "PEM input carries data after the PUBLIC KEY block", Hint: "pass exactly one SPKI PEM block; nothing was verified"}
		}
		der = block.Bytes
	}
	pub, err := parseP256SPKI(der)
	if err != nil {
		return nil, nil, &Refusal{Code: CodeInvalidPublicKey, Message: "public key is not a P-256 SPKI: " + err.Error(), Hint: "pass the SPKI DER or PEM that pub produced; nothing was verified"}
	}
	return der, pub, nil
}

func parseP256SPKI(der []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 key")
	}
	return pub, nil
}

// VerifyDigest checks sig over digest under the P-256 SPKI with
// crypto/ecdsa. The verdict is false, not an error, for a well-formed
// signature that does not match; an unparsable SPKI is an error.
func VerifyDigest(spki, digest []byte, sig Signature) (bool, error) {
	if err := ValidateDigest(digest); err != nil {
		return false, err
	}
	_, pub, err := ParseSPKI(spki)
	if err != nil {
		return false, err
	}
	return ecdsa.Verify(pub, digest, sig.R, sig.S), nil
}
