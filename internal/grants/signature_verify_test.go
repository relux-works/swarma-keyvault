package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

// Public values only, from RFC 6979 A.2.5, P-256/SHA-256/message "test":
// https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5
// This published signature is already low-S. No key or signature is generated,
// and the fixture establishes no grant issuer enrollment or authorization.
func publicSignatureVector(t *testing.T) (*ecdsa.PublicKey, [sha256.Size]byte, []byte) {
	t.Helper()
	integer := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatal("invalid public vector integer")
		}
		return n
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     integer("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"),
		Y:     integer("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"),
	}
	raw, err := hex.DecodeString("3045022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D383670220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")
	if err != nil {
		t.Fatal(err)
	}
	return pub, sha256.Sum256([]byte("test")), raw
}

func requirePublicSignatureControl(t *testing.T) {
	t.Helper()
	pub, digest, raw := publicSignatureVector(t)
	if err := verifyP256Signature(pub, digest, raw); err != nil {
		t.Fatal("published valid control refused", err)
	}
}

// The independent published vector verifies without changing any input.
// Success is mathematical verification only, not a valid/enrolled grant.
func TestVerifyP256SignatureKnownAnswer(t *testing.T) {
	pub, digest, raw := publicSignatureVector(t)
	x, y, originalDigest, originalRaw := new(big.Int).Set(pub.X), new(big.Int).Set(pub.Y), digest, bytes.Clone(raw)
	if err := verifyP256Signature(pub, digest, raw); err != nil {
		t.Fatal("published known answer refused", err)
	}
	if pub.Curve != elliptic.P256() || pub.X.Cmp(x) != 0 || pub.Y.Cmp(y) != 0 || digest != originalDigest || !bytes.Equal(raw, originalRaw) {
		t.Fatal("verification mutated an input")
	}
}

// These validly shaped neighboring signatures fail the mathematical check;
// unchanged published controls pass before and after every refusal. Domain
// hashes of "test" cannot reuse its plain SHA-256 signature; these are not
// complete signed-grant integration fixtures.
func TestVerifyP256SignatureRefusesChangedMath(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ecdsa.PublicKey, *[sha256.Size]byte, []byte)
	}{
		{"changed digest", func(_ *ecdsa.PublicKey, d *[sha256.Size]byte, _ []byte) { d[0] ^= 1 }},
		{"different valid public point", func(p *ecdsa.PublicKey, _ *[sha256.Size]byte, _ []byte) {
			p.X = new(big.Int).Set(elliptic.P256().Params().Gx)
			p.Y = new(big.Int).Set(elliptic.P256().Params().Gy)
		}},
		{"changed S", func(_ *ecdsa.PublicKey, _ *[sha256.Size]byte, raw []byte) { raw[len(raw)-1] ^= 1 }},
	}
	for _, domain := range []struct {
		name  string
		value digestDomain
	}{
		{"certificate domain", certificateDomain}, {"revocation domain", revocationDomain},
		{"request correlation domain", requestDomain}, {"result correlation domain", resultDomain},
	} {
		digest, err := domainDigest(domain.value, []byte("test"))
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, struct {
			name   string
			change func(*ecdsa.PublicKey, *[sha256.Size]byte, []byte)
		}{domain.name, func(_ *ecdsa.PublicKey, actual *[sha256.Size]byte, _ []byte) {
			*actual = digest
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requirePublicSignatureControl(t)
			pub, digest, raw := publicSignatureVector(t)
			test.change(pub, &digest, raw)
			x, y, originalDigest, originalRaw := new(big.Int).Set(pub.X), new(big.Int).Set(pub.Y), digest, bytes.Clone(raw)
			if err := verifyP256Signature(pub, digest, raw); !errors.Is(err, errSignatureInvalid) {
				t.Fatalf("wanted signature-invalid, got %v", err)
			}
			if pub.X.Cmp(x) != 0 || pub.Y.Cmp(y) != 0 || digest != originalDigest || !bytes.Equal(raw, originalRaw) {
				t.Fatal("refusal mutated an input")
			}
			requirePublicSignatureControl(t)
		})
	}
}

type signatureUnadmittedCurve struct{ elliptic.Curve }

func (signatureUnadmittedCurve) Params() *elliptic.CurveParams {
	panic("unadmitted curve implementation called")
}

func signatureCoordinateText(n *big.Int) string {
	if n == nil {
		return "<nil>"
	}
	return n.Text(16)
}

// Missing/invalid points and other standard curves refuse without invoking an
// arbitrary curve implementation. The typed API excludes non-ECDSA keys at
// compile time; this table does not claim SPKI parsing or enrollment coverage.
func TestVerifyP256SignatureRefusesPublicKeys(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ecdsa.PublicKey) *ecdsa.PublicKey
	}{
		{"nil key", func(_ *ecdsa.PublicKey) *ecdsa.PublicKey { return nil }},
		{"nil curve", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.Curve = nil; return p }},
		{"nil X", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.X = nil; return p }},
		{"nil Y", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.Y = nil; return p }},
		{"negative X", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.X.Neg(p.X); return p }},
		{"negative Y", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.Y.Neg(p.Y); return p }},
		{"zero point", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.X.SetInt64(0); p.Y.SetInt64(0); return p }},
		{"off curve", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.X.Add(p.X, big.NewInt(1)); return p }},
		{"field boundary", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.X.Set(elliptic.P256().Params().P); return p }},
		{"oversized coordinate", func(p *ecdsa.PublicKey) *ecdsa.PublicKey { p.Y.Lsh(big.NewInt(1), 256); return p }},
		{"arbitrary curve", func(p *ecdsa.PublicKey) *ecdsa.PublicKey {
			p.Curve = signatureUnadmittedCurve{elliptic.P256()}
			return p
		}},
	}
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P384(), elliptic.P521()} {
		c := curve
		tests = append(tests, struct {
			name   string
			change func(*ecdsa.PublicKey) *ecdsa.PublicKey
		}{c.Params().Name, func(p *ecdsa.PublicKey) *ecdsa.PublicKey {
			p.Curve, p.X, p.Y = c, new(big.Int).Set(c.Params().Gx), new(big.Int).Set(c.Params().Gy)
			return p
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requirePublicSignatureControl(t)
			pub, digest, raw := publicSignatureVector(t)
			pub = test.change(pub)
			original := bytes.Clone(raw)
			var originalCurve elliptic.Curve
			var originalX, originalY string
			if pub != nil {
				originalCurve, originalX, originalY = pub.Curve, signatureCoordinateText(pub.X), signatureCoordinateText(pub.Y)
			}
			if test.name == "off curve" && elliptic.P256().IsOnCurve(pub.X, pub.Y) {
				t.Fatal("negative public-point fixture is unexpectedly on curve")
			}
			if err := verifyP256Signature(pub, digest, raw); !errors.Is(err, errSignatureInvalid) {
				t.Fatalf("wanted signature-invalid, got %v", err)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("key refusal changed signature")
			}
			if pub != nil && (pub.Curve != originalCurve || signatureCoordinateText(pub.X) != originalX || signatureCoordinateText(pub.Y) != originalY) {
				t.Fatal("refusal changed public key")
			}
			requirePublicSignatureControl(t)
		})
	}
}

// Even a mathematically valid high-S reflection must refuse the fixed low-S
// contract. Other DER aliases/raw/trailing/over-limit shapes refuse with the
// intended class and unchanged received bytes, alongside valid controls.
func TestVerifyP256SignatureRefusesRepresentations(t *testing.T) {
	pub, digest, raw := publicSignatureVector(t)
	r, s, err := parseLowSSignatureDER(raw)
	if err != nil {
		t.Fatal(err)
	}
	high := new(big.Int).Sub(elliptic.P256().Params().N, s)
	highDER, err := asn1.Marshal(struct{ R, S *big.Int }{r, high})
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], highDER) {
		t.Fatal("high-S control must be mathematically valid before policy refusal")
	}
	raw64 := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	nonminimal := append(bytes.Clone(raw[:4]), append([]byte{0}, raw[4:]...)...)
	nonminimal[1]++
	nonminimal[3]++
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{"high S", highDER, errSignatureInvalid},
		{"raw64", raw64, errSignatureInvalid},
		{"nonminimal R", nonminimal, errSignatureInvalid},
		{"trailing byte", append(bytes.Clone(raw), 0), errSignatureInvalid},
		{"nil", nil, errSignatureInvalid},
		{"empty", []byte{}, errSignatureInvalid},
		{"malformed exactly72", make([]byte, 72), errSignatureInvalid},
		{"over limit73", make([]byte, 73), errInputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requirePublicSignatureControl(t)
			before := bytes.Clone(test.raw)
			if err := verifyP256Signature(pub, digest, test.raw); !errors.Is(err, test.want) {
				t.Fatalf("wanted %v, got %v", test.want, err)
			}
			if !bytes.Equal(test.raw, before) {
				t.Fatal("refusal normalized input")
			}
			requirePublicSignatureControl(t)
		})
	}
}
