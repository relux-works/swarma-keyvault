package keyvault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testDigest(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

// ParseSignature admits exactly strict DER (re-encodes to itself) with r, s
// in [1, n-1], and exactly 64 raw bytes; every other shape is
// invalid_signature. Positive controls: a crypto/ecdsa DER signature and
// its raw form parse to the same integers. The low-S judgement is
// separate: a high-S twin parses and IsLowS reports false.
func TestParseSignatureStrictness(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := testDigest("strict")
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ParseSignature(der, FormatSignatureDERLowS)
	if err != nil {
		t.Fatalf("control DER: %v", err)
	}
	raw, _ := sig.Encode(FormatSignatureRaw)
	if len(raw) != RawSignatureSize {
		t.Fatalf("raw is %d bytes", len(raw))
	}
	fromRaw, err := ParseSignature(raw, FormatSignatureRaw)
	if err != nil || fromRaw.R.Cmp(sig.R) != 0 || fromRaw.S.Cmp(sig.S) != 0 {
		t.Fatalf("raw round trip: %v %+v vs %+v", err, fromRaw, sig)
	}
	if back, _ := sig.Encode(FormatSignatureDERLowS); !bytes.Equal(back, der) {
		t.Fatal("DER round trip differs")
	}
	if !ecdsa.Verify(&priv.PublicKey, digest, sig.R, sig.S) {
		t.Fatal("control does not verify")
	}
	highS := Signature{R: sig.LowS().R, S: new(big.Int).Sub(p256Order, sig.LowS().S)}
	highDER, _ := highS.Encode(FormatSignatureDERLowS)
	parsedHigh, err := ParseSignature(highDER, FormatSignatureDERLowS)
	if err != nil || parsedHigh.IsLowS() || !parsedHigh.LowS().IsLowS() || parsedHigh.LowS().S.Cmp(sig.LowS().S) != 0 {
		t.Fatalf("high-S twin: %v low=%v", err, parsedHigh.IsLowS())
	}
	if !ecdsa.Verify(&priv.PublicKey, digest, parsedHigh.R, parsedHigh.S) {
		t.Fatal("high-S twin is a valid ECDSA signature by construction; the test premise is wrong")
	}

	// Non-minimal integer: r with a redundant leading zero.
	type sigASN1 struct{ R, S *big.Int }
	type sigRaw struct {
		R, S asn1.RawValue
	}
	rBytes := sig.R.Bytes()
	padded := append([]byte{0x00, 0x00}, rBytes...)
	if rBytes[0]&0x80 != 0 {
		padded = append([]byte{0x00}, rBytes...)
		padded = append([]byte{0x00}, padded...)
	}
	nonMinimal, _ := asn1.Marshal(sigRaw{R: asn1.RawValue{Tag: asn1.TagInteger, Bytes: padded}, S: asn1.RawValue{Tag: asn1.TagInteger, Bytes: sig.S.Bytes()}})
	negative, _ := asn1.Marshal(sigASN1{R: new(big.Int).Neg(sig.R), S: sig.S})
	zeroR, _ := asn1.Marshal(sigASN1{R: big.NewInt(0), S: sig.S})
	overN, _ := asn1.Marshal(sigASN1{R: sig.R, S: new(big.Int).Set(p256Order)})
	longForm := append([]byte{0x30, 0x81, byte(len(der) - 2)}, der[2:]...) // long-form length for a short SEQUENCE
	cases := map[string]struct {
		data   []byte
		format string
	}{
		"trailing byte":       {append(append([]byte(nil), der...), 0x00), FormatSignatureDERLowS},
		"truncated":           {der[:len(der)-1], FormatSignatureDERLowS},
		"empty":               {nil, FormatSignatureDERLowS},
		"non-minimal integer": {nonMinimal, FormatSignatureDERLowS},
		"long-form length":    {longForm, FormatSignatureDERLowS},
		"negative r":          {negative, FormatSignatureDERLowS},
		"zero r":              {zeroR, FormatSignatureDERLowS},
		"s equals n":          {overN, FormatSignatureDERLowS},
		"raw 63 bytes":        {raw[:63], FormatSignatureRaw},
		"raw 65 bytes":        {append(append([]byte(nil), raw...), 0), FormatSignatureRaw},
		"raw zero s":          {append(append([]byte(nil), raw[:32]...), make([]byte, 32)...), FormatSignatureRaw},
		"DER given as raw":    {der, FormatSignatureRaw},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSignature(tc.data, tc.format)
			if got := refusalCode(t, err); got != CodeInvalidSignature {
				t.Fatalf("code %s, want %s", got, CodeInvalidSignature)
			}
		})
	}
	if _, err := ParseSignature(der, "ecdsa-p1363"); refusalCode(t, err) != CodeInvalidFormat {
		t.Fatalf("unknown format: %v", err)
	}
}

// ParseSPKI takes P-256 SPKI as DER or PEM and refuses another curve, a
// non-PUBLIC KEY block, trailing PEM data and garbage as
// invalid_public_key.
func TestParseSPKI(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	for name, input := range map[string][]byte{"der": der, "pem": EncodePEM(der), "pem with whitespace": append([]byte("\n"), EncodePEM(der)...)} {
		got, pub, err := ParseSPKI(input)
		if err != nil || !bytes.Equal(got, der) || pub.X.Cmp(priv.PublicKey.X) != 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	bad := map[string][]byte{
		"p-384":             der384,
		"garbage":           []byte("not a key"),
		"wrong block type":  []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"trailing pem data": append(EncodePEM(der), []byte("extra\n")...),
		"truncated der":     der[:len(der)-3],
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseSPKI(input)
			if refusalCode(t, err) != CodeInvalidPublicKey {
				t.Fatalf("%v", err)
			}
		})
	}
}

// Manager.Sign runs its gates before the backend signs: a mis-sized digest
// (31 and 33 bytes) is invalid_digest with zero store calls of any kind;
// a record without usage sign is usage_refused (an empty usages list is an
// invariant violation and stays metadata_unknown, see the forgery table); an elapsed not_after is expired (one hour
// past, judged by the manager clock); a rev1 tag is metadata_unknown; a
// record with no registry row is unsupported_primitive (failure class);
// an address with no key is ErrNotFound. None of those reach Sign.
// Positive controls: a valid record signs once, the result is low-S and
// verifies with crypto/ecdsa; a high-S value from the backend is
// normalised (same r, s -> n-s) and still verifies; a not_after one hour
// ahead signs. Faults after the gate: ErrNotFound from the backend maps to
// not found, an OSStatus maps to security (failure), and a signature that
// does not verify under the record's own public key is refused as
// security instead of emitted.
func TestManagerSignGates(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	digest := testDigest("gates")
	addr := func(purpose string) Address { return Address{Kind: KindKey, Service: TestService, Purpose: purpose} }

	setup := func(t *testing.T, purpose string, mutate func(*Record)) (*fakeStore, *Manager, *ecdsa.PrivateKey) {
		t.Helper()
		label := tl(purpose, 1)
		store := newFakeStore(label)
		priv := store.installSigner(t, label)
		if mutate != nil {
			rec := testRecord(label)
			mutate(&rec)
			item := store.keys[label]
			item.Tag, _ = EncodeRecord(rec)
			store.keys[label] = item
		}
		m := newTestManager(t, store)
		m.SetClock(func() time.Time { return now })
		return store, m, priv
	}

	t.Run("control signs low-S and verifies", func(t *testing.T) {
		store, m, priv := setup(t, "ok", nil)
		signed, err := m.Sign(addr("ok"), digest)
		if err != nil || len(store.signs) != 1 || store.signs[0] != tl("ok", 1) || signed.Normalized {
			t.Fatalf("%v signs=%v normalized=%v", err, store.signs, signed.Normalized)
		}
		if !signed.Signature.IsLowS() || !ecdsa.Verify(&priv.PublicKey, digest, signed.Signature.R, signed.Signature.S) {
			t.Fatal("signature is not low-S or does not verify")
		}
	})
	t.Run("high-S from the backend is normalised", func(t *testing.T) {
		store, m, priv := setup(t, "hs", nil)
		store.signHighS = true
		signed, err := m.Sign(addr("hs"), digest)
		if err != nil || !signed.Normalized || !signed.Signature.IsLowS() {
			t.Fatalf("%v normalized=%v", err, signed.Normalized)
		}
		if !ecdsa.Verify(&priv.PublicKey, digest, signed.Signature.R, signed.Signature.S) {
			t.Fatal("normalised signature does not verify")
		}
	})
	t.Run("future not_after signs", func(t *testing.T) {
		_, m, _ := setup(t, "future", func(r *Record) { na := NewTime(now.Add(time.Hour)); r.Validity.NotAfter = &na })
		if _, err := m.Sign(addr("future"), digest); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("mis-sized digest before any call", func(t *testing.T) {
		store, m, _ := setup(t, "len", nil)
		for _, n := range []int{0, 31, 33, 64} {
			_, err := m.Sign(addr("len"), make([]byte, n))
			if refusalCode(t, err) != CodeInvalidDigest {
				t.Fatalf("%d bytes: %v", n, err)
			}
		}
		if c, d, u, l := store.calls(); c+d+u+l != 0 || len(store.signs) != 0 {
			t.Fatalf("store touched: %d %d %d %d signs=%d", c, d, u, l, len(store.signs))
		}
	})
	refused := map[string]struct {
		mutate  func(*Record)
		code    string
		failure bool
	}{
		"usages without sign": {func(r *Record) { r.Usages = []string{"verify"} }, CodeUsageRefused, false},
		"expired one hour":    {func(r *Record) { na := NewTime(now.Add(-time.Hour)); r.Validity.NotAfter = &na }, CodeExpired, false},
		"expired exactly now": {func(r *Record) { na := NewTime(now); r.Validity.NotAfter = &na }, CodeExpired, false},
		// The fake backend serves the keychain only: an enclave record is
		// refused by the store-served gate before any private operation.
		"store not served": {func(r *Record) { r.Store = StoreEnclave }, CodeUnsupportedPrimitive, true},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			store, m, _ := setup(t, "gate", tc.mutate)
			_, err := m.Sign(addr("gate"), digest)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != tc.code || refusal.Failure != tc.failure {
				t.Fatalf("%v (want %s failure=%v)", err, tc.code, tc.failure)
			}
			if len(store.signs) != 0 {
				t.Fatal("backend signed despite the gate")
			}
		})
	}
	t.Run("rev1 tag is metadata_unknown", func(t *testing.T) {
		store, m, _ := setup(t, "legacy", nil)
		item := store.keys[tl("legacy", 1)]
		item.Tag = []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z")
		store.keys[item.Label] = item
		if _, err := m.Sign(addr("legacy"), digest); refusalCode(t, err) != CodeMetadataUnknown || len(store.signs) != 0 {
			t.Fatalf("%v signs=%d", err, len(store.signs))
		}
	})
	t.Run("missing key", func(t *testing.T) {
		store, m, _ := setup(t, "present", nil)
		if _, err := m.Sign(addr("absent"), digest); !errors.Is(err, ErrNotFound) || len(store.signs) != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("backend not found after gate", func(t *testing.T) {
		store, m, _ := setup(t, "gone", nil)
		delete(store.signers, tl("gone", 1))
		if _, err := m.Sign(addr("gone"), digest); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("backend OSStatus is security failure", func(t *testing.T) {
		store, m, _ := setup(t, "os", nil)
		store.signE = &StatusError{Op: "sign", Status: -25293}
		_, err := m.Sign(addr("os"), digest)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != CodeSecurity || !refusal.Failure || refusal.Status != -25293 || !strings.Contains(refusal.Message, "errSecAuthFailed") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("signature under another key is refused", func(t *testing.T) {
		store, m, _ := setup(t, "mismatch", nil)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		store.signers[tl("mismatch", 1)] = other
		_, err := m.Sign(addr("mismatch"), digest)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != CodeSecurity || !refusal.Failure || !strings.Contains(refusal.Message, "does not verify") {
			t.Fatalf("%v", err)
		}
	})
}

// PublicKeyFor (the verify address path) needs a readable, trusted record
// with a registry row and a readable SPKI; it does not need usage sign or
// an unexpired validity (verification is always allowed for a readable
// public half), and it never calls Sign.
func TestManagerPublicKeyFor(t *testing.T) {
	now := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	label := tl("pk", 1)
	build := func(t *testing.T, mutate func(*Record), spki bool) (*fakeStore, *Manager) {
		store := newFakeStore(label)
		store.installSigner(t, label)
		rec := testRecord(label)
		if mutate != nil {
			mutate(&rec)
		}
		item := store.keys[label]
		item.Tag, _ = EncodeRecord(rec)
		if !spki {
			item.SPKI = nil
		}
		store.keys[label] = item
		m := newTestManager(t, store)
		m.SetClock(func() time.Time { return now })
		return store, m
	}
	a := Address{Kind: KindKey, Service: TestService, Purpose: "pk"}
	for name, mutate := range map[string]func(*Record){
		"sign and verify": nil,
		"verify only":     func(r *Record) { r.Usages = []string{"verify"} },
		"expired":         func(r *Record) { na := NewTime(now.Add(-time.Hour)); r.Validity.NotAfter = &na },
	} {
		t.Run(name, func(t *testing.T) {
			store, m := build(t, mutate, true)
			key, err := m.PublicKeyFor(a)
			if err != nil || len(key.SPKI) == 0 || len(store.signs) != 0 {
				t.Fatalf("%v", err)
			}
		})
	}
	// No registry row (the enclave row taken away) and a store the backend
	// does not serve both refuse verify as unsupported_primitive.
	t.Run("no registry row", func(t *testing.T) {
		withoutRegistryRow(t, PrimitiveKey{Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreEnclave})
		_, m := build(t, func(r *Record) { r.Store = StoreEnclave }, true)
		_, err := m.PublicKeyFor(a)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != CodeUnsupportedPrimitive || !refusal.Failure || !strings.Contains(refusal.Message, "no registry row") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("store not served", func(t *testing.T) {
		_, m := build(t, func(r *Record) { r.Store = StoreEnclave }, true)
		_, err := m.PublicKeyFor(a)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != CodeUnsupportedPrimitive || !refusal.Failure {
			t.Fatalf("%v", err)
		}
	})
	t.Run("unreadable public half", func(t *testing.T) {
		_, m := build(t, nil, false)
		var refusal *Refusal
		if _, err := m.PublicKeyFor(a); !errors.As(err, &refusal) || refusal.Code != CodeSecurity || !refusal.Failure {
			t.Fatalf("%v", err)
		}
	})
}
