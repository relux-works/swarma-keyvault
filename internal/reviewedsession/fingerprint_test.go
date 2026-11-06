package reviewedsession

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func publicP256(t *testing.T) ([]byte, string) {
	t.Helper()
	// Standard public generator point only; no owner/private key is accessed.
	x, y := elliptic.P256().Params().Gx, elliptic.P256().Params().Gy
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	id := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
	return der, id
}

func TestFingerprintHashBytesEncodingAndTail(t *testing.T) {
	der, id := publicP256(t)
	h := sha256.Sum256(der)
	for _, p := range []profile{localRepository, a2aCertificate, muGrantMac} {
		f, err := fingerprint(p, der, bytes.Clone(der))
		if err != nil {
			t.Fatal(err)
		}
		want := hex.EncodeToString(h[:])
		if p == muGrantMac {
			want = base64.RawURLEncoding.EncodeToString(h[:])
		}
		if f.full != want || f.tail != want[len(want)-8:] {
			t.Fatal(p, f)
		}
		if p == localRepository && f.kind != "requester-p256-spki" || p == a2aCertificate && f.kind != "application-p256-spki" || p == muGrantMac && f.kind != "mac-p256-spki" {
			t.Fatal("wrong key role", f)
		}
		wrong := bytes.Clone(der)
		wrong[len(wrong)-1] ^= 1
		if _, err := fingerprint(p, der, wrong); err == nil {
			t.Fatal("full pin mismatch accepted")
		}
	}
	f, err := muSubjectFingerprint(id, der)
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := sha256.Sum256([]byte(id))
	if f.full == base64.RawURLEncoding.EncodeToString(wrongHash[:]) {
		t.Fatal("hashed textual key ID")
	}
	for _, bad := range []string{"", id + "=", "ed25519:" + id[5:], "p256:AA", "p256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 33))} {
		if _, err := muSubjectFingerprint(bad, der); err == nil {
			t.Fatal(bad)
		}
	}
	for _, bad := range [][]byte{nil, []byte(id), append(bytes.Clone(der), 0)} {
		if _, err := fingerprint(localRepository, bad, bad); err == nil {
			t.Fatal("invalid DER accepted")
		}
	}
}

func TestRawEd25519IsNotSPKI(t *testing.T) {
	raw := make([]byte, ed25519.PublicKeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatal(err)
	}
	f, err := fingerprint(repository, raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	rawHash, spkiHash := sha256.Sum256(raw), sha256.Sum256(der)
	if f.full != hex.EncodeToString(rawHash[:]) || f.full == hex.EncodeToString(spkiHash[:]) || f.kind != "raw-ed25519-device" {
		t.Fatal(f)
	}
	if _, err := fingerprint(repository, der, der); err == nil {
		t.Fatal("SPKI admitted as raw device bytes")
	}
	for _, p := range []profile{localRepository, a2aCertificate, muGrantMac} {
		if _, err := fingerprint(p, der, der); err == nil {
			t.Fatal("Ed25519 SPKI admitted as P-256", p)
		}
	}
}

func FuzzControlParser(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > commitMax+8 {
			t.Skip()
		}
		_, _ = parseControlFrame(raw)
	})
}

func FuzzInputParser(f *testing.F) {
	f.Add([]byte(`{"schema":"kv-reviewed-input/1","profile":"repository-1","inputs":{"payload_path":"public.json"}}`))
	f.Add([]byte(`{"schema":{"a":1},"profile":[],"inputs":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > inputMax+1 {
			t.Skip()
		}
		_, _ = parseInput(raw)
	})
}
