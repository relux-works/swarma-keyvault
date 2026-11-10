package seedsetup

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixtureRecord(t *testing.T, target publicTarget) record {
	t.Helper()
	data, err := os.ReadFile("testdata/public-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Public string `json:"public_key"`
		NPub   string `json:"npub"`
		XPub   string `json:"namecoin_xpub"`
		Origin string `json:"origin"`
	}
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("public fixture decode")
	}
	point := func(i byte) ([]byte, string) {
		var scalar [32]byte
		scalar[31] = i
		k, e := ecdh.P256().NewPrivateKey(scalar[:])
		if e != nil {
			t.Fatal(e)
		}
		p := k.PublicKey().Bytes()
		h := sha256.Sum256(p)
		return p, hex.EncodeToString(h[:])
	}
	np, nf := point(1)
	cp, cf := point(2)
	return record{Schema: "keyvault-recovery/2", GroupID: strings.Repeat("01", 16), Service: target.NostrIdentity, Version: target.Version, Created: "2026-11-10T00:00:00Z", Nostr: purpose{Service: target.NostrIdentity, Purpose: "nostr", Version: target.NostrVersion, Path: "m/44'/1237'/0'/0/0", Algorithm: "secp256k1-bip340", Presence: "none", PublicKey: f.Public, NPub: f.NPub, WrappingPoint: np, WrappingFingerprint: nf}, Namecoin: purpose{Service: target.NamecoinIdentity, Purpose: "namecoin", Version: target.NamecoinVersion, Path: "m/84'/7'/0'", Algorithm: "bip32-secp256k1", Presence: "biometry-any", XPub: f.XPub, Origin: f.Origin, WrappingPoint: cp, WrappingFingerprint: cf}}
}

// Published public fixtures are accepted; wrong policy/pins/schema never become
// an accepted recovery receipt. These tests perform no native custody operation.
func TestPublicRecordPolicy(t *testing.T) {
	good := fixtureRecord(t, publicTarget{"north", "south", 3, 5, 7})
	if err := validateRecord(good, publicTarget{"north", "south", 3, 5, 7}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*record)
	}{
		{"generation", "nostr_policy", func(r *record) { r.Nostr.Version = 1 }},
		{"password-fallback", "namecoin_policy", func(r *record) { r.Namecoin.Presence = "user-presence" }},
		{"wrong-key", "npub_binding", func(r *record) {
			r.Nostr.PublicKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		}},
		{"shared-wrap", "shared_wrapping_key", func(r *record) {
			r.Namecoin.WrappingPoint = r.Nostr.WrappingPoint
			r.Namecoin.WrappingFingerprint = r.Nostr.WrappingFingerprint
		}},
		{"private-extended", "xpub_profile", func(r *record) { r.Namecoin.XPub = "xprv-forbidden" }},
		{"origin", "namecoin_policy", func(r *record) { r.Namecoin.Origin = "[00000000/44h/7h/0h]" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.change(&r)
			err := validateRecord(r, publicTarget{"north", "south", 3, 5, 7})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}

// Closed JSON rejects duplicates, unknown private fields, missing required
// public fields and trailing material beside a valid positive control.
func TestClosedPublicReceipt(t *testing.T) {
	r := fixtureRecord(t, publicTarget{"north", "south", 3, 5, 7})
	raw, _ := json.Marshal(r)
	var out record
	if err := decode(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(raw), `"schema":`, `"seed":"forbidden","schema":`, 1), strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1), strings.Replace(string(raw), `"schema":"keyvault-recovery/2",`, "", 1), strings.Replace(string(raw), `"schema":`, `"SCHEMA":"unexpected","schema":`, 1), string(raw) + ` {}`} {
		if decode([]byte(bad), &out) == nil {
			t.Fatal("forbidden response accepted")
		}
	}
}

// Independent targets preserve purpose separation: swapping one service or
// generation must refuse, while the same bytes under their exact target pass.
func TestPublicRecordTargetIsolation(t *testing.T) {
	target := publicTarget{"north", "south", 3, 5, 7}
	good := fixtureRecord(t, target)
	for _, bad := range []publicTarget{{"south", "north", 3, 5, 7}, {"north", "other", 3, 5, 7}, {"north", "south", 4, 5, 7}, {"north", "south", 3, 6, 7}, {"north", "south", 3, 5, 8}, {"", "south", 3, 5, 7}} {
		if validateRecord(good, bad) == nil {
			t.Fatal("response accepted under a different target")
		}
	}
	raw, _ := json.Marshal(good)
	var decoded record
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"service":"south"`), []byte(`"service":"south","service":"other"`), 1), bytes.Replace(raw, []byte(`"service":"south",`), nil, 1)} {
		if decode(bad, &decoded) == nil {
			t.Fatal("missing/duplicate second identity accepted")
		}
	}
}
