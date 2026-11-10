package seedsetup

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func refused(code string) error { return errors.New(code) }

// Closed typed schemas plus duplicate rejection admit exactly the CLI's JSON
// forms. Raw child output/error text is never echoed, including on refusal.
func decode(raw []byte, target any) error {
	if len(raw) > 32768 {
		return refused("response_size")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return refused("response_nesting")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return refused("duplicate_json")
				}
				seen[s] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return refused("json_shape")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return refused("response_json")
	}
	if _, err := d.Token(); err != io.EOF {
		return refused("response_tail")
	}
	if err := requiredFields(raw, reflect.TypeOf(target)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return refused("response_schema")
	}
	return nil
}
func requiredFields(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return refused("response_object")
	}
	admitted := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		admitted[tag[0]] = true
		value, present := fields[tag[0]]
		optional := len(tag) > 1 && tag[1] == "omitempty"
		if !present {
			if !optional {
				return refused("response_missing_field")
			}
			continue
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return refused("response_null_field")
		}
		if err := requiredFields(value, f.Type); err != nil {
			return err
		}
	}
	for k := range fields {
		if !admitted[k] {
			return refused("response_unknown_field")
		}
	}
	return nil
}

type purpose struct {
	Service             string `json:"service"`
	Purpose             string `json:"purpose"`
	Version             int    `json:"version"`
	Path                string `json:"path"`
	Algorithm           string `json:"algorithm"`
	Presence            string `json:"presence"`
	PublicKey           string `json:"public_key"`
	NPub                string `json:"npub"`
	XPub                string `json:"xpub"`
	Origin              string `json:"origin"`
	WrappingPoint       []byte `json:"wrapping_point"`
	WrappingFingerprint string `json:"wrapping_fingerprint"`
}
type record struct {
	Schema   string  `json:"schema"`
	GroupID  string  `json:"group_id"`
	Service  string  `json:"service"`
	Version  int     `json:"version"`
	Created  string  `json:"created"`
	Nostr    purpose `json:"nostr"`
	Namecoin purpose `json:"namecoin"`
}

// publicTarget binds all three addresses to a confirmed public plan.
// No missing generation or identity is inherited from a child response.
type publicTarget struct {
	NostrIdentity, NamecoinIdentity        string
	Version, NostrVersion, NamecoinVersion int
}

func (t publicTarget) validate() error {
	if !validIdentity(t.NostrIdentity) || !validIdentity(t.NamecoinIdentity) {
		return refused("invalid_target")
	}
	for _, v := range []int{t.Version, t.NostrVersion, t.NamecoinVersion} {
		if v < 1 || v > 2147483647 {
			return refused("invalid_target")
		}
	}
	return nil
}

// Public BIP-340 verification admits canonical fixed-size hex only.
func verifyDigest(publicHex, signature, digest string) bool {
	p, err := hex.DecodeString(publicHex)
	if err != nil || !hexValue(publicHex, 32) {
		return false
	}
	pk, err := schnorr.ParsePubKey(p)
	if err != nil {
		return false
	}
	raw, err := hex.DecodeString(signature)
	if err != nil || !hexValue(signature, 64) || !hexValue(digest, 32) {
		return false
	}
	d, _ := hex.DecodeString(digest)
	sig, err := schnorr.ParseSignature(raw)
	return err == nil && sig.Verify(d, pk)
}

func hexValue(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func validateRecord(r record, target publicTarget) error {
	if err := target.validate(); err != nil {
		return err
	}
	if r.Schema != "keyvault-recovery/2" || r.Service != target.NostrIdentity || r.Version != target.Version || !hexValue(r.GroupID, 16) {
		return refused("record_identity")
	}
	stamp, e := time.Parse(time.RFC3339, r.Created)
	if e != nil || stamp.UTC().Format(time.RFC3339) != r.Created {
		return refused("record_time")
	}
	n, c := r.Nostr, r.Namecoin
	if n.Service != target.NostrIdentity || n.Purpose != "nostr" || n.Version != target.NostrVersion || n.Path != "m/44'/1237'/0'/0/0" || n.Algorithm != "secp256k1-bip340" || n.Presence != "none" || n.XPub != "" || n.Origin != "" {
		return refused("nostr_policy")
	}
	pub, e := hex.DecodeString(n.PublicKey)
	if e != nil || !hexValue(n.PublicKey, 32) {
		return refused("nostr_public")
	}
	if _, e = schnorr.ParsePubKey(pub); e != nil {
		return refused("nostr_point")
	}
	hrp, words, e := bech32.Decode(n.NPub)
	if e != nil || hrp != "npub" {
		return refused("npub_encoding")
	}
	raw, e := bech32.ConvertBits(words, 5, 8, false)
	encoded, e2 := bech32.Encode("npub", words)
	if e != nil || e2 != nil || encoded != n.NPub || !bytes.Equal(raw, pub) {
		return refused("npub_binding")
	}
	if c.Service != target.NamecoinIdentity || c.Purpose != "namecoin" || c.Version != target.NamecoinVersion || c.Path != "m/84'/7'/0'" || c.Algorithm != "bip32-secp256k1" || c.Presence != "biometry-any" || c.PublicKey != "" || c.NPub != "" || !regexp.MustCompile(`^\[[0-9a-f]{8}/84h/7h/0h\]$`).MatchString(c.Origin) {
		return refused("namecoin_policy")
	}
	x := base58.Decode(c.XPub)
	if len(x) != 82 || binary.BigEndian.Uint32(x[:4]) != 0x0488b21e || x[4] != 3 || binary.BigEndian.Uint32(x[9:13]) != 0x80000000 {
		return refused("xpub_profile")
	}
	first := sha256.Sum256(x[:78])
	sum := sha256.Sum256(first[:])
	if !bytes.Equal(x[78:], sum[:4]) || base58.Encode(x) != c.XPub {
		return refused("xpub_checksum")
	}
	if _, e = btcec.ParsePubKey(x[45:78]); e != nil {
		return refused("xpub_point")
	}
	for _, p := range []purpose{n, c} {
		if _, e := ecdh.P256().NewPublicKey(p.WrappingPoint); e != nil {
			return refused("wrap_point")
		}
		sum := sha256.Sum256(p.WrappingPoint)
		if hex.EncodeToString(sum[:]) != p.WrappingFingerprint {
			return refused("wrap_fingerprint")
		}
	}
	if bytes.Equal(n.WrappingPoint, c.WrappingPoint) {
		return refused("shared_wrapping_key")
	}
	return nil
}
