package keyvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
)

const recoveryAlgorithm = "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM"
const recoveryMaxMetadata = 32768
const recoveryMaxCiphertext = 65536

// RecoveryPurpose is public metadata. Empty public fields remain explicit in
// canonical JSON; a purpose's immutable path and policy determine its authority.
type RecoveryPurpose struct {
	Service             string `json:"service,omitempty"`
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

type RecoveryRecord struct {
	Schema   string          `json:"schema"`
	GroupID  string          `json:"group_id"`
	Service  string          `json:"service"`
	Version  int             `json:"version"`
	Created  string          `json:"created"`
	Nostr    RecoveryPurpose `json:"nostr"`
	Namecoin RecoveryPurpose `json:"namecoin"`
}

func (r RecoveryRecord) Account() string {
	a, _ := nostrAddress(r.Service, "recovery", r.Version)
	return a
}

func (r RecoveryRecord) NostrRecord() NostrRecord {
	return NostrRecord{Schema: "nostr-key/1", Service: r.purposeService(r.Nostr), Purpose: "nostr", Version: r.Nostr.Version, Algorithm: r.Nostr.Algorithm, Storage: "enclave-wrapped-keychain", Created: r.Created, PublicKey: r.Nostr.PublicKey, NPub: r.Nostr.NPub}
}

// Only the immutable v1 schema inherits its one service. V2 has no fallback.
func (r RecoveryRecord) purposeService(p RecoveryPurpose) string {
	if r.Schema == "keyvault-recovery/1" {
		return r.Service
	}
	return p.Service
}

func (r RecoveryRecord) PurposeAccount(p RecoveryPurpose) string {
	a, _ := nostrAddress(r.purposeService(p), p.Purpose, p.Version)
	return a
}

func (r RecoveryRecord) ciphertextSchema() string {
	if r.Schema == "keyvault-recovery/2" {
		return "keyvault-recovery-ciphertext/2"
	}
	return "keyvault-recovery-ciphertext/1"
}

func lowerHex(s string, size int) bool {
	v, e := hex.DecodeString(s)
	return e == nil && len(v) == size && hex.EncodeToString(v) == s
}

func validateWrapping(point []byte, fingerprint string) error {
	if len(point) != 65 {
		return recoveryRefuse("invalid_envelope")
	}
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return recoveryRefuse("invalid_envelope")
	}
	h := sha256.Sum256(point)
	if hex.EncodeToString(h[:]) != fingerprint {
		return recoveryRefuse("invalid_envelope")
	}
	return nil
}

func validateRecoveryRecord(r RecoveryRecord) error {
	if _, err := nostrAddress(r.Service, "recovery", r.Version); err != nil {
		return recoveryRefuse("invalid_record")
	}
	created, err := time.Parse(time.RFC3339, r.Created)
	if err != nil || created.UTC().Format(time.RFC3339) != r.Created || !lowerHex(r.GroupID, 16) {
		return recoveryRefuse("invalid_record")
	}
	n, c := r.Nostr, r.Namecoin
	switch r.Schema {
	case "keyvault-recovery/1":
		if n.Service != "" || c.Service != "" {
			return recoveryRefuse("invalid_record")
		}
	case "keyvault-recovery/2":
		if n.Service != r.Service || c.Service == "" {
			return recoveryRefuse("invalid_record")
		}
	default:
		return recoveryRefuse("invalid_record")
	}
	if _, err := nostrAddress(r.purposeService(n), n.Purpose, n.Version); err != nil {
		return recoveryRefuse("invalid_record")
	}
	if _, err := nostrAddress(r.purposeService(c), c.Purpose, c.Version); err != nil {
		return recoveryRefuse("invalid_record")
	}
	if n.Purpose != "nostr" || n.Path != "m/44'/1237'/0'/0/0" || n.Algorithm != "secp256k1-bip340" || n.Presence != "none" || n.XPub != "" || n.Origin != "" || validateNostrRecord(r.NostrRecord()) != nil {
		return recoveryRefuse("invalid_record")
	}
	if c.Purpose != "namecoin" || c.Path != "m/84'/7'/0'" || c.Algorithm != "bip32-secp256k1" || c.Presence != "biometry-any" || c.PublicKey != "" || c.NPub != "" {
		return recoveryRefuse("invalid_record")
	}
	if len(c.Origin) != 20 || c.Origin[0] != '[' || c.Origin[9:] != "/84h/7h/0h]" || !lowerHex(c.Origin[1:9], 4) {
		return recoveryRefuse("invalid_record")
	}
	raw := base58.Decode(c.XPub)
	if len(raw) != 82 || base58.Encode(raw) != c.XPub || !bytes.Equal(raw[:4], []byte{4, 0x88, 0xb2, 0x1e}) || raw[4] != 3 || binary.BigEndian.Uint32(raw[9:13]) != 0x80000000 {
		return recoveryRefuse("invalid_record")
	}
	h := sha256.Sum256(raw[:78])
	check := sha256.Sum256(h[:])
	if !bytes.Equal(raw[78:], check[:4]) {
		return recoveryRefuse("invalid_record")
	}
	if _, err := btcec.ParsePubKey(raw[45:78]); err != nil {
		return recoveryRefuse("invalid_record")
	}
	if validateWrapping(n.WrappingPoint, n.WrappingFingerprint) != nil || validateWrapping(c.WrappingPoint, c.WrappingFingerprint) != nil || bytes.Equal(n.WrappingPoint, c.WrappingPoint) {
		return recoveryRefuse("invalid_record")
	}
	return nil
}

func parseRecoveryRecord(raw []byte) (RecoveryRecord, error) {
	var r RecoveryRecord
	if len(raw) > recoveryMaxMetadata || DecodeSingleJSON(raw, &r) != nil || validateRecoveryRecord(r) != nil {
		return r, recoveryRefuse("invalid_record")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return RecoveryRecord{}, recoveryRefuse("invalid_record")
	}
	return r, nil
}

type recoveryEnvelope struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	EnclaveBlob []byte `json:"enclave_blob"`
	Point       []byte `json:"point"`
	Fingerprint string `json:"fingerprint"`
	Ciphertext  []byte `json:"ciphertext"`
}

type recoveryCiphertext struct {
	Schema   string           `json:"schema"`
	Nostr    recoveryEnvelope `json:"nostr"`
	Namecoin recoveryEnvelope `json:"namecoin"`
}

func parseRecoveryCiphertext(raw []byte, r RecoveryRecord) (recoveryCiphertext, error) {
	var c recoveryCiphertext
	if len(raw) > recoveryMaxCiphertext || DecodeSingleJSON(raw, &c) != nil || c.Schema != r.ciphertextSchema() || validateRecoveryRecord(r) != nil {
		return c, recoveryRefuse("invalid_envelope")
	}
	for _, v := range []struct {
		e    recoveryEnvelope
		p    RecoveryPurpose
		size int
	}{{c.Nostr, r.Nostr, 149}, {c.Namecoin, r.Namecoin, 181}} {
		if v.e.Schema != "keyvault-enclave/1" || v.e.Algorithm != recoveryAlgorithm || len(v.e.EnclaveBlob) < 1 || len(v.e.EnclaveBlob) > 16384 || len(v.e.Ciphertext) != v.size || !bytes.Equal(v.e.Point, v.p.WrappingPoint) || v.e.Fingerprint != v.p.WrappingFingerprint {
			return c, recoveryRefuse("invalid_envelope")
		}
		if _, err := ecdh.P256().NewPublicKey(v.e.Ciphertext[:65]); err != nil {
			return c, recoveryRefuse("invalid_envelope")
		}
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(canonical, raw) {
		return c, recoveryRefuse("invalid_envelope")
	}
	return c, nil
}

func recoveryBinding(r RecoveryRecord, p RecoveryPurpose) [32]byte {
	metadata, _ := json.Marshal(r)
	namespace := "works.relux.mac-keyvault." + p.Purpose + "-wrap.v1"
	logical := r.PurposeAccount(p)
	domain := "works.relux.mac-keyvault.recovery-envelope.v1"
	if r.Schema == "keyvault-recovery/2" {
		domain = "works.relux.mac-keyvault.recovery-envelope.v2"
	}
	h := sha256.New()
	for _, part := range []string{domain, namespace, r.Account(), p.Purpose, logical} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write(metadata)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(p.WrappingPoint)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func recoverySeal(r RecoveryRecord, p RecoveryPurpose, blob, secret []byte) (recoveryEnvelope, error) {
	var out recoveryEnvelope
	size := 32
	if p.Purpose == "namecoin" {
		size = 64
	} else if p.Purpose != "nostr" {
		return out, recoveryRefuse("invalid_purpose")
	}
	if len(secret) != size || validateRecoveryRecord(r) != nil || len(blob) == 0 || len(blob) > 16384 {
		return out, recoveryRefuse("invalid_envelope")
	}
	plain := make([]byte, 36+size)
	defer clear(plain)
	copy(plain, "KVN1")
	binding := recoveryBinding(r, p)
	copy(plain[4:36], binding[:])
	copy(plain[36:], secret)
	peer, err := ecdh.P256().NewPublicKey(p.WrappingPoint)
	if err != nil {
		return out, recoveryRefuse("invalid_envelope")
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return out, recoveryRefuse("random_unavailable")
	}
	z, err := eph.ECDH(peer)
	if err != nil {
		return out, recoveryRefuse("seal_failed")
	}
	defer clear(z)
	point := eph.PublicKey().Bytes()
	h := sha256.New()
	_, _ = h.Write(z)
	_, _ = h.Write([]byte{0, 0, 0, 1})
	_, _ = h.Write(point)
	derived := h.Sum(nil)
	defer clear(derived)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return out, recoveryRefuse("seal_failed")
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return out, recoveryRefuse("seal_failed")
	}
	out = recoveryEnvelope{Schema: "keyvault-enclave/1", Algorithm: recoveryAlgorithm, EnclaveBlob: bytes.Clone(blob), Point: bytes.Clone(p.WrappingPoint), Fingerprint: p.WrappingFingerprint, Ciphertext: gcm.Seal(bytes.Clone(point), derived[16:], plain, nil)}
	return out, nil
}

func recoveryNostrPlain(r RecoveryRecord, plain []byte) ([]byte, error) {
	if len(plain) != 68 || !bytes.Equal(plain[:4], []byte("KVN1")) {
		return nil, recoveryRefuse("invalid_plaintext")
	}
	binding := recoveryBinding(r, r.Nostr)
	if !bytes.Equal(plain[4:36], binding[:]) {
		return nil, recoveryRefuse("binding_mismatch")
	}
	key, err := nostrPrivate(plain[36:])
	if err != nil {
		return nil, recoveryRefuse("invalid_plaintext")
	}
	key.Zero()
	return plain[36:], nil
}

// recoveryRows admits every emitted legacy row and paired recovery row. It
// refuses ambiguous mappings in the shared namespace instead of hiding them.
func recoveryRows(raw []byte) ([]NostrRecord, []RecoveryRecord, error) {
	nostr := []NostrRecord{}
	groups := []RecoveryRecord{}
	seen := map[string]bool{}
	physical := map[string]bool{}
	if len(raw) > 4*1024*1024 {
		return nil, nil, recoveryRefuse("invalid_record")
	}
	for _, row := range bytes.Split(raw, []byte{0x1e}) {
		if len(row) == 0 {
			continue
		}
		fields := bytes.Split(row, []byte{0x1f})
		if len(fields) != 2 || len(fields[1]) > recoveryMaxMetadata {
			return nil, nil, recoveryRefuse("invalid_record")
		}
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(fields[1], &header) != nil {
			return nil, nil, recoveryRefuse("invalid_record")
		}
		if physical[string(fields[0])] {
			return nil, nil, recoveryRefuse("duplicate")
		}
		physical[string(fields[0])] = true
		var r NostrRecord
		switch header.Schema {
		case "nostr-key/1":
			if DecodeSingleJSON(fields[1], &r) != nil || validateNostrRecord(r) != nil || r.Storage != "keychain-acl" || string(fields[0]) != r.Account() {
				return nil, nil, recoveryRefuse("invalid_record")
			}
			canonical, _ := json.Marshal(r)
			if !bytes.Equal(canonical, fields[1]) {
				return nil, nil, recoveryRefuse("invalid_record")
			}
		case "keyvault-recovery/1", "keyvault-recovery/2":
			g, err := parseRecoveryRecord(fields[1])
			if err != nil || string(fields[0]) != g.Account() {
				return nil, nil, recoveryRefuse("invalid_record")
			}
			groups = append(groups, g)
			r = g.NostrRecord()
			account := g.PurposeAccount(g.Namecoin)
			if seen[account] {
				return nil, nil, recoveryRefuse("duplicate")
			}
			seen[account] = true
		default:
			return nil, nil, recoveryRefuse("invalid_record")
		}
		if seen[r.Account()] {
			return nil, nil, recoveryRefuse("duplicate")
		}
		seen[r.Account()] = true
		nostr = append(nostr, r)
	}
	return nostr, groups, nil
}
