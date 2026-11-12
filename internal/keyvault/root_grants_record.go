package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const RootGrantsNamespace = "works.relux.mac-keyvault.root-grants.v1"

// RootGrantsRecord is ordered public sidecar metadata, not enrollment or proof
// of sealing, possession, biometric policy, ACL qualification or grant authority.
// Service is the explicit grants identity; the physical Keychain service is
// RootGrantsNamespace. Existing pair records and their private values stay intact.
type RootGrantsRecord struct {
	Schema              string                `json:"schema"`
	Service             string                `json:"service"`
	Purpose             string                `json:"purpose"`
	Version             int                   `json:"version"`
	Created             string                `json:"created"`
	Profile             string                `json:"profile"`
	Derivation          string                `json:"derivation"`
	Path                string                `json:"path"`
	Algorithm           string                `json:"algorithm"`
	Presence            string                `json:"presence"`
	PublicKey           string                `json:"public_key"`
	SealPublicKey       string                `json:"seal_public_key"`
	SealScript          string                `json:"seal_script"`
	Pair                RootGrantsPairBinding `json:"pair"`
	WrappingPoint       []byte                `json:"wrapping_point"`
	WrappingFingerprint string                `json:"wrapping_fingerprint"`
}

// RootGrantsAddress admits one exact standalone destination, with no newest,
// missing-version default, namespace override or version-selection behavior.
type RootGrantsAddress struct {
	Service string `json:"service"`
	Version int    `json:"version"`
}

func (a RootGrantsAddress) Account() (string, error) {
	return nostrAddress(a.Service, "root-grants", a.Version)
}

func validateRootGrantsPublic(p RootGrantsPublic) error {
	if p.Profile != rootGrantsProfile || p.Derivation != rootGrantsDerivation || p.Path != rootGrantsPath ||
		p.Algorithm != "secp256k1-bip340+ecdsa" || len(p.PublicKey) != 64 || !lowerHex(p.PublicKey, 32) ||
		p.SealPublicKey != "02"+p.PublicKey {
		return recoveryRefuse("invalid_record")
	}
	x, _ := hex.DecodeString(p.PublicKey)
	if _, err := schnorr.ParsePubKey(x); err != nil {
		return recoveryRefuse("invalid_record")
	}
	// K is an x coordinate: validate its field range/point, not scalar range n.
	// Private scalar range and even parity are checked inside KVG1 validation.
	compressed, _ := hex.DecodeString(p.SealPublicKey)
	if p.SealScript != "76a914"+hex.EncodeToString(recoveryHash160(compressed))+"88ac" {
		return recoveryRefuse("invalid_record")
	}
	return nil
}

func validateRootGrantsPair(p RootGrantsPairBinding) error {
	if p.Schema != "keyvault-recovery/1" && p.Schema != "keyvault-recovery/2" {
		return recoveryRefuse("retained_record_mismatch")
	}
	for _, a := range []struct {
		service, purpose string
		version          int
	}{{p.Service, "recovery", p.Version}, {p.NostrIdentity, "nostr", p.NostrVersion}, {p.NamecoinIdentity, "namecoin", p.NamecoinVersion}} {
		if _, err := nostrAddress(a.service, a.purpose, a.version); err != nil {
			return recoveryRefuse("retained_record_mismatch")
		}
	}
	if p.NostrIdentity != p.Service || (p.Schema == "keyvault-recovery/1" && p.NamecoinIdentity != p.Service) ||
		len(p.GroupID) != 32 || len(p.MetadataSHA256) != 64 || len(p.NostrPublicKey) != 64 ||
		!lowerHex(p.GroupID, 16) || !lowerHex(p.MetadataSHA256, 32) || !lowerHex(p.NostrPublicKey, 32) ||
		!validRecoveryNamecoinPins(p.NamecoinXPub, p.NamecoinOrigin) {
		return recoveryRefuse("retained_record_mismatch")
	}
	key, _ := hex.DecodeString(p.NostrPublicKey)
	npub, err := NostrNPub(key)
	if err != nil || npub != p.NostrNPub {
		return recoveryRefuse("retained_record_mismatch")
	}
	return nil
}

func (r RootGrantsRecord) publicRoot() RootGrantsPublic {
	return RootGrantsPublic{Profile: r.Profile, Derivation: r.Derivation, Path: r.Path, Algorithm: r.Algorithm,
		PublicKey: r.PublicKey, SealPublicKey: r.SealPublicKey, SealScript: r.SealScript}
}

func validateRootGrantsRecord(r RootGrantsRecord) error {
	if _, err := (RootGrantsAddress{Service: r.Service, Version: r.Version}).Account(); err != nil {
		return recoveryRefuse("invalid_record")
	}
	if len(r.Created) != 20 {
		return recoveryRefuse("invalid_record")
	}
	t, err := time.Parse(time.RFC3339, r.Created)
	if err != nil || t.UTC().Format(time.RFC3339) != r.Created || r.Schema != "keyvault-root-grants/1" ||
		r.Purpose != "root-grants" || r.Presence != "biometry-any-per-signature" ||
		validateRootGrantsPublic(r.publicRoot()) != nil || validateRootGrantsPair(r.Pair) != nil ||
		validateWrapping(r.WrappingPoint, r.WrappingFingerprint) != nil {
		return recoveryRefuse("invalid_record")
	}
	return nil
}

// NewRootGrantsRecord constructs public metadata only; it certifies neither
// owner enrollment nor seal authenticity. Every identity/version is explicit.
func NewRootGrantsRecord(address RootGrantsAddress, created string, public RootGrantsPreparationPublic, wrappingPoint []byte) (RootGrantsRecord, error) {
	if len(wrappingPoint) != 65 {
		return RootGrantsRecord{}, recoveryRefuse("invalid_record")
	}
	fingerprint := sha256.Sum256(wrappingPoint)
	r := RootGrantsRecord{
		Schema: "keyvault-root-grants/1", Service: address.Service, Purpose: "root-grants", Version: address.Version,
		Created: created, Profile: public.Root.Profile, Derivation: public.Root.Derivation, Path: public.Root.Path,
		Algorithm: public.Root.Algorithm, Presence: "biometry-any-per-signature", PublicKey: public.Root.PublicKey,
		SealPublicKey: public.Root.SealPublicKey, SealScript: public.Root.SealScript, Pair: public.Pair,
		WrappingPoint: bytes.Clone(wrappingPoint), WrappingFingerprint: hex.EncodeToString(fingerprint[:]),
	}
	if err := validateRootGrantsRecord(r); err != nil {
		return RootGrantsRecord{}, err
	}
	return r, nil
}

func CanonicalRootGrantsRecord(r RootGrantsRecord) ([]byte, error) {
	if err := validateRootGrantsRecord(r); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > recoveryMaxMetadata {
		return nil, recoveryRefuse("invalid_record")
	}
	return raw, nil
}

func ParseRootGrantsRecord(raw []byte) (RootGrantsRecord, error) {
	var r RootGrantsRecord
	if len(raw) == 0 || len(raw) > recoveryMaxMetadata || DecodeSingleJSON(raw, &r) != nil {
		return RootGrantsRecord{}, recoveryRefuse("invalid_record")
	}
	canonical, err := CanonicalRootGrantsRecord(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return RootGrantsRecord{}, recoveryRefuse("invalid_record")
	}
	return r, nil
}

func rootGrantsMatchPair(raw []byte, expected RootGrantsPairBinding) error {
	r, err := parseRecoveryRecord(raw)
	if err != nil || rootGrantsPairBinding(raw, r) != expected {
		return recoveryRefuse("retained_record_mismatch")
	}
	return nil
}

// RootGrantsProjection contains only public role/address/pin data. It omits the
// device blob, ciphertext, wrapping metadata and every private capability.
type RootGrantsProjection struct {
	Namespace     string                `json:"namespace"`
	Account       string                `json:"account"`
	Profile       string                `json:"profile"`
	Derivation    string                `json:"derivation"`
	Path          string                `json:"path"`
	PublicKey     string                `json:"public_key"`
	SealPublicKey string                `json:"seal_public_key"`
	SealScript    string                `json:"seal_script"`
	Pair          RootGrantsPairBinding `json:"pair"`
}

func rootGrantsProject(r RootGrantsRecord) RootGrantsProjection {
	account, _ := (RootGrantsAddress{Service: r.Service, Version: r.Version}).Account()
	return RootGrantsProjection{Namespace: RootGrantsNamespace, Account: account, Profile: r.Profile, Derivation: r.Derivation,
		Path: r.Path, PublicKey: r.PublicKey, SealPublicKey: r.SealPublicKey, SealScript: r.SealScript, Pair: r.Pair}
}

type RootGrantsPublicExport struct {
	Root              RootGrantsProjection `json:"root"`
	IDValueUTF8       string               `json:"id_value_utf8"`
	IDValueByteLength int                  `json:"id_value_byte_length"`
	IDValueSHA256     string               `json:"id_value_sha256"`
}

// ExportRootGrants rechecks the exact retained public pair and external binding
// before building the compact LIP value. Callers must independently authenticate
// record lookup and expected pins; this pure constructor is not a vault lookup,
// owner enrollment, publication or proof of seal authenticity.
func ExportRootGrants(r RootGrantsRecord, pairMetadata []byte, expected RootGrantsPairBinding) (RootGrantsPublicExport, error) {
	if validateRootGrantsRecord(r) != nil || r.Pair != expected || rootGrantsMatchPair(pairMetadata, expected) != nil {
		return RootGrantsPublicExport{}, recoveryRefuse("retained_record_mismatch")
	}
	value := `{"nostr":{"names":{"_":"` + expected.NostrPublicKey + `"}},"swarma":{"landlord":{"grant":"` + r.PublicKey + `"}}}`
	if len(value) > 520 {
		return RootGrantsPublicExport{}, recoveryRefuse("limit_exceeded")
	}
	h := sha256.Sum256([]byte(value))
	return RootGrantsPublicExport{Root: rootGrantsProject(r), IDValueUTF8: value, IDValueByteLength: len(value), IDValueSHA256: hex.EncodeToString(h[:])}, nil
}
