package keyvault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

const NostrNamespace = "works.relux.mac-keyvault.nostr.v1"

// NostrRecord contains public metadata only. This software key is protected at
// rest by a file-Keychain ACL; it is neither a Secure Enclave key nor a key whose
// use requires user presence. No private export or import operation is provided.
type NostrRecord struct {
	Schema        string `json:"schema"`
	Service       string `json:"service"`
	Purpose       string `json:"purpose"`
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	Storage       string `json:"storage"`
	Presence      bool   `json:"presence"`
	PrivateExport bool   `json:"private_export"`
	Created       string `json:"created"`
	PublicKey     string `json:"public_key"`
	NPub          string `json:"npub"`
}

func nostrRefuse(code string) error {
	return &Refusal{Code: "nostr_" + code, Message: "Nostr operation refused: " + code, Hint: "preserve existing custody; check the public record and selected signed vault binary"}
}

func nostrAddress(service, purpose string, version int) (string, error) {
	if ValidateName("service", CodeInvalidService, service) != nil || ValidateName("purpose", CodeInvalidPurpose, purpose) != nil || version < 1 || version > 2147483647 {
		return "", nostrRefuse("invalid_address")
	}
	return service + "/" + purpose + "@" + strconv.Itoa(version), nil
}

func (r NostrRecord) Account() string {
	account, _ := nostrAddress(r.Service, r.Purpose, r.Version)
	return account
}

func validateNostrRecord(r NostrRecord) error {
	if _, err := nostrAddress(r.Service, r.Purpose, r.Version); err != nil {
		return err
	}
	created, err := time.Parse(time.RFC3339, r.Created)
	if err != nil || created.UTC().Format(time.RFC3339) != r.Created || r.Schema != "nostr-key/1" || r.Algorithm != "secp256k1-bip340" || r.Storage != "keychain-acl" || r.Presence || r.PrivateExport {
		return nostrRefuse("invalid_record")
	}
	pub, err := hex.DecodeString(r.PublicKey)
	if err != nil || hex.EncodeToString(pub) != r.PublicKey {
		return nostrRefuse("invalid_record")
	}
	npub, err := NostrNPub(pub)
	if err != nil || npub != r.NPub {
		return nostrRefuse("invalid_record")
	}
	return nil
}

// NostrNPub encodes a valid BIP-340 x-only public key using NIP-19's original
// bech32 checksum, not bech32m. It never accepts private-key material.
func NostrNPub(public []byte) (string, error) {
	if len(public) != 32 {
		return "", nostrRefuse("invalid_public_key")
	}
	if _, err := schnorr.ParsePubKey(public); err != nil {
		return "", nostrRefuse("invalid_public_key")
	}
	words, err := bech32.ConvertBits(public, 8, 5, true)
	if err != nil {
		return "", nostrRefuse("invalid_public_key")
	}
	return bech32.Encode("npub", words)
}

// VerifyNostr is offline public verification. The module deliberately accepts
// exactly a 32-byte NIP-01 event id, a subset of current BIP-340 message lengths.
func VerifyNostr(public, digest, signature []byte) error {
	if len(digest) != 32 {
		return nostrRefuse("invalid_digest")
	}
	if len(public) != 32 {
		return nostrRefuse("invalid_public_key")
	}
	pub, err := schnorr.ParsePubKey(public)
	if err != nil {
		return nostrRefuse("invalid_public_key")
	}
	if len(signature) != 64 {
		return nostrRefuse("invalid_signature")
	}
	sig, err := schnorr.ParseSignature(signature)
	if err != nil || !sig.Verify(digest, pub) {
		return nostrRefuse("invalid_signature")
	}
	return nil
}

func nostrPrivate(secret []byte) (*btcec.PrivateKey, error) {
	var scalar btcec.ModNScalar
	defer scalar.Zero()
	if len(secret) != 32 || scalar.SetByteSlice(secret) || scalar.IsZero() {
		return nil, nostrRefuse("invalid_secret")
	}
	return btcec.PrivKeyFromScalar(&scalar), nil
}

func signNostrWithAux(secret, digest []byte, aux [32]byte) ([]byte, error) {
	defer clear(aux[:])
	if len(digest) != 32 {
		return nil, nostrRefuse("invalid_digest")
	}
	private, err := nostrPrivate(secret)
	if err != nil {
		return nil, err
	}
	defer private.Zero()
	sig, err := schnorr.Sign(private, digest, schnorr.CustomNonce(aux))
	if err != nil {
		return nil, nostrRefuse("sign_failed")
	}
	return sig.Serialize(), nil
}

func signNostrSecret(rec NostrRecord, secret, digest []byte) ([]byte, error) {
	return signNostrSecretWithRandom(rec, secret, digest, rand.Reader)
}

func signNostrSecretWithRandom(rec NostrRecord, secret, digest []byte, random io.Reader) ([]byte, error) {
	defer clear(secret)
	if len(digest) != 32 {
		return nil, nostrRefuse("invalid_digest")
	}
	if err := validateNostrRecord(rec); err != nil {
		return nil, err
	}
	private, err := nostrPrivate(secret)
	if err != nil {
		return nil, err
	}
	public := schnorr.SerializePubKey(private.PubKey())
	private.Zero()
	expected, _ := hex.DecodeString(rec.PublicKey)
	if subtle.ConstantTimeCompare(public, expected) != 1 {
		return nil, nostrRefuse("key_mismatch")
	}
	var aux [32]byte
	defer clear(aux[:])
	if random == nil {
		return nil, nostrRefuse("random_unavailable")
	}
	if _, err := io.ReadFull(random, aux[:]); err != nil {
		return nil, nostrRefuse("random_unavailable")
	}
	return signNostrWithAux(secret, digest, aux)
}

func newNostrMaterial(r NostrRecord) (NostrRecord, []byte, error) {
	return newNostrMaterialWithRandom(r, rand.Reader)
}

func newNostrMaterialWithRandom(r NostrRecord, random io.Reader) (NostrRecord, []byte, error) {
	if r.PublicKey != "" || r.NPub != "" {
		return NostrRecord{}, nil, nostrRefuse("invalid_record")
	}
	if random == nil {
		return NostrRecord{}, nil, nostrRefuse("random_unavailable")
	}
	secret := make([]byte, 32)
	defer clear(secret)
	var private *btcec.PrivateKey
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := io.ReadFull(random, secret); err != nil {
			return NostrRecord{}, nil, nostrRefuse("random_unavailable")
		}
		var err error
		private, err = nostrPrivate(secret)
		if err == nil {
			break
		}
	}
	if private == nil {
		return NostrRecord{}, nil, nostrRefuse("random_unavailable")
	}
	defer private.Zero()
	public := schnorr.SerializePubKey(private.PubKey())
	r.PublicKey = hex.EncodeToString(public)
	r.NPub, _ = NostrNPub(public)
	if err := validateNostrRecord(r); err != nil {
		return NostrRecord{}, nil, err
	}
	return r, private.Serialize(), nil
}

// NostrBackend exposes only public records and signing, never a secret getter.
// Create generates the scalar inside the vault backend and atomically refuses
// an existing account. Implementations must not upsert or expand an ACL.
type NostrBackend interface {
	Create(NostrRecord) (NostrRecord, error)
	List() ([]NostrRecord, error)
	Sign(NostrRecord, []byte) ([]byte, error)
}

type NostrManager struct {
	backend NostrBackend
	lock    Locker
	now     func() time.Time
}

func NewNostrManager(backend NostrBackend, lock Locker) *NostrManager {
	return &NostrManager{backend: backend, lock: lock, now: time.Now}
}

func (m *NostrManager) List() ([]NostrRecord, error) {
	if m.backend == nil {
		return nil, nostrRefuse("store_unavailable")
	}
	records, err := m.backend.List()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range records {
		if err := validateNostrRecord(r); err != nil {
			return nil, err
		}
		if seen[r.Account()] {
			return nil, nostrRefuse("duplicate")
		}
		seen[r.Account()] = true
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Account() < records[j].Account() })
	return records, nil
}

func (m *NostrManager) Describe(service, purpose string, version int) (NostrRecord, error) {
	account, err := nostrAddress(service, purpose, version)
	if err != nil {
		return NostrRecord{}, err
	}
	records, err := m.List()
	if err != nil {
		return NostrRecord{}, err
	}
	for _, r := range records {
		if r.Account() == account {
			return r, nil
		}
	}
	return NostrRecord{}, ErrNotFound
}

func (m *NostrManager) Generate(service, purpose string, version int) (NostrRecord, error) {
	if _, err := nostrAddress(service, purpose, version); err != nil {
		return NostrRecord{}, err
	}
	if m.lock == nil || m.backend == nil {
		return NostrRecord{}, nostrRefuse("store_unavailable")
	}
	release, err := m.lock.Lock()
	if err != nil {
		return NostrRecord{}, nostrRefuse("lock_unavailable")
	}
	defer release()
	_, err = m.Describe(service, purpose, version)
	if err == nil {
		return NostrRecord{}, nostrRefuse("duplicate")
	}
	if !errors.Is(err, ErrNotFound) {
		return NostrRecord{}, err
	}
	r := NostrRecord{Schema: "nostr-key/1", Service: service, Purpose: purpose, Version: version, Algorithm: "secp256k1-bip340", Storage: "keychain-acl", Created: m.now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	created, err := m.backend.Create(r)
	if err != nil {
		return NostrRecord{}, err
	}
	if created.Account() != r.Account() || created.Created != r.Created {
		return NostrRecord{}, nostrRefuse("invalid_record")
	}
	if err := validateNostrRecord(created); err != nil {
		return NostrRecord{}, err
	}
	return created, nil
}

func (m *NostrManager) Sign(service, purpose string, version int, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, nostrRefuse("invalid_digest")
	}
	r, err := m.Describe(service, purpose, version)
	if err != nil {
		return nil, err
	}
	sig, err := m.backend.Sign(r, digest)
	if err != nil {
		return nil, err
	}
	pub, _ := hex.DecodeString(r.PublicKey)
	if err := VerifyNostr(pub, digest, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// parseNostrList reads only attributes returned by the native metadata query.
// The service namespace is fixed natively; each account must match its record.
func parseNostrList(raw []byte) ([]NostrRecord, error) {
	records := []NostrRecord{}
	if len(raw) > 4*1024*1024 {
		return nil, nostrRefuse("invalid_record")
	}
	for _, row := range strings.Split(string(raw), "\x1e") {
		if row == "" {
			continue
		}
		fields := strings.Split(row, "\x1f")
		if len(fields) != 2 || len(fields[1]) > 4096 {
			return nil, nostrRefuse("invalid_record")
		}
		var r NostrRecord
		if DecodeSingleJSON([]byte(fields[1]), &r) != nil || validateNostrRecord(r) != nil || fields[0] != r.Account() {
			return nil, nostrRefuse("invalid_record")
		}
		canonical, _ := json.Marshal(r)
		if string(canonical) != fields[1] {
			return nil, nostrRefuse("invalid_record")
		}
		records = append(records, r)
	}
	return records, nil
}
