package keyvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	AgentNostrNamespace         = "works.relux.mac-keyvault.agent-nostr.v1"
	AgentNostrRecordSchema      = "agent-nostr-key/1"
	AgentNostrReceiptSchema     = "agent-nostr-enrollment/1"
	AgentNostrEnvelopeSchema    = "keyvault-agent-nostr-envelope/1"
	AgentNostrAlgorithm         = "secp256k1-bip340"
	AgentNostrStorage           = "enclave-wrapped-keychain"
	AgentNostrEnvelopeAlgorithm = "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM"
	AgentNostrMaxMetadata       = 8192
	AgentNostrMaxReceipt        = 8192
	AgentNostrMaxEnvelope       = 32768
	AgentNostrMaxBlob           = 16384
	AgentNostrMaxPublicOutput   = 1048576
	AgentNostrPlaintextSize     = 69
	AgentNostrCiphertextSize    = 150
)

const (
	AgentNostrCodeInvalidInput       = "invalid_input"
	AgentNostrCodeInvalidEnrollment  = "invalid_enrollment"
	AgentNostrCodeEnrollmentMismatch = "enrollment_mismatch"
	AgentNostrCodeDuplicate          = "duplicate"
	AgentNostrCodeNotFound           = "not_found"
	AgentNostrCodeCorruptRecord      = "corrupt_record"
	AgentNostrCodeUnavailable        = "unavailable"
	AgentNostrCodeUntrusted          = "untrusted"
	AgentNostrCodeUnknown            = "unknown"
)

var agentNostrScalarOrder = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

var errAgentNostrRawSizeLimit = errors.New("agent Nostr raw input exceeds size limit")

func decodeAgentNostrRawWithinLimit(raw []byte, limit int, target any, decode func([]byte, any) error) error {
	if len(raw) == 0 || len(raw) > limit {
		return errAgentNostrRawSizeLimit
	}
	return decode(raw, target)
}

type AgentNostrRecord struct {
	Schema              string `json:"schema"`
	Namespace           string `json:"namespace"`
	Service             string `json:"service"`
	Purpose             string `json:"purpose"`
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
	Storage             string `json:"storage"`
	Presence            bool   `json:"presence"`
	PrivateExport       bool   `json:"private_export"`
	Created             string `json:"created"`
	PublicKey           string `json:"public_key"`
	NPub                string `json:"npub"`
	WrappingPoint       string `json:"wrapping_point"`
	WrappingFingerprint string `json:"wrapping_fingerprint"`
}

type AgentNostrEnrollment struct {
	Schema            string `json:"schema"`
	OwnerMXID         string `json:"owner_mxid"`
	Service           string `json:"service"`
	Purpose           string `json:"purpose"`
	Version           int    `json:"version"`
	PublicKey         string `json:"public_key"`
	KeySHA256         string `json:"key_sha256"`
	RecordFingerprint string `json:"record_fingerprint"`
}

type AgentNostrEnvelope struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	EnclaveBlob string `json:"enclave_blob"`
	Point       string `json:"point"`
	Fingerprint string `json:"fingerprint"`
	Ciphertext  string `json:"ciphertext"`
}

type AgentNostrPublic struct {
	Record            AgentNostrRecord `json:"record"`
	RecordFingerprint string           `json:"record_fingerprint"`
	KeySHA256         string           `json:"key_sha256"`
}

type AgentNostrSignature struct {
	Algorithm         string `json:"algorithm"`
	Signature         string `json:"signature"`
	RecordFingerprint string `json:"record_fingerprint"`
	KeySHA256         string `json:"key_sha256"`
}

type AgentNostrWrap struct {
	Blob          []byte
	Point         []byte
	Fingerprint   string
	Policy        string
	SilentRefused bool
}

type AgentNostrItem struct {
	Account  string
	Metadata []byte
}

// AgentNostrSelection retains one physical item between its public metadata
// read and its ciphertext read. Implementations must read the value from that
// same retained item and recheck its metadata and ACL before releasing it.
type AgentNostrSelection interface {
	Metadata() []byte
	LoadEnvelope() (metadata, envelope []byte, err error)
	Close()
}

// AgentNostrStore is a closed interface over the new physical namespace.
// It has no legacy/recovery lookup, delete, update, or raw-private operation.
// AddAgentNostr reports whether the atomic add was entered; a known native
// refusal may still prove no effect, while an unclassified error after entry
// leaves the result unknown.
type AgentNostrStore interface {
	ListAgentNostr() ([]AgentNostrItem, error)
	SelectAgentNostr(account string) (AgentNostrSelection, error)
	AddAgentNostr(account string, metadata, envelope []byte) (mutationAttempted bool, err error)
}

// AgentNostrPrivate is the typed Go boundary to the separately admitted
// private helper route.
type AgentNostrPrivate interface {
	CreateWrap() (AgentNostrWrap, error)
	UnwrapAgentNostr(AgentNostrEnvelope) ([]byte, error)
}

// AgentNostrPrivateError records only a fixed helper status and whether the
// request crossed the private-release boundary. It never carries raw output.
type AgentNostrPrivateError struct {
	Code       string
	Dispatched bool
}

func (e *AgentNostrPrivateError) Error() string {
	if e == nil {
		return "agent Nostr private operation failed"
	}
	return "agent Nostr private operation failed"
}

// AgentNostrFailure is the closed public failure classification. Candidate
// fields are populated only when outcome is unknown after a possible effect.
type AgentNostrFailure struct {
	Code              string
	Operation         string
	Service           string
	Purpose           string
	Version           int
	Outcome           string
	PublicKey         string
	KeySHA256         string
	RecordFingerprint string
}

func (e *AgentNostrFailure) Error() string {
	if e == nil {
		return "agent Nostr operation failed"
	}
	return "agent_nostr_" + e.Code
}

type AgentNostrManager struct {
	store             AgentNostrStore
	private           AgentNostrPrivate
	lock              Locker
	now               func() time.Time
	random            io.Reader
	sign              func(secret, digest []byte, aux [32]byte) ([]byte, error)
	scalarInRange     func([]byte) bool
	publicFromSecret  func([]byte) ([]byte, error)
	signGuardObserved func(string)
}

func NewAgentNostrManager(store AgentNostrStore, private AgentNostrPrivate, lock Locker) *AgentNostrManager {
	return &AgentNostrManager{
		store: store, private: private, lock: lock, now: time.Now, random: rand.Reader, sign: signNostrWithAux,
		scalarInRange: agentNostrScalarInRange, publicFromSecret: agentNostrPublicFromSecret,
	}
}

func ValidateAgentNostrService(service string) error {
	if ValidateName("service", CodeInvalidService, service) != nil || len(service) > 40 || !strings.HasPrefix(service, "agent-") || len(service) <= len("agent-") {
		return errors.New("invalid agent Nostr service")
	}
	suffix := service[len("agent-"):]
	first := suffix[0]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return errors.New("invalid agent Nostr service")
	}
	return nil
}

func ValidateAgentNostrVersion(version int) error {
	if version < 1 || version > 2147483647 {
		return errors.New("invalid agent Nostr version")
	}
	return nil
}

func AgentNostrAccount(service string, version int) string {
	return service + "/nostr@" + strconv.Itoa(version)
}

func AgentNostrIdentityValid(identity string) bool {
	if len(identity) < 4 || len(identity) > 1024 || !utf8.ValidString(identity) || identity[0] != '@' {
		return false
	}
	colon := strings.IndexByte(identity[1:], ':')
	if colon < 1 || colon+2 >= len(identity) {
		return false
	}
	for _, r := range identity {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func ParseAgentNostrRecord(raw []byte) (AgentNostrRecord, string, error) {
	var record AgentNostrRecord
	if decodeAgentNostrRawWithinLimit(raw, AgentNostrMaxMetadata, &record, DecodeSingleJSON) != nil || validateAgentNostrRecord(record) != nil {
		return AgentNostrRecord{}, "", errors.New("invalid agent Nostr record")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return AgentNostrRecord{}, "", errors.New("noncanonical agent Nostr record")
	}
	return record, sha256Hex(raw), nil
}

func MarshalAgentNostrRecord(record AgentNostrRecord) ([]byte, error) {
	if err := validateAgentNostrRecord(record); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > AgentNostrMaxMetadata {
		return nil, errors.New("invalid agent Nostr record")
	}
	return raw, nil
}

func validateAgentNostrRecord(record AgentNostrRecord) error {
	if record.Schema != AgentNostrRecordSchema || record.Namespace != AgentNostrNamespace || ValidateAgentNostrService(record.Service) != nil ||
		record.Purpose != "nostr" || ValidateAgentNostrVersion(record.Version) != nil || record.Algorithm != AgentNostrAlgorithm ||
		record.Storage != AgentNostrStorage || record.Presence || record.PrivateExport {
		return errors.New("invalid agent Nostr record")
	}
	created, err := time.Parse(time.RFC3339, record.Created)
	if err != nil || created.Format("2006-01-02T15:04:05Z") != record.Created || !strings.HasSuffix(record.Created, "Z") {
		return errors.New("invalid agent Nostr timestamp")
	}
	public, err := hex.DecodeString(record.PublicKey)
	if err != nil || len(public) != 32 || hex.EncodeToString(public) != record.PublicKey {
		return errors.New("invalid agent Nostr public key")
	}
	defer clear(public)
	if _, err := schnorr.ParsePubKey(public); err != nil {
		return errors.New("invalid agent Nostr public key")
	}
	npub, err := NostrNPub(public)
	if err != nil || npub != record.NPub {
		return errors.New("invalid agent Nostr public encoding")
	}
	point, err := decodeAgentNostrBase64(record.WrappingPoint)
	if err != nil || validateWrapping(point, record.WrappingFingerprint) != nil || !lowerHex(record.WrappingFingerprint, 32) {
		return errors.New("invalid agent Nostr wrapping point")
	}
	return nil
}

func ParseAgentNostrEnrollment(raw []byte) (AgentNostrEnrollment, error) {
	var receipt AgentNostrEnrollment
	if decodeAgentNostrRawWithinLimit(raw, AgentNostrMaxReceipt, &receipt, DecodeSingleJSON) != nil || validateAgentNostrEnrollment(receipt) != nil {
		return AgentNostrEnrollment{}, errors.New("invalid agent Nostr enrollment")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(raw, canonical) {
		return AgentNostrEnrollment{}, errors.New("noncanonical agent Nostr enrollment")
	}
	return receipt, nil
}

func MarshalAgentNostrEnrollment(receipt AgentNostrEnrollment) ([]byte, error) {
	if err := validateAgentNostrEnrollment(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > AgentNostrMaxReceipt {
		return nil, errors.New("invalid agent Nostr enrollment")
	}
	return raw, nil
}

func validateAgentNostrEnrollment(receipt AgentNostrEnrollment) error {
	if receipt.Schema != AgentNostrReceiptSchema || !AgentNostrIdentityValid(receipt.OwnerMXID) || ValidateAgentNostrService(receipt.Service) != nil ||
		receipt.Purpose != "nostr" || ValidateAgentNostrVersion(receipt.Version) != nil || !lowerHex(receipt.PublicKey, 32) ||
		!lowerHex(receipt.KeySHA256, 32) || !lowerHex(receipt.RecordFingerprint, 32) {
		return errors.New("invalid agent Nostr enrollment")
	}
	public, err := hex.DecodeString(receipt.PublicKey)
	if err != nil {
		return errors.New("invalid agent Nostr enrollment")
	}
	if _, err := schnorr.ParsePubKey(public); err != nil {
		return errors.New("invalid agent Nostr enrollment")
	}
	if subtle.ConstantTimeCompare([]byte(receipt.KeySHA256), []byte(sha256Hex(public))) != 1 {
		return errors.New("invalid agent Nostr enrollment")
	}
	return nil
}

func ParseAgentNostrEnvelope(raw []byte, record AgentNostrRecord) (AgentNostrEnvelope, error) {
	var envelope AgentNostrEnvelope
	if decodeAgentNostrRawWithinLimit(raw, AgentNostrMaxEnvelope, &envelope, DecodeSingleJSON) != nil || validateAgentNostrEnvelope(envelope, record) != nil {
		return AgentNostrEnvelope{}, errors.New("invalid agent Nostr envelope")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return AgentNostrEnvelope{}, errors.New("noncanonical agent Nostr envelope")
	}
	return envelope, nil
}

func MarshalAgentNostrEnvelope(envelope AgentNostrEnvelope, record AgentNostrRecord) ([]byte, error) {
	if err := validateAgentNostrEnvelope(envelope, record); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > AgentNostrMaxEnvelope {
		return nil, errors.New("invalid agent Nostr envelope")
	}
	return raw, nil
}

func validateAgentNostrEnvelope(envelope AgentNostrEnvelope, record AgentNostrRecord) error {
	if validateAgentNostrRecord(record) != nil || envelope.Schema != AgentNostrEnvelopeSchema || envelope.Algorithm != AgentNostrEnvelopeAlgorithm {
		return errors.New("invalid agent Nostr envelope header")
	}
	blob, err := decodeAgentNostrBase64(envelope.EnclaveBlob)
	if err != nil || len(blob) < 1 || len(blob) > AgentNostrMaxBlob {
		clear(blob)
		return errors.New("invalid agent Nostr envelope blob")
	}
	defer clear(blob)
	point, err := decodeAgentNostrBase64(envelope.Point)
	if err != nil || len(point) != 65 || envelope.Point != record.WrappingPoint || envelope.Fingerprint != record.WrappingFingerprint || validateWrapping(point, envelope.Fingerprint) != nil {
		clear(point)
		return errors.New("invalid agent Nostr envelope point")
	}
	defer clear(point)
	ciphertext, err := decodeAgentNostrBase64(envelope.Ciphertext)
	if err != nil || len(ciphertext) != AgentNostrCiphertextSize {
		clear(ciphertext)
		return errors.New("invalid agent Nostr ciphertext")
	}
	defer clear(ciphertext)
	return nil
}

func AgentNostrPublicResult(record AgentNostrRecord, metadata []byte) AgentNostrPublic {
	public, _ := hex.DecodeString(record.PublicKey)
	return AgentNostrPublic{Record: record, RecordFingerprint: sha256Hex(metadata), KeySHA256: sha256Hex(public)}
}

func AgentNostrEnrollmentMatches(receipt AgentNostrEnrollment, identity, service string, version int, record AgentNostrRecord, recordFingerprint, keyHash string) bool {
	return AgentNostrIdentityValid(identity) && receipt.OwnerMXID == identity && receipt.Service == service && receipt.Purpose == "nostr" && receipt.Version == version &&
		receipt.PublicKey == record.PublicKey && subtle.ConstantTimeCompare([]byte(receipt.KeySHA256), []byte(keyHash)) == 1 &&
		subtle.ConstantTimeCompare([]byte(receipt.RecordFingerprint), []byte(recordFingerprint)) == 1
}

func (m *AgentNostrManager) List() ([]AgentNostrPublic, error) {
	records, err := m.listRecords()
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (m *AgentNostrManager) listRecords() ([]AgentNostrPublic, error) {
	if m == nil || m.store == nil {
		return nil, agentNostrFailure(AgentNostrCodeUnavailable, "", "", 0)
	}
	items, err := m.store.ListAgentNostr()
	if err != nil {
		return nil, agentNostrMapStoreError(err)
	}
	rows := make([]AgentNostrPublic, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		record, fingerprint, err := ParseAgentNostrRecord(item.Metadata)
		if err != nil || item.Account != AgentNostrAccount(record.Service, record.Version) {
			return nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "", "", 0)
		}
		account := AgentNostrAccount(record.Service, record.Version)
		if seen[account] {
			return nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "", "", 0)
		}
		seen[account] = true
		public := AgentNostrPublicResult(record, item.Metadata)
		if public.RecordFingerprint != fingerprint {
			return nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "", "", 0)
		}
		rows = append(rows, public)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Record.Service != rows[j].Record.Service {
			return rows[i].Record.Service < rows[j].Record.Service
		}
		return rows[i].Record.Version < rows[j].Record.Version
	})
	return rows, nil
}

func (m *AgentNostrManager) Describe(service string, version int) (AgentNostrPublic, error) {
	if ValidateAgentNostrService(service) != nil || ValidateAgentNostrVersion(version) != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeInvalidInput, "", service, version)
	}
	if m == nil || m.store == nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "describe", service, version)
	}
	account := AgentNostrAccount(service, version)
	selection, err := m.store.SelectAgentNostr(account)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeNotFound, "describe", service, version)
		}
		return AgentNostrPublic{}, agentNostrMapStoreError(err)
	}
	if selection == nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "describe", service, version)
	}
	defer selection.Close()
	metadata := selection.Metadata()
	record, fingerprint, err := ParseAgentNostrRecord(metadata)
	if err != nil || AgentNostrAccount(record.Service, record.Version) != account {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "describe", service, version)
	}
	public := AgentNostrPublicResult(record, metadata)
	if public.RecordFingerprint != fingerprint {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "describe", service, version)
	}
	return public, nil
}

func (m *AgentNostrManager) Generate(service string, version int) (AgentNostrPublic, error) {
	if ValidateAgentNostrService(service) != nil || ValidateAgentNostrVersion(version) != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeInvalidInput, "generate", service, version)
	}
	if m == nil || m.store == nil || m.private == nil || m.lock == nil || m.random == nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	release, err := m.lock.Lock()
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	defer release()
	rows, err := m.listRecords()
	if err != nil {
		return AgentNostrPublic{}, err
	}
	for _, row := range rows {
		if row.Record.Service == service && row.Record.Version == version {
			return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeDuplicate, "generate", service, version)
		}
	}
	secret, publicBytes, err := agentNostrNewSecret(m.random)
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	defer clear(secret)
	keyHash := sha256Hex(publicBytes)
	privateWrap, err := m.private.CreateWrap()
	defer clear(privateWrap.Blob)
	defer clear(privateWrap.Point)
	if err != nil {
		return AgentNostrPublic{}, agentNostrPrivateFailure(err, "generate", service, version, hex.EncodeToString(publicBytes), keyHash, "")
	}
	if err := validateAgentNostrWrap(privateWrap); err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUntrusted, "generate", service, version)
	}
	npub, err := NostrNPub(publicBytes)
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	created := m.now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	record := AgentNostrRecord{
		Schema: AgentNostrRecordSchema, Namespace: AgentNostrNamespace, Service: service, Purpose: "nostr", Version: version,
		Algorithm: AgentNostrAlgorithm, Storage: AgentNostrStorage, Presence: false, PrivateExport: false, Created: created,
		PublicKey: hex.EncodeToString(publicBytes), NPub: npub, WrappingPoint: base64.StdEncoding.EncodeToString(privateWrap.Point), WrappingFingerprint: privateWrap.Fingerprint,
	}
	metadata, err := MarshalAgentNostrRecord(record)
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	fingerprint := sha256Hex(metadata)
	plaintext := make([]byte, AgentNostrPlaintextSize)
	copy(plaintext[:5], []byte("KVAN1"))
	metadataHash := sha256.Sum256(metadata)
	copy(plaintext[5:37], metadataHash[:])
	copy(plaintext[37:], secret)
	defer clear(plaintext)
	ciphertext, err := agentNostrSeal(privateWrap.Point, plaintext, m.random)
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	envelope := AgentNostrEnvelope{
		Schema: AgentNostrEnvelopeSchema, Algorithm: AgentNostrEnvelopeAlgorithm,
		EnclaveBlob: base64.StdEncoding.EncodeToString(privateWrap.Blob),
		Point:       record.WrappingPoint, Fingerprint: record.WrappingFingerprint,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	clear(ciphertext)
	envelopeBytes, err := MarshalAgentNostrEnvelope(envelope, record)
	if err != nil {
		return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
	}
	defer clear(envelopeBytes)
	account := AgentNostrAccount(service, version)
	mutationAttempted, err := m.store.AddAgentNostr(account, metadata, envelopeBytes)
	if err != nil {
		var failure *AgentNostrFailure
		if errors.As(err, &failure) {
			switch failure.Code {
			case AgentNostrCodeDuplicate:
				return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeDuplicate, "generate", service, version)
			case AgentNostrCodeCorruptRecord, AgentNostrCodeUntrusted, AgentNostrCodeUnavailable:
				return AgentNostrPublic{}, agentNostrFailure(failure.Code, "generate", service, version)
			case AgentNostrCodeNotFound:
				return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
			case AgentNostrCodeUnknown:
				if mutationAttempted {
					return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
				}
				return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
			}
		}
		if errors.Is(err, ErrNotFound) {
			return AgentNostrPublic{}, agentNostrFailure(AgentNostrCodeUnavailable, "generate", service, version)
		}
		if mutationAttempted {
			return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
		}
		return AgentNostrPublic{}, agentNostrMapStoreError(err)
	}
	if !mutationAttempted {
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	selection, err := m.store.SelectAgentNostr(account)
	if err != nil || selection == nil {
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	defer selection.Close()
	readbackMetadata := selection.Metadata()
	if !bytes.Equal(readbackMetadata, metadata) {
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	metadataAgain, envelopeAgain, err := selection.LoadEnvelope()
	if err != nil || !bytes.Equal(metadataAgain, metadata) || !bytes.Equal(envelopeAgain, envelopeBytes) {
		clear(envelopeAgain)
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	defer clear(envelopeAgain)
	readbackRecord, readbackFingerprint, err := ParseAgentNostrRecord(metadataAgain)
	if err != nil || readbackRecord != record || readbackFingerprint != fingerprint {
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	if _, err := ParseAgentNostrEnvelope(envelopeAgain, readbackRecord); err != nil {
		return AgentNostrPublic{}, agentNostrUnknown("generate", service, version, record.PublicKey, keyHash, fingerprint)
	}
	return AgentNostrPublicResult(record, metadata), nil
}

func (m *AgentNostrManager) Sign(identity string, receipt AgentNostrEnrollment, service string, version int, digest []byte) (AgentNostrSignature, error) {
	if ValidateAgentNostrService(service) != nil || ValidateAgentNostrVersion(version) != nil || len(digest) != 32 {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeInvalidInput, "sign", service, version)
	}
	if validateAgentNostrEnrollment(receipt) != nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeInvalidEnrollment, "sign", service, version)
	}
	if !AgentNostrEnrollmentMatches(receipt, identity, service, version, AgentNostrRecord{PublicKey: receipt.PublicKey}, receipt.RecordFingerprint, receipt.KeySHA256) {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeEnrollmentMismatch, "sign", service, version)
	}
	if m == nil || m.store == nil || m.private == nil || m.lock == nil || m.random == nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeUnavailable, "sign", service, version)
	}
	release, err := m.lock.Lock()
	if err != nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeUnavailable, "sign", service, version)
	}
	defer release()
	account := AgentNostrAccount(service, version)
	selection, err := m.store.SelectAgentNostr(account)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeNotFound, "sign", service, version)
		}
		return AgentNostrSignature{}, agentNostrMapStoreError(err)
	}
	if selection == nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	defer selection.Close()
	metadata := selection.Metadata()
	record, fingerprint, err := ParseAgentNostrRecord(metadata)
	if err != nil || AgentNostrAccount(record.Service, record.Version) != account {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	public := AgentNostrPublicResult(record, metadata)
	if !AgentNostrEnrollmentMatches(receipt, identity, service, version, record, fingerprint, public.KeySHA256) {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeEnrollmentMismatch, "sign", service, version)
	}
	metadataAgain, envelopeBytes, err := selection.LoadEnvelope()
	defer clear(envelopeBytes)
	if err != nil {
		return AgentNostrSignature{}, agentNostrMapStoreError(err)
	}
	if !bytes.Equal(metadata, metadataAgain) {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeEnrollmentMismatch, "sign", service, version)
	}
	envelope, err := ParseAgentNostrEnvelope(envelopeBytes, record)
	if err != nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	plaintext, err := m.private.UnwrapAgentNostr(envelope)
	if err != nil {
		clear(plaintext)
		return AgentNostrSignature{}, agentNostrPrivateFailure(err, "sign", service, version, record.PublicKey, public.KeySHA256, fingerprint)
	}
	defer clear(plaintext)
	if len(plaintext) != AgentNostrPlaintextSize || !bytes.Equal(plaintext[:5], []byte("KVAN1")) {
		m.observeAgentNostrSignGuard("domain")
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	metadataHash := sha256.Sum256(metadata)
	if subtle.ConstantTimeCompare(plaintext[5:37], metadataHash[:]) != 1 {
		m.observeAgentNostrSignGuard("metadata-binding")
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	secret := plaintext[37:]
	scalarInRange := m.scalarInRange
	if scalarInRange == nil {
		scalarInRange = agentNostrScalarInRange
	}
	if !scalarInRange(secret) {
		m.observeAgentNostrSignGuard("scalar-range")
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	publicFromSecret := m.publicFromSecret
	if publicFromSecret == nil {
		publicFromSecret = agentNostrPublicFromSecret
	}
	actualPublic, err := publicFromSecret(secret)
	if err != nil {
		m.observeAgentNostrSignGuard("private-scalar-construction")
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	defer clear(actualPublic)
	expectedPublic, _ := hex.DecodeString(record.PublicKey)
	defer clear(expectedPublic)
	if subtle.ConstantTimeCompare(actualPublic, expectedPublic) != 1 {
		m.observeAgentNostrSignGuard("public-key-match")
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	var aux [32]byte
	if _, err := io.ReadFull(m.random, aux[:]); err != nil {
		clear(aux[:])
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeUnavailable, "sign", service, version)
	}
	defer clear(aux[:])
	if m.sign == nil {
		clear(aux[:])
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeUnavailable, "sign", service, version)
	}
	signature, err := m.sign(secret, digest, aux)
	if err != nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeUnavailable, "sign", service, version)
	}
	if VerifyNostr(expectedPublic, digest, signature) != nil {
		return AgentNostrSignature{}, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", service, version)
	}
	return AgentNostrSignature{Algorithm: AgentNostrAlgorithm, Signature: hex.EncodeToString(signature), RecordFingerprint: fingerprint, KeySHA256: public.KeySHA256}, nil
}

func (m *AgentNostrManager) observeAgentNostrSignGuard(guard string) {
	if m != nil && m.signGuardObserved != nil {
		m.signGuardObserved(guard)
	}
}

func agentNostrNewSecret(random io.Reader) ([]byte, []byte, error) {
	if random == nil {
		return nil, nil, errors.New("random source unavailable")
	}
	secret := make([]byte, 32)
	defer clear(secret)
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := io.ReadFull(random, secret); err != nil {
			return nil, nil, err
		}
		private, err := nostrPrivate(secret)
		if err != nil {
			continue
		}
		public := schnorr.SerializePubKey(private.PubKey())
		private.Zero()
		return bytes.Clone(secret), public, nil
	}
	return nil, nil, errors.New("random source produced no valid scalar")
}

func agentNostrScalarInRange(secret []byte) bool {
	if len(secret) != len(agentNostrScalarOrder) {
		return false
	}
	less, equal, nonzero := 0, 1, 0
	for i, limit := range agentNostrScalarOrder {
		value := int(secret[i])
		less |= equal & subtle.ConstantTimeLessOrEq(value+1, int(limit))
		equal &= subtle.ConstantTimeByteEq(secret[i], limit)
		nonzero |= value
	}
	return less == 1 && subtle.ConstantTimeLessOrEq(1, nonzero) == 1
}

func agentNostrPublicFromSecret(secret []byte) ([]byte, error) {
	privateKey, err := nostrPrivate(secret)
	if err != nil {
		return nil, err
	}
	defer privateKey.Zero()
	return schnorr.SerializePubKey(privateKey.PubKey()), nil
}

func validateAgentNostrWrap(wrap AgentNostrWrap) error {
	if len(wrap.Blob) < 1 || len(wrap.Blob) > AgentNostrMaxBlob || len(wrap.Point) != 65 || wrap.Policy != "none" || wrap.SilentRefused ||
		!lowerHex(wrap.Fingerprint, 32) || validateWrapping(wrap.Point, wrap.Fingerprint) != nil {
		return errors.New("invalid agent Nostr wrap result")
	}
	return nil
}

func agentNostrSeal(wrappingPoint, plaintext []byte, random io.Reader) ([]byte, error) {
	if len(plaintext) != AgentNostrPlaintextSize || len(wrappingPoint) != 65 {
		return nil, errors.New("invalid agent Nostr plaintext or point")
	}
	wrappingKey, err := ecdh.P256().NewPublicKey(wrappingPoint)
	if err != nil {
		return nil, errors.New("invalid agent Nostr wrapping point")
	}
	ephemeral, err := ecdh.P256().GenerateKey(random)
	if err != nil {
		return nil, err
	}
	ephemeralSecret := ephemeral.Bytes()
	defer clear(ephemeralSecret)
	point := ephemeral.PublicKey().Bytes()
	shared, err := ephemeral.ECDH(wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	var sealed []byte
	err = agentNostrWithDerived(shared, point, sha256.Sum256, func(derived []byte) error {
		block, err := aes.NewCipher(derived[:16])
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return err
		}
		sealed = aead.Seal(nil, derived[16:], plaintext, nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := append(bytes.Clone(point), sealed...)
	if len(result) != AgentNostrCiphertextSize {
		clear(result)
		return nil, errors.New("agent Nostr ciphertext size mismatch")
	}
	return result, nil
}

func agentNostrWithDerived(shared, point []byte, hash func([]byte) [32]byte, use func([]byte) error) error {
	transcript := make([]byte, len(shared)+4+len(point))
	defer clear(transcript)
	copy(transcript, shared)
	copy(transcript[len(shared):], []byte{0, 0, 0, 1})
	copy(transcript[len(shared)+4:], point)
	derived := hash(transcript)
	defer clear(derived[:])
	return use(derived[:])
}

func decodeAgentNostrBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("invalid canonical base64")
	}
	return decoded, nil
}

func agentNostrFailure(code, operation, service string, version int) *AgentNostrFailure {
	return &AgentNostrFailure{Code: code, Operation: operation, Service: service, Purpose: "nostr", Version: version}
}

func agentNostrUnknown(operation, service string, version int, publicKey, keyHash, fingerprint string) *AgentNostrFailure {
	return &AgentNostrFailure{Code: AgentNostrCodeUnknown, Operation: operation, Service: service, Purpose: "nostr", Version: version, Outcome: "unknown", PublicKey: publicKey, KeySHA256: keyHash, RecordFingerprint: fingerprint}
}

func agentNostrMapStoreError(err error) *AgentNostrFailure {
	var failure *AgentNostrFailure
	if errors.As(err, &failure) && failure != nil {
		switch failure.Code {
		case AgentNostrCodeDuplicate, AgentNostrCodeNotFound, AgentNostrCodeCorruptRecord, AgentNostrCodeUnavailable, AgentNostrCodeUntrusted:
			return failure
		}
	}
	if errors.Is(err, ErrNotFound) {
		return agentNostrFailure(AgentNostrCodeNotFound, "", "", 0)
	}
	return agentNostrFailure(AgentNostrCodeUnavailable, "", "", 0)
}

func agentNostrPrivateFailure(err error, operation, service string, version int, publicKey, keyHash, fingerprint string) *AgentNostrFailure {
	var privateErr *AgentNostrPrivateError
	if !errors.As(err, &privateErr) {
		return agentNostrUnknown(operation, service, version, publicKey, keyHash, fingerprint)
	}
	switch privateErr.Code {
	case "bad_request", "invalid_blob":
		return agentNostrFailure(AgentNostrCodeCorruptRecord, operation, service, version)
	case "policy_refused", "presence_required", "parent_not_admitted", "not_admitted":
		return agentNostrFailure(AgentNostrCodeUntrusted, operation, service, version)
	case "auth_refused", "enclave_unavailable", "unavailable":
		return agentNostrFailure(AgentNostrCodeUnavailable, operation, service, version)
	default:
		if privateErr.Dispatched {
			return agentNostrUnknown(operation, service, version, publicKey, keyHash, fingerprint)
		}
		return agentNostrFailure(AgentNostrCodeUnavailable, operation, service, version)
	}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
