// Package keyvault manages non-extractable P-256 key pairs in the login
// keychain for mac-keyvault. Every item carries a schema-2 record in its
// application tag. Policy gates (namespace, record validation, duplicate
// labels, delete confirmation, explicit Secure Enclave refusal, unknown
// metadata on rotate) live in Manager so they run before any
// Security.framework call.
package keyvault

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LabelPrefix is the only namespace mac-keyvault creates, lists, or deletes.
const LabelPrefix = signerclient.LabelPrefix

// TestService is the service every test record uses; test labels are
// works.relux.mac-keyvault.<kind>.test.<purpose>.v<N>. TestLabelPrefix is
// the key-kind form of that namespace.
const (
	TestService     = "test"
	TestLabelPrefix = LabelPrefix + KindKey + "." + TestService + "."
)

// IsTestLabel reports whether label belongs to the test namespace: a
// parseable label with service "test", or a rev1-era label under
// works.relux.mac-keyvault.test. that a cleanup may still need to remove.
func IsTestLabel(label string) bool {
	if parsed, ok := ParseLabel(label); ok {
		return parsed.Service == TestService
	}
	legacy := LabelPrefix + TestService + "."
	return strings.HasPrefix(label, legacy) && len(label) > len(legacy)
}

// errSecMissingEntitlement is Security.framework's answer when the calling
// binary lacks the provisioning profile the Data Protection keychain and the
// Secure Enclave require.
const errSecMissingEntitlement = -34018

const errSecItemNotFound = -25300

// errSecParam is what ECIES decryption answers for an envelope that fails
// its GCM tag: tampered, truncated or made for another key.
const errSecParam = -50

// StoreKind names where a key pair lives.
type StoreKind = signerclient.StoreKind

const (
	StoreKeychain = signerclient.StoreKeychain
	StoreEnclave  = signerclient.StoreEnclave
	StoreUnknown  = signerclient.StoreUnknown
)

// Item is what the Backend stores: a label, the raw application tag, and the
// DER SubjectPublicKeyInfo of the public half (empty when unreadable).
// Problem is set when the store could not trust the item at all (an unsafe
// or unreadable Secure Enclave key file); such an item is listed, never used.
type Item struct {
	Label   string
	Tag     []byte
	SPKI    []byte
	Problem string
}

// Key is one managed item with its decoded record.
type Key struct {
	Label  string
	Record Record
	SPKI   []byte
	// RecordProblem is non-empty when the tag was present but unreadable;
	// an absent tag is not a problem, it is schema 0.
	RecordProblem string
}

// Fingerprint is base64url(SHA-256(DER(SPKI))) without padding, or "" when
// the SPKI is unknown.
func (k Key) Fingerprint() string {
	if len(k.SPKI) == 0 {
		return ""
	}
	return signerclient.Fingerprint(k.SPKI)
}

// Findings lists what a reader must know about the record beyond its fields.
func (k Key) Findings(now time.Time) ([]Operation, []string) {
	ops, findings := Operations(k.Record, now)
	if k.RecordProblem != "" {
		findings = append(findings, FindingRecordUnreadable)
	}
	// A readable schema-2 record that violates a per-kind invariant is
	// reported, not hidden: reads show record_invalid:<code>, and the
	// write paths (rotate, meta) refuse the same record.
	if k.RecordProblem == "" && k.Record.Schema == SchemaVersion {
		if err := ValidateStored(k.Label, k.Record); err != nil {
			findings = append(findings, FindingRecordInvalid+":"+refusalCodeOf(err))
		}
	}
	return ops, findings
}

// refusalCodeOf names the code of a Refusal, or the error text otherwise.
func refusalCodeOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return err.Error()
}

// CreateOptions describes a key pair to generate.
type CreateOptions struct {
	Label        string
	Tag          []byte
	Store        StoreKind
	UserPresence bool
}

// Backend is the key store the Manager gates. The production implementation
// is SecurityStore.
type Backend interface {
	Create(opts CreateOptions) (Item, error)
	// List returns every item whose label carries LabelPrefix.
	List() ([]Item, error)
	// Delete removes the pair under label or returns ErrNotFound.
	Delete(label string) error
	// UpdateTag replaces the application tag under label or returns ErrNotFound.
	UpdateTag(label string, tag []byte) error
	// Sign produces an ECDSA signature over a SHA-256 digest with the
	// private half under label, encoded as DER (X9.62), or ErrNotFound.
	// It is the only operation that uses private material and the
	// material never leaves Security.framework.
	Sign(label string, digest []byte) ([]byte, error)
}

// StoreServer is implemented by a Backend that says which stores it can
// operate on. A Backend without it serves the login keychain only, as every
// backend before the Secure Enclave store did.
type StoreServer interface {
	Serves(store StoreKind) bool
}

// StoreSigner is implemented by a Backend that serves several stores: the
// Manager hands it the authorized record, so the signature is made in the
// store that record names and under exactly that record's policy, never in
// whichever store holds the label, or whatever policy it carries, at
// signing time.
type StoreSigner interface {
	SignIn(authorized Record, label string, digest []byte) ([]byte, error)
}

func (m *Manager) serves(store StoreKind) bool {
	if server, ok := m.backend.(StoreServer); ok {
		return server.Serves(store)
	}
	return store == StoreKeychain
}

// ErrNotFound reports an address with no key pair behind it.
var ErrNotFound = errors.New("key not found")

// StatusError carries a raw Security.framework OSStatus.
type StatusError struct {
	Op     string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("Security.framework %s failed: OSStatus %d", e.Op, e.Status)
}

// Refusal is a policy gate rejection raised before or instead of a store
// call, or an operational failure translated per the error contract (model
// §8); see signerclient.Refusal.
type Refusal = signerclient.Refusal

// Error-contract codes.
const (
	CodeForeignLabel         = signerclient.CodeForeignLabel
	CodeDuplicate            = signerclient.CodeDuplicate
	CodeConfirmationRequired = signerclient.CodeConfirmationRequired
	CodeMissingEntitlement   = signerclient.CodeMissingEntitlement
	CodeUnsupportedStore     = signerclient.CodeUnsupportedStore
	CodeSecurity             = signerclient.CodeSecurity
)

// OSStatusName translates the Security.framework statuses the tool meets so
// a raw number never appears alone.
func OSStatusName(status int) string {
	switch status {
	case errSecMissingEntitlement:
		return "errSecMissingEntitlement"
	case errSecItemNotFound:
		return "errSecItemNotFound"
	case -25316:
		return "errSecDataNotAvailable"
	case -25293:
		return "errSecAuthFailed"
	case -25299:
		return "errSecDuplicateItem"
	case -25308:
		return "errSecInteractionNotAllowed"
	case -128:
		return "errSecUserCanceled"
	case -25291:
		return "errSecNotAvailable"
	case errSecParam:
		return "errSecParam"
	default:
		return fmt.Sprintf("OSStatus %d", status)
	}
}

// Translate maps a StatusError to the error contract: -34018 becomes
// missing_entitlement, everything else security; both are operational
// failures (exit 1) carrying the OSStatus and its name.
func Translate(op string, err error) error {
	var status *StatusError
	if !errors.As(err, &status) {
		return err
	}
	if status.Status == errSecMissingEntitlement {
		return &Refusal{Code: CodeMissingEntitlement, Failure: true, Status: status.Status, Message: fmt.Sprintf("Security.framework refused %s with errSecMissingEntitlement: the Secure Enclave and the Data Protection keychain need a binary signed with a provisioning profile", op), Hint: "this binary is not signed with a provisioning profile; use the login keychain store (drop --enclave / --user-presence); nothing was created and no fallback was made"}
	}
	return &Refusal{Code: CodeSecurity, Failure: true, Status: status.Status, Message: fmt.Sprintf("Security.framework %s failed with %s", op, OSStatusName(status.Status)), Hint: fmt.Sprintf("%s (%d) from %s; check the login keychain state and rerun", OSStatusName(status.Status), status.Status, op)}
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// RequireOwnLabel refuses any label outside LabelPrefix. It is the guard every
// mutating Manager path runs before touching the store.
func RequireOwnLabel(label string) error { return signerclient.RequireOwnLabel(label) }

// Manager applies the policy gates around a Backend.
type Manager struct {
	backend Backend
	lock    Locker
	origin  Origin
	now     func() time.Time
}

// NewManager wires the gates around backend. lock serialises the
// check-then-create window across processes; origin (user, host, tool) is
// stamped into every record the manager creates with source "generated".
func NewManager(backend Backend, lock Locker, origin Origin) *Manager {
	if lock == nil {
		lock = NoLock{}
	}
	return &Manager{backend: backend, lock: lock, origin: origin, now: time.Now}
}

// SetClock overrides the creation timestamp source.
func (m *Manager) SetClock(now func() time.Time) {
	m.now = now
}

func keyOf(item Item) Key {
	rec, problem := DecodeRecord(item.Tag)
	if item.Problem != "" {
		problem = item.Problem
	}
	return Key{Label: item.Label, Record: rec, SPKI: item.SPKI, RecordProblem: problem}
}

// List returns the managed keys sorted by label, optionally only one
// service and/or kind (judged by the label so unreadable records are still
// listed). Anything outside the namespace is dropped even if the store
// returns it.
func (m *Manager) List(service, kind string) ([]Key, error) {
	items, err := m.backend.List()
	if err != nil {
		return nil, Translate("list", err)
	}
	keys := []Key{}
	for _, item := range items {
		if RequireOwnLabel(item.Label) != nil {
			continue
		}
		key := keyOf(item)
		if service != "" || kind != "" {
			parsed, ok := ParseLabel(item.Label)
			if !ok || (service != "" && parsed.Service != service) || (kind != "" && parsed.Kind != kind) {
				continue
			}
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })
	return keys, nil
}

// resolve finds the newest generation the address names.
func (m *Manager) resolve(addr Address) (Key, error) {
	keys, err := m.List("", "")
	if err != nil {
		return Key{}, err
	}
	return pick(keys, addr)
}

// pick selects the newest generation of addr by label; the hint of a miss
// names the versions and kinds that do exist for the same service/purpose.
func pick(keys []Key, addr Address) (Key, error) {
	found, ok := Key{}, false
	foundVersion := 0
	var nearby []string
	for _, key := range keys {
		parsed, parsable := ParseLabel(key.Label)
		if parsable && parsed.Service == addr.Service && parsed.Purpose == addr.Purpose {
			nearby = append(nearby, fmt.Sprintf("%s v%d", parsed.Kind, parsed.Version))
		}
		if !addressMatches(addr, key) {
			continue
		}
		if !ok || parsed.Version > foundVersion {
			found, foundVersion, ok = key, parsed.Version, true
		}
	}
	if !ok {
		return Key{}, &NotFoundError{Address: addr, Nearby: nearby}
	}
	return found, nil
}

// NotFoundError is ErrNotFound with the nearest existing versions/kinds.
type NotFoundError struct {
	Address Address
	Nearby  []string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s: %s", ErrNotFound, e.Address) }
func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// Hint names what does exist for the address.
func (e *NotFoundError) Hint() string {
	if len(e.Nearby) == 0 {
		return "no version of " + e.Address.Service + "/" + e.Address.Purpose + " exists for any kind; list shows every record"
	}
	sort.Strings(e.Nearby)
	return "existing generations of " + e.Address.Service + "/" + e.Address.Purpose + ": " + strings.Join(e.Nearby, ", ")
}

// Describe returns the key the address names or ErrNotFound.
func (m *Manager) Describe(addr Address) (Key, error) {
	return m.resolve(addr)
}

// InitSpec is the user's input for a new record; the vault fills schema,
// version, created and origin.
type InitSpec struct {
	Service      string
	Purpose      string
	Kind         string
	Title        string
	Description  string
	Algorithm    string
	Store        StoreKind
	UserPresence bool
	Extraction   string
	Usages       []string
	Format       Format
	Meta         map[string]any
	NotAfter     *time.Time
	// Generate is the --generate SPEC for kind secret; refused for keys.
	Generate string
}

// Init validates the spec, then under the lock refuses a duplicate
// (kind, service, purpose) in any version and creates version 1. A Secure
// Enclave or user-presence request that Security.framework rejects with
// -34018 fails with missing_entitlement instead of falling back to the
// plain keychain.
func (m *Manager) Init(spec InitSpec) (Key, error) {
	rec := Record{
		Schema: SchemaVersion, Kind: spec.Kind, Service: spec.Service, Purpose: spec.Purpose, Version: 1,
		Title: spec.Title, Description: spec.Description, Algorithm: spec.Algorithm, Store: spec.Store,
		Extraction: spec.Extraction, Usages: spec.Usages, Format: spec.Format,
		Meta: spec.Meta, UserPresence: spec.UserPresence,
		Origin: Origin{User: m.origin.User, Host: m.origin.Host, Tool: m.origin.Tool, Source: SourceGenerated},
	}
	if spec.NotAfter != nil {
		notAfter := NewTime(*spec.NotAfter)
		rec.Validity.NotAfter = &notAfter
	}
	// created is stamped before validation so the record the invariant
	// table sees is the record that is stored.
	rec.Created = NewTime(m.now())
	if err := ValidateNew(rec); err != nil {
		return Key{}, err
	}
	if spec.Generate != "" && rec.Kind != KindSecret {
		return Key{}, &Refusal{Code: CodeInvalidGenerate, Message: fmt.Sprintf("--generate is only valid for kind secret, not for kind %s", rec.Kind), Hint: "a key pair is generated by SecKeyCreateRandomKey; drop --generate"}
	}
	if err := RequireOwnLabel(rec.Label()); err != nil {
		return Key{}, err
	}
	return m.create(rec)
}

// create holds the lock across the duplicate check and the store create.
func (m *Manager) create(rec Record) (Key, error) {
	release, err := m.lock.Lock()
	if err != nil {
		return Key{}, err
	}
	defer release()
	label := rec.Label()
	// One listing under the lock decides both duplicate shapes.
	keys, err := m.List("", "")
	if err != nil {
		return Key{}, err
	}
	family := Address{Kind: rec.Kind, Service: rec.Service, Purpose: rec.Purpose}
	if _, err := pick(keys, Address{Kind: rec.Kind, Service: rec.Service, Purpose: rec.Purpose, Version: rec.Version}); err == nil {
		return Key{}, &Refusal{Code: CodeDuplicate, Message: fmt.Sprintf("%s version %d already exists as %s", family, rec.Version, label), Hint: "use rotate to create the next version, or delete --confirm --version N first"}
	}
	if rec.Version == 1 {
		if existing, err := pick(keys, family); err == nil {
			return Key{}, &Refusal{Code: CodeDuplicate, Message: fmt.Sprintf("%s already exists as %s", family, existing.Label), Hint: "use rotate to create the next version, or --version with describe/delete to address one"}
		}
	}
	tag, err := EncodeRecord(rec)
	if err != nil {
		return Key{}, err
	}
	item, err := m.backend.Create(CreateOptions{Label: label, Tag: tag, Store: rec.Store, UserPresence: rec.UserPresence})
	if err != nil {
		op := "create"
		if rec.Store == StoreEnclave {
			op = "create (Secure Enclave)"
		} else if rec.UserPresence {
			op = "create (user-presence ACL)"
		}
		return Key{}, Translate(op, err)
	}
	return keyOf(item), nil
}

// RotateResult reports the retained old pair and the new versioned pair.
type RotateResult struct {
	Old Key
	New Key
}

// Rotate creates the next generation of the newest key the address names,
// copying title, description, usages, format, extraction, validity, meta and
// the user-presence policy. It refuses a key whose store or record is not
// known (schema 1, unreadable tag, unknown store) instead of guessing the
// keychain (review F4), and a readable record that violates any per-kind
// invariant or its label (review F8/F13, closed as a class by
// ValidateStored). Every older generation is kept until deleted.
func (m *Manager) Rotate(addr Address) (RotateResult, error) {
	newest, err := m.resolve(addr)
	if err != nil {
		return RotateResult{}, err
	}
	// Any generation names its family; the next version follows the newest.
	family := Address{Kind: addr.Kind, Service: addr.Service, Purpose: addr.Purpose}
	if newest, err = m.resolve(family); err != nil {
		return RotateResult{}, err
	}
	rec := newest.Record
	hint := "delete --confirm --version N and init a fresh record; the vault never guesses store or policy"
	switch {
	case newest.RecordProblem != "":
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s has an unreadable record (%s); its store and policy are unknown, so no generation is created", newest.Label, newest.RecordProblem), Hint: hint}
	case rec.Schema != SchemaVersion:
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries record schema %d, not %d; its policy is unknown and is never upgraded silently, so no generation is created", newest.Label, rec.Schema, SchemaVersion), Hint: hint}
	}
	// The stored record must satisfy every invariant (an unknown store
	// among them: the keychain is never assumed) and agree with its label
	// before any of it is reproduced into the next generation.
	if err := ValidateStored(newest.Label, rec); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); no generation is created", newest.Label, err), Hint: hint}
	}
	next := rec
	next.Version = rec.Version + 1
	next.Origin = Origin{User: m.origin.User, Host: m.origin.Host, Tool: m.origin.Tool, Source: SourceGenerated}
	next.Meta = map[string]any{}
	for name, value := range rec.Meta {
		next.Meta[name] = value
	}
	next.Created = NewTime(m.now())
	if err := ValidateNew(next); err != nil {
		return RotateResult{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); no generation is created", newest.Label, err), Hint: hint}
	}
	created, err := m.create(next)
	if err != nil {
		return RotateResult{}, err
	}
	return RotateResult{Old: newest, New: created}, nil
}

// Delete removes the pair the address names. It refuses without confirmation
// and refuses any label outside LabelPrefix; both refusals happen before the
// backend is called. An address without a version deletes the newest
// generation only.
func (m *Manager) Delete(addr Address, confirmed bool) (string, error) {
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return "", err
	}
	if !confirmed {
		return "", &Refusal{Code: CodeConfirmationRequired, Message: fmt.Sprintf("deleting %s destroys its private key irreversibly", addr), Hint: "rerun with --confirm (and --version N to pick one generation)"}
	}
	key, err := m.resolve(addr)
	if err != nil {
		return "", err
	}
	label := key.Label
	if err := RequireOwnLabel(label); err != nil {
		return "", err
	}
	if err := m.backend.Delete(label); err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", &NotFoundError{Address: addr}
		}
		return "", Translate("delete", err)
	}
	return label, nil
}

// MetaSet stores one meta entry on the record under the lock; the reserved
// names and unsupported value types are refused before the store is touched.
func (m *Manager) MetaSet(addr Address, name string, value any) (Key, error) {
	if err := ValidateMetaEntry(name, value); err != nil {
		return Key{}, err
	}
	return m.updateMeta(addr, func(meta map[string]any) { meta[name] = value })
}

// MetaUnset removes one meta entry; a missing name is ErrNotFound.
func (m *Manager) MetaUnset(addr Address, name string) (Key, error) {
	missing := false
	key, err := m.updateMeta(addr, func(meta map[string]any) {
		if _, ok := meta[name]; !ok {
			missing = true
			return
		}
		delete(meta, name)
	})
	if err != nil {
		return Key{}, err
	}
	if missing {
		return Key{}, &MetaNotFoundError{Name: name, Label: key.Label}
	}
	return key, nil
}

// MetaNotFoundError is ErrNotFound for one meta name.
type MetaNotFoundError struct {
	Name  string
	Label string
}

func (e *MetaNotFoundError) Error() string {
	return fmt.Sprintf("%s: meta %q on %s", ErrNotFound, e.Name, e.Label)
}
func (e *MetaNotFoundError) Unwrap() error { return ErrNotFound }

// Hint tells the caller how to see what exists.
func (e *MetaNotFoundError) Hint() string {
	return "meta get " + e.Label + " lists the names that exist"
}

func (m *Manager) updateMeta(addr Address, change func(map[string]any)) (Key, error) {
	release, err := m.lock.Lock()
	if err != nil {
		return Key{}, err
	}
	defer release()
	key, err := m.resolve(addr)
	if err != nil {
		return Key{}, err
	}
	if key.RecordProblem != "" || key.Record.Schema != SchemaVersion {
		return Key{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s does not carry a schema-%d record; meta lives inside the record and a v1 or unreadable tag is never rewritten", key.Label, SchemaVersion), Hint: "delete --confirm and init a fresh record"}
	}
	if err := RequireOwnLabel(key.Label); err != nil {
		return Key{}, err
	}
	// A stored record that violates a per-kind invariant is never rewritten
	// (a meta write would re-persist the forged field as if it were valid).
	if err := ValidateStored(key.Label, key.Record); err != nil {
		return Key{}, &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot reproduce (%v); meta is not rewritten", key.Label, err), Hint: "delete --confirm --version N and init a fresh record; the vault never guesses store or policy"}
	}
	before := len(key.Record.Meta)
	change(key.Record.Meta)
	if len(key.Record.Meta) == before && before == 0 {
		return key, nil
	}
	tag, err := EncodeRecord(key.Record)
	if err != nil {
		return Key{}, err
	}
	if err := m.backend.UpdateTag(key.Label, tag); err != nil {
		return Key{}, Translate("update", err)
	}
	return key, nil
}

// StoreDecrypter is implemented by a Backend that can open ECIES envelopes
// with a private half it holds. The plaintext leaves the backend; the key
// does not.
type StoreDecrypter interface {
	Decrypt(label string, envelope []byte) ([]byte, error)
}

// ErrEnvelopeInvalid reports an envelope the key could not open: tampered,
// truncated, or made for another key. GCM does not tell these apart.
var ErrEnvelopeInvalid = errors.New("envelope does not open under this key")

// Decrypt opens an ECIES envelope with the newest generation the address
// names, after the same gates as Sign: address inside the namespace, readable
// and valid record, registry row, usages ∋ decrypt, validity unexpired. An
// envelope the key cannot open is ErrEnvelopeInvalid.
func (m *Manager) Decrypt(addr Address, envelope []byte) (Key, []byte, error) {
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return Key{}, nil, err
	}
	key, err := m.resolve(addr)
	if err != nil {
		return Key{}, nil, err
	}
	if err := m.authorize(key, OperationDecrypt); err != nil {
		return Key{}, nil, err
	}
	if err := RequireOwnLabel(key.Label); err != nil {
		return Key{}, nil, err
	}
	decrypter, ok := m.backend.(StoreDecrypter)
	if !ok {
		return Key{}, nil, &Refusal{Code: CodeUnsupportedPrimitive, Failure: true, Message: fmt.Sprintf("this vault's backend cannot decrypt with %s", key.Label), Hint: "decryption runs in mac-keyvault-kek"}
	}
	plain, err := decrypter.Decrypt(key.Label, envelope)
	if err != nil {
		var status *StatusError
		switch {
		case errors.Is(err, ErrNotFound):
			return Key{}, nil, &NotFoundError{Address: addr}
		case errors.As(err, &status) && status.Status == errSecParam:
			return Key{}, nil, ErrEnvelopeInvalid
		}
		return Key{}, nil, Translate("decrypt", err)
	}
	return key, plain, nil
}

// OperationSign and OperationVerify are the registry names sign and
// verify are gated on.
const (
	OperationSign   = "ecdsa-sha256-sign"
	OperationVerify = "ecdsa-sha256-verify"
	// OperationDecrypt opens an ECIES envelope; mac-keyvault-kek performs it.
	OperationDecrypt = "ecies-p256-decrypt"
)

// authorize is the operations gate (model §6): the named operation must be
// in what the record can do right now, judged by the same registry
// derivation describe prints. The reason of a miss is reported by its own
// code: no registry row is unsupported_primitive (exit 1), a missing usage
// is usage_refused, an elapsed validity.not_after is expired. A record that
// is unreadable or violates its invariants is refused as metadata_unknown
// before any of that: the vault never operates on a record it cannot trust.
func (m *Manager) authorize(key Key, operation string) error {
	rec := key.Record
	if key.RecordProblem != "" || rec.Schema != SchemaVersion {
		return &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s does not carry a readable schema-%d record; its policy is unknown, so %s is not performed", key.Label, SchemaVersion, operation), Hint: "describe shows the findings; delete --confirm and init a fresh record"}
	}
	if err := ValidateStored(key.Label, rec); err != nil {
		return &Refusal{Code: CodeMetadataUnknown, Message: fmt.Sprintf("%s carries a record this revision cannot trust (%v); %s is not performed", key.Label, err, operation), Hint: "describe shows the findings; delete --confirm --version N and init a fresh record"}
	}
	primitive, ok := LookupPrimitive(rec)
	if !ok {
		return &Refusal{Code: CodeUnsupportedPrimitive, Failure: true, Message: fmt.Sprintf("%s is (%s, %s, %s), a primitive this revision has no registry row for", key.Label, rec.Kind, rec.Algorithm, rec.Store), Hint: "only (key, ec-p256, keychain) and (key, ec-p256, enclave) perform operations in this revision"}
	}
	if !m.serves(rec.Store) {
		return &Refusal{Code: CodeUnsupportedPrimitive, Failure: true, Message: fmt.Sprintf("%s is (%s, %s, %s), a store this vault's backend does not serve", key.Label, rec.Kind, rec.Algorithm, rec.Store), Hint: "the Secure Enclave store needs mac-keyvault-enclave next to the mac-keyvault binary; setup.sh builds both"}
	}
	var row *Operation
	for i := range primitive.Operations {
		if primitive.Operations[i].Name == operation {
			row = &primitive.Operations[i]
		}
	}
	if row == nil {
		return &Refusal{Code: CodeUnsupportedPrimitive, Failure: true, Message: fmt.Sprintf("%s does not support %s", key.Label, operation), Hint: "describe lists the operations of the record"}
	}
	ops, _ := Operations(rec, m.now())
	for _, op := range ops {
		if op.Name == operation {
			return nil
		}
	}
	if row.requires != "" && !contains(rec.Usages, row.requires) {
		return &Refusal{Code: CodeUsageRefused, Message: fmt.Sprintf("%s has usages [%s]; %s requires usage %s", key.Label, strings.Join(rec.SortedUsages(), ", "), operation, row.requires), Hint: "init a record with --usages including " + row.requires + "; usages are fixed at creation"}
	}
	if row.expires && rec.Validity.NotAfter != nil {
		return &Refusal{Code: CodeExpired, Message: fmt.Sprintf("%s expired at %s (validity.not_after); %s is refused", key.Label, rec.Validity.NotAfter.UTC().Format(time.RFC3339), operation), Hint: "rotate creates the next generation with the same not_after; init a fresh record for a new validity"}
	}
	return &Refusal{Code: CodeUnsupportedPrimitive, Failure: true, Message: fmt.Sprintf("%s cannot perform %s under its policy", key.Label, operation), Hint: "describe lists the operations of the record"}
}

// SignResult is one signature with the key that produced it.
type SignResult struct {
	Key       Key
	Signature Signature
	// Normalized reports that Security.framework produced a high-S value
	// and the vault replaced s by n-s.
	Normalized bool
}

// Sign produces a low-S ECDSA signature over a 32-byte SHA-256 digest with
// the newest generation the address names. Gates, in order and all before
// the backend signs: digest length, address inside the namespace, readable
// and valid record, registry row, usages ∋ sign, validity unexpired.
func (m *Manager) Sign(addr Address, digest []byte) (SignResult, error) {
	return m.SignIf(addr, digest, nil)
}

// SignIf is Sign with a final gate: allow, when set, runs after resolution
// and policy checks, immediately before the private operation, and its
// error refuses the signature without touching the key.
func (m *Manager) SignIf(addr Address, digest []byte, allow func() error) (SignResult, error) {
	if allow == nil {
		return m.SignIfKey(addr, digest, nil)
	}
	return m.SignIfKey(addr, digest, func(ResolvedSigningKey) error { return allow() })
}

// ResolvedSigningKey is a narrow public snapshot of the actual key selected
// after normal signing policy checks. SPKI is owned by the snapshot; changing
// it cannot alter the record or public key passed to the signing backend.
type ResolvedSigningKey struct {
	Address      Address
	Store        StoreKind
	UserPresence bool
	Extraction   string
	SPKI         []byte
}

// SignIfKey adds a final key-aware policy gate to Sign. The gate observes the
// resolved generation rather than a separate earlier describe lookup. Rejection
// performs no private operation. It grants no additional signing authority.
func (m *Manager) SignIfKey(addr Address, digest []byte, allow func(ResolvedSigningKey) error) (SignResult, error) {
	return m.signIfKey(addr, digest, allow, nil)
}

// SignOwnerDocument uses only the typed native full-document backend. There is
// no generic digest signer fallback. After native consent, the final source
// check and current signing policy must still allow dispatch.
func (m *Manager) SignOwnerDocument(ctx context.Context, addr Address, digest, document []byte, allow func(ResolvedSigningKey) error, final func() error) (SignResult, error) {
	if ctx == nil || final == nil || allow == nil {
		return SignResult{}, errors.New("owner document: missing gate")
	}
	owned := append([]byte(nil), document...)
	digest = append([]byte(nil), digest...)
	return m.signIfKey(addr, digest, allow, func(key Key) ([]byte, error) {
		signer, ok := m.backend.(ownerDocumentSigner)
		if !ok {
			return nil, errors.New("owner document: native backend unavailable")
		}
		return signer.signOwnerDocument(ctx, key, digest, owned, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := final(); err != nil {
				return err
			}
			// Native review and the source check may take time. Evaluate expiry
			// with the manager's current clock only after both have completed.
			if err := m.authorize(key, OperationSign); err != nil {
				return err
			}
			return ctx.Err()
		})
	})
}

func (m *Manager) signIfKey(addr Address, digest []byte, allow func(ResolvedSigningKey) error, documentDispatch func(Key) ([]byte, error)) (SignResult, error) {
	if err := ValidateDigest(digest); err != nil {
		return SignResult{}, err
	}
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return SignResult{}, err
	}
	key, err := m.resolve(addr)
	if err != nil {
		return SignResult{}, err
	}
	if err := m.authorize(key, OperationSign); err != nil {
		return SignResult{}, err
	}
	if err := RequireOwnLabel(key.Label); err != nil {
		return SignResult{}, err
	}
	if allow != nil {
		view := ResolvedSigningKey{
			Address: Address{Kind: key.Record.Kind, Service: key.Record.Service, Purpose: key.Record.Purpose, Version: key.Record.Version},
			Store:   key.Record.Store, UserPresence: key.Record.UserPresence, Extraction: key.Record.Extraction,
			SPKI: append([]byte(nil), key.SPKI...),
		}
		if err := allow(view); err != nil {
			return SignResult{}, err
		}
	}
	var der []byte
	if documentDispatch != nil {
		der, err = documentDispatch(key)
	} else if signer, ok := m.backend.(StoreSigner); ok {
		der, err = signer.SignIn(key.Record, key.Label, digest)
	} else {
		der, err = m.backend.Sign(key.Label, digest)
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SignResult{}, &NotFoundError{Address: addr}
		}
		return SignResult{}, Translate("sign", err)
	}
	sig, err := ParseSignature(der, FormatSignatureDERLowS)
	if err != nil {
		return SignResult{}, &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("Security.framework returned a signature the vault cannot parse for %s: %v", key.Label, err), Hint: "nothing was emitted; rerun and report the bridge output"}
	}
	result := SignResult{Key: key, Signature: sig.LowS(), Normalized: !sig.IsLowS()}
	if len(key.SPKI) != 0 {
		// The public half is known: refuse to emit a signature that
		// does not verify under it (a bridge or keychain fault, never a
		// caller error).
		if ok, err := VerifyDigest(key.SPKI, digest, result.Signature); err != nil || !ok {
			return SignResult{}, &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("the signature Security.framework produced for %s does not verify under its own public key", key.Label), Hint: "nothing was emitted; the keychain item may be damaged, describe and rotate it"}
		}
	}
	return result, nil
}

// PublicKeyFor resolves the address for verify: the key must carry a
// readable public half and its record must admit ecdsa-sha256-verify.
func (m *Manager) PublicKeyFor(addr Address) (Key, error) {
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return Key{}, err
	}
	key, err := m.resolve(addr)
	if err != nil {
		return Key{}, err
	}
	if err := m.authorize(key, OperationVerify); err != nil {
		return Key{}, err
	}
	if len(key.SPKI) == 0 {
		return Key{}, &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("public key of %s is unreadable; nothing can be verified against it", key.Label), Hint: "describe reports the fingerprint as unknown; pass --spki with a saved public key instead"}
	}
	return key, nil
}

// spkiFromPoint converts an uncompressed X9.63 P-256 point into DER SPKI.
func spkiFromPoint(point []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// EncodePEM wraps DER SPKI as a PUBLIC KEY PEM block.
func EncodePEM(spki []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
}

// EncodeJWK renders DER SPKI of a P-256 key as a public JWK.
func EncodeJWK(spki []byte) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("jwk: not a P-256 public key")
	}
	coordinate := func(v []byte) string {
		padded := make([]byte, 32)
		copy(padded[32-len(v):], v)
		return base64.RawURLEncoding.EncodeToString(padded)
	}
	return json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": coordinate(pub.X.Bytes()), "y": coordinate(pub.Y.Bytes())})
}

// Codes the classifier itself assigns; every Code* constant of this
// package is an alias of the signerclient registry (ErrorContract), the
// single source of the error contract.
const (
	CodeUsage    = signerclient.CodeUsage
	CodeFailure  = signerclient.CodeFailure
	CodeNotFound = signerclient.CodeNotFound
)
