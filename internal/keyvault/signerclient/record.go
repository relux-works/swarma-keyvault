// Record model for schema-2 key metadata and kind-specific invariants.
//
// The schema-2 record lives here, in the contract package, because the
// describe result IS the record view and a consumer must judge it exactly
// as the vault does: the same closed struct, the same
// DisallowUnknownFields decode, the same per-kind invariant table
// (invariants.go) and the same label grammar. The vault package
// (internal/keyvault) aliases every name defined here; nothing below
// touches Security.framework or leaves the standard library, so kvctl can
// still vendor the package verbatim.
package signerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the record schema this revision writes.
const SchemaVersion = 2

// Record is the schema-2 description of one vault item. It is stored as JSON
// in the item's kSecAttrApplicationTag so it cannot drift from the key on
// delete or rotate.
// label, fingerprint, exposure and operations are derived on every read and
// never stored.
type Record struct {
	Schema      int            `json:"schema"`
	Kind        string         `json:"kind"`
	Service     string         `json:"service"`
	Purpose     string         `json:"purpose"`
	Version     int            `json:"version"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Algorithm   string         `json:"algorithm"`
	Store       StoreKind      `json:"store"`
	Extraction  string         `json:"extraction"`
	Usages      []string       `json:"usages"`
	Format      Format         `json:"format"`
	Created     Time           `json:"created"`
	Origin      Origin         `json:"origin"`
	Issuer      *Issuer        `json:"issuer"`
	Validity    Validity       `json:"validity"`
	Meta        map[string]any `json:"meta"`
	// UserPresence records the biometry/passcode policy requested at init so
	// rotate reproduces it instead of weakening it. Never true on an
	// unprovisioned binary (-34018).
	UserPresence bool `json:"user_presence,omitempty"`
}

// Format names the default representations a command emits for the item;
// which keys are allowed depends on the kind.
type Format struct {
	Public    string `json:"public,omitempty"`
	Signature string `json:"signature,omitempty"`
	Envelope  string `json:"envelope,omitempty"`
}

// Origin records who put the item into the vault and how; the vault sets
// it, never the user.
type Origin struct {
	User   string `json:"user"`
	Host   string `json:"host"`
	Tool   string `json:"tool"`
	Source string `json:"source"`
}

// Issuer is the X.509 issuer of a certificate; nil for every other kind.
type Issuer struct {
	DN          string `json:"dn"`
	Fingerprint string `json:"fingerprint"`
}

// Validity bounds the item; nil means unbounded.
type Validity struct {
	NotBefore *Time `json:"not_before"`
	NotAfter  *Time `json:"not_after"`
}

// Time marshals as RFC3339 in UTC, or null when zero.
type Time struct{ time.Time }

// NewTime truncates t to whole UTC seconds.
func NewTime(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*t = Time{}
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return err
	}
	*t = NewTime(parsed)
	return nil
}

// Model vocabulary. Values outside these sets are refused before any
// Security.framework call; a known-but-unavailable value is refused with its
// own reason, never mapped to a neighbour.
const (
	KindPublicKey   = "public-key"
	KindCertificate = "certificate"
	KindSecret      = "secret"

	AlgorithmECP256    = "ec-p256"
	AlgorithmAES256GCM = "aes-256-gcm"
	AlgorithmOpaque    = "opaque"
	AlgorithmECP384    = "ec-p384"
	AlgorithmRSA3072   = "rsa-3072"
	AlgorithmEd25519   = "ed25519"

	ExposureNever   = "never"
	ExposureProcess = "process"

	ExtractionNone  = "none"
	ExtractionHuman = "human"
	ExtractionAgent = "agent"

	FormatPublicSPKIDER = "spki-der"
	FormatPublicSPKIPEM = "spki-pem"
	FormatPublicJWK     = "jwk"

	FormatSignatureDERLowS = "ecdsa-der-low-s"
	FormatSignatureRaw     = "ecdsa-raw"

	SourceGenerated = "generated"

	// Unknown is what a v1 or unreadable record reports for fields it does
	// not carry; it is never upgraded silently.
	Unknown = "unknown"
)

var (
	kinds       = []string{KindKey, KindPublicKey, KindCertificate, KindSecret}
	extractions = []string{ExtractionNone, ExtractionHuman, ExtractionAgent}
	// Usages the policy filter understands.
	Usages           = []string{"sign", "verify", "wrap", "encrypt", "decrypt", "attest"}
	formatsPublic    = []string{FormatPublicSPKIDER, FormatPublicSPKIPEM, FormatPublicJWK}
	formatsSignature = []string{FormatSignatureDERLowS, FormatSignatureRaw}
	// ReservedMetaNames are every top-level record name plus the derived
	// names a read prints; none may appear inside meta.
	ReservedMetaNames = []string{"schema", "kind", "service", "purpose", "version", "title", "description", "algorithm", "store", "extraction", "usages", "format", "created", "origin", "issuer", "validity", "meta", "user_presence", "label", "fingerprint", "exposure", "operations", "findings"}
)

// MaxTitleLength bounds title; MaxNameLength bounds service and purpose.
const (
	MaxTitleLength = 80
	MaxNameLength  = 40
)

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Findings a read reports next to the record (model §6): the findings
// vocabulary a describe result may carry.
const (
	FindingValidityExpired  = "validity_expired"
	FindingRecordUnreadable = "record_unreadable"
	// FindingRecordInvalid prefixes a read finding "record_invalid:<code>"
	// for a schema-2 record that violates an invariant row; the item is
	// still listed and described so the operator can see and delete it.
	FindingRecordInvalid = "record_invalid"
)

// HintFixInput is the hint every input refusal carries: the vault made no
// Security call and changed nothing.
const HintFixInput = "nothing was created or changed; fix the input and rerun"

// StoreKind names where a key pair lives.
type StoreKind string

const (
	StoreKeychain StoreKind = "keychain"
	StoreEnclave  StoreKind = "enclave"
	StoreUnknown  StoreKind = "unknown"
)

// LabelPrefix is the only namespace mac-keyvault creates, lists, or deletes.
const LabelPrefix = "works.relux.mac-keyvault."

// Refusal is a policy gate rejection raised before or instead of a store
// call, or an operational failure translated per the error contract (model
// §8): a stable code, a message in the caller's terms, and a hint that says
// what to do next. Failure marks the exit-1 (operational) class.
type Refusal struct {
	Code    string
	Message string
	Hint    string
	Status  int // underlying OSStatus when a Security call produced the refusal
	Failure bool
}

func (e *Refusal) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s: %s (OSStatus %d)", e.Code, e.Message, e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Kinds lists the closed kind vocabulary in model order.
func Kinds() []string { return append([]string(nil), kinds...) }

// Contains reports whether value is in set.
func Contains(set []string, value string) bool {
	for _, item := range set {
		if item == value {
			return true
		}
	}
	return false
}

// ValidateName checks a service or purpose name.
func ValidateName(field, code, value string) error {
	if value == "" || !namePattern.MatchString(value) || len(value) > MaxNameLength {
		return &Refusal{Code: code, Message: fmt.Sprintf("%s %q must match %s and be 1-%d characters", field, value, namePattern, MaxNameLength), Hint: HintFixInput}
	}
	return nil
}

// ValidateKind checks a record kind against the closed vocabulary; every
// CLI path that takes --kind (addresses and the list filter) goes through
// it before any Security call (review F10).
func ValidateKind(kind string) error {
	if !Contains(kinds, kind) {
		return &Refusal{Code: CodeInvalidKind, Message: fmt.Sprintf("kind %q is not one of %s", kind, strings.Join(kinds, ", ")), Hint: HintFixInput}
	}
	return nil
}

// ValidateMeta refuses reserved names and values that are not string, number
// or bool.
func ValidateMeta(meta map[string]any) error {
	for name, value := range meta {
		if err := ValidateMetaEntry(name, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateMetaEntry checks one meta name/value pair.
func ValidateMetaEntry(name string, value any) error {
	if name == "" {
		return &Refusal{Code: CodeInvalidMeta, Message: "meta names must not be empty", Hint: HintFixInput}
	}
	if Contains(ReservedMetaNames, name) {
		return &Refusal{Code: CodeInvalidMeta, Message: fmt.Sprintf("meta name %q is reserved for the record model", name), Hint: "a field the vault reacts to belongs in the model, not in meta; pick another name"}
	}
	switch value.(type) {
	case string, bool, float64, int, int64, json.Number:
		return nil
	default:
		return &Refusal{Code: CodeInvalidMeta, Message: fmt.Sprintf("meta %q has unsupported type %T", name, value), Hint: "only string, number and bool values are allowed"}
	}
}

// Label derives the keychain label of the record:
// works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>, .v<N> always present.
func (r Record) Label() string {
	return Address{Kind: r.Kind, Service: r.Service, Purpose: r.Purpose, Version: r.Version}.Label()
}

// Address names the record for messages.
func (r Record) Address() string {
	return r.Service + "/" + r.Purpose
}

// SortedUsages returns the usages in the canonical order.
func (r Record) SortedUsages() []string {
	out := append([]string(nil), r.Usages...)
	sort.Slice(out, func(i, j int) bool { return indexOf(Usages, out[i]) < indexOf(Usages, out[j]) })
	return out
}

func indexOf(set []string, value string) int {
	for i, item := range set {
		if item == value {
			return i
		}
	}
	return len(set)
}

// EncodeRecord serialises the record for the application tag.
func EncodeRecord(rec Record) ([]byte, error) {
	if rec.Meta == nil {
		rec.Meta = map[string]any{}
	}
	rec.Usages = rec.SortedUsages()
	return json.Marshal(rec)
}

// DecodeSingleJSON decodes exactly one JSON document into v with numbers
// kept as json.Number. A second document, a trailing token or trailing
// garbage after the first document is an error; surrounding whitespace is
// not. It is the one document-boundary rule for every JSON the vault reads:
// --meta-json and --json-value input as well as the persisted record tag.
//
// The decoder is also strict about members: a JSON object member that no
// struct field of v (top-level or nested) declares is an error, so a
// persisted record carrying a field the schema does not define is a read
// failure, never a readable record with the field silently erased before
// ValidateStored can see it (review F14). Open maps such as Record.Meta and
// the --meta-json / --json-value targets (map[string]any, any) are not
// closed by this; DisallowUnknownFields only constrains struct targets.
//
// Before the typed decode the document takes CheckDocument, the one
// recursive strict pass: a member name repeated (verbatim or
// escape-spelt) in ANY object of the document, nested or top-level, is a
// read failure, because the typed decode would keep only the last value
// and no invariant could see the first (review rev8 F1: a persisted tag
// or a describe result with `"format":{"public":"wrong","public":"spki-der"}`
// read as a valid record).
func DecodeSingleJSON(data []byte, v any) error {
	if err := CheckDocument(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the JSON document")
		}
		return err
	}
	return nil
}

// Address selects a vault item: kind, service, purpose and optionally one
// version (0 = the newest). It is the only way a command names an item; a
// raw label is refused before any Security call (review F1, model §1).
type Address struct {
	Kind    string
	Service string
	Purpose string
	Version int
}

// Label derives works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>;
// version 0 (newest) yields no suffix and is never a real label.
func (a Address) Label() string {
	label := LabelPrefix + a.Kind + "." + a.Service + "." + a.Purpose
	if a.Version > 0 {
		label += ".v" + strconv.Itoa(a.Version)
	}
	return label
}

// ParseLabel inverts Label for items read back from the keychain; ok is
// false for any label that is not exactly prefix.kind.service.purpose.vN.
func ParseLabel(label string) (Address, bool) {
	if RequireOwnLabel(label) != nil {
		return Address{}, false
	}
	parts := strings.Split(strings.TrimPrefix(label, LabelPrefix), ".")
	if len(parts) != 4 || !strings.HasPrefix(parts[3], "v") {
		return Address{}, false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[3], "v"))
	if err != nil || version < 1 || !Contains(kinds, parts[0]) || !namePattern.MatchString(parts[1]) || !namePattern.MatchString(parts[2]) {
		return Address{}, false
	}
	return Address{Kind: parts[0], Service: parts[1], Purpose: parts[2], Version: version}, true
}

// String renders the address for messages.
func (a Address) String() string {
	s := a.Service + "/" + a.Purpose
	if a.Kind != KindKey {
		s += " (kind " + a.Kind + ")"
	}
	if a.Version > 0 {
		s += " v" + strconv.Itoa(a.Version)
	}
	return s
}

// RequireOwnLabel refuses any label outside LabelPrefix. It is the guard every
// mutating Manager path runs before touching the store.
func RequireOwnLabel(label string) error {
	if !strings.HasPrefix(label, LabelPrefix) || len(label) == len(LabelPrefix) {
		return &Refusal{Code: CodeForeignLabel, Message: fmt.Sprintf("label %q resolves outside the %s namespace; refusing to touch it", label, LabelPrefix), Hint: "addresses are <service>/<purpose>; raw labels are not accepted"}
	}
	return nil
}
