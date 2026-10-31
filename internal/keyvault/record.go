package keyvault

import (
	"fmt"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"strings"
	"time"
)

// The schema-2 record model, its vocabulary, the invariant table and the
// label grammar live in the contract package (signerclient/record.go,
// signerclient/invariants.go) so the signer client judges a describe
// result with the vault's own code (review rev7 F1). This file aliases
// them and keeps what only the vault does: reading the persisted tag,
// parsing CLI addresses and the create-scope gate.

// SchemaVersion is the record schema this revision writes.
const SchemaVersion = signerclient.SchemaVersion

type (
	Record   = signerclient.Record
	Format   = signerclient.Format
	Origin   = signerclient.Origin
	Issuer   = signerclient.Issuer
	Validity = signerclient.Validity
	Time     = signerclient.Time
	Address  = signerclient.Address
)

// NewTime truncates t to whole UTC seconds.
func NewTime(t time.Time) Time { return signerclient.NewTime(t) }

// Model vocabulary. Values outside these sets are refused before any
// Security.framework call; a known-but-unavailable value is refused with its
// own reason, never mapped to a neighbour.
const (
	KindKey         = signerclient.KindKey
	KindPublicKey   = signerclient.KindPublicKey
	KindCertificate = signerclient.KindCertificate
	KindSecret      = signerclient.KindSecret

	AlgorithmECP256    = signerclient.AlgorithmECP256
	AlgorithmAES256GCM = signerclient.AlgorithmAES256GCM
	AlgorithmOpaque    = signerclient.AlgorithmOpaque
	AlgorithmECP384    = signerclient.AlgorithmECP384
	AlgorithmRSA3072   = signerclient.AlgorithmRSA3072
	AlgorithmEd25519   = signerclient.AlgorithmEd25519

	ExposureNever   = signerclient.ExposureNever
	ExposureProcess = signerclient.ExposureProcess

	ExtractionNone  = signerclient.ExtractionNone
	ExtractionHuman = signerclient.ExtractionHuman
	ExtractionAgent = signerclient.ExtractionAgent

	FormatPublicSPKIDER = signerclient.FormatPublicSPKIDER
	FormatPublicSPKIPEM = signerclient.FormatPublicSPKIPEM
	FormatPublicJWK     = signerclient.FormatPublicJWK

	FormatSignatureDERLowS = signerclient.FormatSignatureDERLowS
	FormatSignatureRaw     = signerclient.FormatSignatureRaw

	SourceGenerated = signerclient.SourceGenerated

	// Unknown is what a v1 or unreadable record reports for fields it does
	// not carry; it is never upgraded silently.
	Unknown = signerclient.Unknown

	MaxTitleLength = signerclient.MaxTitleLength
	MaxNameLength  = signerclient.MaxNameLength
)

var (
	kinds = signerclient.Kinds()
	// Usages the policy filter understands.
	Usages = signerclient.Usages
	// ReservedMetaNames are every top-level record name plus the derived
	// names a read prints; none may appear inside meta.
	ReservedMetaNames = signerclient.ReservedMetaNames
)

// Refusal codes raised by record validation and the rotate/meta gates.
const (
	CodeInvalidService        = signerclient.CodeInvalidService
	CodeInvalidPurpose        = signerclient.CodeInvalidPurpose
	CodeInvalidKind           = signerclient.CodeInvalidKind
	CodeUnsupportedKind       = signerclient.CodeUnsupportedKind
	CodeInvalidAlgorithm      = signerclient.CodeInvalidAlgorithm
	CodeUnsupportedAlgorithm  = signerclient.CodeUnsupportedAlgorithm
	CodeInvalidUsages         = signerclient.CodeInvalidUsages
	CodeInvalidFormat         = signerclient.CodeInvalidFormat
	CodeInvalidExtraction     = signerclient.CodeInvalidExtraction
	CodeInvalidGenerate       = signerclient.CodeInvalidGenerate
	CodeInvalidMeta           = signerclient.CodeInvalidMeta
	CodeInvalidTitle          = signerclient.CodeInvalidTitle
	CodeInvalidIssuer         = signerclient.CodeInvalidIssuer
	CodeInvalidValidity       = signerclient.CodeInvalidValidity
	CodeMetadataUnknown       = signerclient.CodeMetadataUnknown
	CodeUnsupportedPrimitive  = signerclient.CodeUnsupportedPrimitive
	FindingValidityExpired    = signerclient.FindingValidityExpired
	FindingRecordUnreadable   = signerclient.FindingRecordUnreadable
	hintFixInputNoSecurityCal = signerclient.HintFixInput
)

func contains(set []string, value string) bool { return signerclient.Contains(set, value) }

// ValidateName checks a service or purpose name.
func ValidateName(field, code, value string) error {
	return signerclient.ValidateName(field, code, value)
}

// ValidateKind checks a record kind against the closed vocabulary; every
// CLI path that takes --kind (addresses and the list filter) goes through
// it before any Security call (review F10).
func ValidateKind(kind string) error { return signerclient.ValidateKind(kind) }

// ValidateNew checks a record the vault is about to create: the closed
// kind vocabulary, the creation scope of this revision, then every row of
// the per-kind invariant table (invariants.go). Every check runs on the
// caller's input alone: nothing here touches Security.framework, and the
// first failing field is refused with its own code.
func ValidateNew(rec Record) error {
	if err := ValidateName("service", CodeInvalidService, rec.Service); err != nil {
		return err
	}
	if err := ValidateName("purpose", CodeInvalidPurpose, rec.Purpose); err != nil {
		return err
	}
	if err := ValidateKind(rec.Kind); err != nil {
		return err
	}
	if rec.Kind != KindKey {
		return &Refusal{Code: CodeUnsupportedKind, Message: fmt.Sprintf("kind %q is not implemented in this revision; only kind key is created", rec.Kind), Hint: "public-key, certificate and secret arrive with T4-T7; nothing was created"}
	}
	return ValidateRecord(rec)
}

// ValidateMeta refuses reserved names and values that are not string, number
// or bool.
func ValidateMeta(meta map[string]any) error { return signerclient.ValidateMeta(meta) }

// ValidateMetaEntry checks one meta name/value pair.
func ValidateMetaEntry(name string, value any) error {
	return signerclient.ValidateMetaEntry(name, value)
}

// EncodeRecord serialises the record for the application tag.
func EncodeRecord(rec Record) ([]byte, error) { return signerclient.EncodeRecord(rec) }

// DecodeSingleJSON decodes exactly one JSON document into v with numbers
// kept as json.Number and unknown struct members refused; see
// signerclient.DecodeSingleJSON.
func DecodeSingleJSON(data []byte, v any) error { return signerclient.DecodeSingleJSON(data, v) }

// legacyTagVersion is the rev1 application tag prefix.
const legacyTagVersion = "mac-keyvault/1"

// DecodeRecord reads an application tag. A schema-2 JSON tag round-trips; a
// rev1 tag is reported as schema 1 with service and purpose unknown; an
// absent tag is schema 0 with everything unknown; a tag that is present but
// unreadable is schema 0 with a non-empty problem so the caller can tell a
// read failure from an absence. Nothing is upgraded.
func DecodeRecord(tag []byte) (rec Record, problem string) {
	unknown := Record{Schema: 0, Kind: Unknown, Service: Unknown, Purpose: Unknown, Algorithm: Unknown, Store: StoreUnknown, Extraction: Unknown, Meta: map[string]any{}}
	text := strings.TrimSpace(string(tag))
	switch {
	case text == "":
		return unknown, ""
	case strings.HasPrefix(text, "{"):
		// Numbers inside meta are decoded as json.Number so a value such
		// as 9007199254740993 round-trips digit-exact instead of being
		// rounded through float64 (review F11).
		// The tag must be exactly one document: a record followed by a
		// second document, token or garbage is a read failure, never a
		// readable record (review F12, same class as F6 for --meta-json;
		// both boundaries share DecodeSingleJSON).
		var decoded Record
		if err := DecodeSingleJSON([]byte(text), &decoded); err != nil {
			return unknown, "record tag is not valid JSON: " + err.Error()
		}
		if decoded.Schema != SchemaVersion {
			return unknown, fmt.Sprintf("record schema %d is not %d", decoded.Schema, SchemaVersion)
		}
		if decoded.Meta == nil {
			decoded.Meta = map[string]any{}
		}
		return decoded, ""
	case strings.HasPrefix(text, legacyTagVersion+" ") || text == legacyTagVersion:
		// The v1 tag carries only store and created; kind and algorithm
		// are reported unknown rather than inferred from what rev1 used
		// to generate, so no registry row matches and no operation is
		// advertised.
		rec := unknown
		rec.Schema = 1
		for _, field := range strings.Fields(text)[1:] {
			switch {
			case strings.HasPrefix(field, "store="):
				switch store := StoreKind(strings.TrimPrefix(field, "store=")); store {
				case StoreKeychain, StoreEnclave:
					rec.Store = store
				}
			case strings.HasPrefix(field, "created="):
				if parsed, err := time.Parse(time.RFC3339, strings.TrimPrefix(field, "created=")); err == nil {
					rec.Created = NewTime(parsed)
				}
			}
		}
		return rec, ""
	default:
		return unknown, "record tag has an unknown format"
	}
}

// ParseAddress parses <service>/<purpose> CLI input with the kind and
// version flags. Input without a slash — a raw label, inside or outside the
// prefix — is foreign_label.
func ParseAddress(input, kind string, version int) (Address, error) {
	service, purpose, ok := strings.Cut(input, "/")
	if !ok {
		return Address{}, &Refusal{Code: CodeForeignLabel, Message: fmt.Sprintf("%q is not a <service>/<purpose> address; raw labels are not accepted", input), Hint: "addresses are <service>/<purpose>, optionally with --kind and --version; the label is derived by the vault"}
	}
	if err := ValidateName("service", CodeInvalidService, service); err != nil {
		return Address{}, err
	}
	if err := ValidateName("purpose", CodeInvalidPurpose, purpose); err != nil {
		return Address{}, err
	}
	if err := ValidateKind(kind); err != nil {
		return Address{}, err
	}
	if version < 0 {
		return Address{}, &Refusal{Code: CodeInvalidPurpose, Message: fmt.Sprintf("version %d must be at least 1", version), Hint: hintFixInputNoSecurityCal}
	}
	addr := Address{Kind: kind, Service: service, Purpose: purpose, Version: version}
	if err := RequireOwnLabel(addr.Label()); err != nil {
		return Address{}, err
	}
	return addr, nil
}

// ParseLabel inverts Address.Label for items read back from the keychain;
// ok is false for any label that is not exactly prefix.kind.service.purpose.vN.
func ParseLabel(label string) (Address, bool) { return signerclient.ParseLabel(label) }

// addressMatches reports whether key is one generation of the address,
// judged by the label alone so that an item with an unreadable record is
// still found.
func addressMatches(a Address, key Key) bool {
	parsed, ok := ParseLabel(key.Label)
	if !ok {
		return false
	}
	return parsed.Kind == a.Kind && parsed.Service == a.Service && parsed.Purpose == a.Purpose && (a.Version == 0 || parsed.Version == a.Version)
}
