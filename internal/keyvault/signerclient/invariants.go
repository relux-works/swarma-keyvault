package signerclient

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Per-kind record invariants (model v2 §2), one table for every field.
//
// Review rev1-rev5 found four forged-persisted-field bypasses one at a time
// (issuer F8, trailing document F12, not_before F13, …). The class is closed
// here instead: every field the schema-2 record carries has exactly one row
// that states what it may hold for each kind, and every path that admits a
// record — Init, Rotate, MetaSet/MetaUnset — runs the whole table before any
// Security call, while every read (describe, list) reports a failing row as
// a finding instead of a refusal. A field without a row is a bug, not a
// permission; the table test forges each field one at a time.

// Format vocabularies per kind (§2 format row).
var (
	formatsCertificatePublic = []string{"x509-der", "x509-pem", "pkcs7-chain"}
	formatsSecretEnvelope    = []string{"json", "der"}
)

// importedSourcePattern is origin.source for imported material:
// imported:<sha256 hex of the imported bytes>.
var importedSourcePattern = regexp.MustCompile(`^imported:[0-9a-f]{64}$`)

// invariant is one row of the table: the field it governs and the check.
type invariant struct {
	Field string
	Check func(Record) error
}

// recordInvariants follows the field order of Record so the coverage test
// can compare the two lists directly. Every field of Record appears exactly
// once; user_presence is a request flag the
// backend answers (never true on an unprovisioned binary) and carries no
// value rule — a stated bound, not an omission.
var recordInvariants = []invariant{
	{"schema", func(r Record) error {
		if r.Schema != SchemaVersion {
			return refuse(CodeInvalidSchema, fmt.Sprintf("schema %d is not %d", r.Schema, SchemaVersion), HintFixInput)
		}
		return nil
	}},
	{"kind", func(r Record) error { return ValidateKind(r.Kind) }},
	{"service", func(r Record) error { return ValidateName("service", CodeInvalidService, r.Service) }},
	{"purpose", func(r Record) error { return ValidateName("purpose", CodeInvalidPurpose, r.Purpose) }},
	{"version", func(r Record) error {
		if r.Version < 1 {
			return refuse(CodeInvalidVersion, fmt.Sprintf("version %d must be at least 1", r.Version), HintFixInput)
		}
		return nil
	}},
	{"title", func(r Record) error {
		// The bound is in characters (code points), not bytes: an
		// 80-character non-ASCII title is admitted, an 81-character one
		// refused (review F7).
		if n := utf8.RuneCountInString(r.Title); n > MaxTitleLength {
			return refuse(CodeInvalidTitle, fmt.Sprintf("title is %d characters, the limit is %d", n, MaxTitleLength), "shorten --title; put the long text in --description")
		}
		return nil
	}},
	{"description", func(Record) error { return nil }}, // free text, no bound (§2)
	{"algorithm", func(r Record) error { return validateAlgorithm(r.Kind, r.Algorithm) }},
	{"store", func(r Record) error {
		switch r.Store {
		case StoreKeychain, StoreEnclave:
			return nil
		}
		return refuse(CodeUnsupportedStore, fmt.Sprintf("store %q is not supported", r.Store), "use --keychain (default) or --enclave")
	}},
	{"extraction", func(r Record) error { return validateExtraction(r.Kind, r.Store, r.Extraction) }},
	{"usages", func(r Record) error { return validateUsages(r.Usages) }},
	{"format", func(r Record) error { return validateFormat(r.Kind, r.Format) }},
	{"created", func(r Record) error {
		if r.Created.IsZero() {
			return refuse(CodeInvalidCreated, "created must be an RFC3339 timestamp, not null", HintFixInput)
		}
		return nil
	}},
	{"origin", func(r Record) error { return validateOrigin(r.Origin) }},
	{"issuer", func(r Record) error { return ValidateIssuer(r.Kind, r.Issuer) }},
	{"validity", func(r Record) error { return validateValidity(r.Kind, r.Validity) }},
	{"meta", func(r Record) error { return ValidateMeta(r.Meta) }},
}

func refuse(code, message, hint string) error {
	return &Refusal{Code: code, Message: message, Hint: hint}
}

// InvariantFields lists the fields the table governs, in table order; the
// table test asserts it against the Record struct so a new field cannot be
// added without a row.
func InvariantFields() []string {
	fields := make([]string, 0, len(recordInvariants))
	for _, row := range recordInvariants {
		fields = append(fields, row.Field)
	}
	return fields
}

// ValidateRecord runs every row against the record and returns the first
// refusal. Nothing here touches Security.framework.
func ValidateRecord(rec Record) error {
	for _, row := range recordInvariants {
		if err := row.Check(rec); err != nil {
			return err
		}
	}
	return nil
}

// ValidateStored checks a record read back from the keychain: every row
// plus agreement between the record and the label it was stored under. A
// forged or drifted stored record is refused by rotate and meta writes and
// reported as a finding by reads.
func ValidateStored(label string, rec Record) error {
	if err := ValidateRecord(rec); err != nil {
		return err
	}
	parsed, ok := ParseLabel(label)
	if !ok || rec.Kind != parsed.Kind || rec.Service != parsed.Service || rec.Purpose != parsed.Purpose || rec.Version != parsed.Version {
		return refuse(CodeMetadataUnknown, fmt.Sprintf("record for %s/%s v%d (kind %s) does not match label %s", rec.Service, rec.Purpose, rec.Version, rec.Kind, label), "delete --confirm --version N and init a fresh record; the vault never guesses store or policy")
	}
	return nil
}

// validateAlgorithm admits the algorithms §2 lists for the kind; a reserved
// or explicitly refused algorithm is named as such and never mapped to a
// neighbour.
func validateAlgorithm(kind, algorithm string) error {
	switch algorithm {
	case AlgorithmECP256:
		if kind == KindSecret {
			return refuse(CodeInvalidAlgorithm, fmt.Sprintf("algorithm %q is not valid for kind secret", algorithm), "use --algorithm aes-256-gcm or opaque for a secret")
		}
		return nil
	case AlgorithmAES256GCM, AlgorithmOpaque:
		if kind != KindSecret {
			return refuse(CodeInvalidAlgorithm, fmt.Sprintf("algorithm %q is only valid for kind secret, not for kind %s", algorithm, kind), "use --algorithm ec-p256 for a key")
		}
		return nil
	case AlgorithmECP384, AlgorithmRSA3072:
		return refuse(CodeUnsupportedAlgorithm, fmt.Sprintf("algorithm %q is reserved and not implemented; it is never mapped to another algorithm", algorithm), "use --algorithm ec-p256")
	case AlgorithmEd25519:
		return refuse(CodeUnsupportedAlgorithm, "algorithm \"ed25519\" is refused explicitly: Security.framework SecKey has no Ed25519 support and the vault never maps it to another curve", "use --algorithm ec-p256")
	default:
		return refuse(CodeInvalidAlgorithm, fmt.Sprintf("algorithm %q is unknown", algorithm), "use --algorithm ec-p256")
	}
}

// validateExtraction enforces §4: none for every kind; human and agent only
// for key and secret (public material has no extraction policy); a Secure
// Enclave item is always none.
func validateExtraction(kind string, store StoreKind, extraction string) error {
	if !Contains(extractions, extraction) {
		return refuse(CodeInvalidExtraction, fmt.Sprintf("extraction %q is not one of %s", extraction, strings.Join(extractions, ", ")), HintFixInput)
	}
	if extraction == ExtractionNone {
		return nil
	}
	if store == StoreEnclave {
		return refuse(CodeInvalidExtraction, "Secure Enclave keys are never extractable", "use --extraction none with --enclave")
	}
	if kind != KindKey && kind != KindSecret {
		return refuse(CodeInvalidExtraction, fmt.Sprintf("extraction %q is not valid for kind %s; only key and secret carry an extraction policy", extraction, kind), "use --extraction none")
	}
	return nil
}

// validateUsages requires a non-empty, duplicate-free subset of Usages.
func validateUsages(usages []string) error {
	if len(usages) == 0 {
		return refuse(CodeInvalidUsages, "usages must name at least one of "+strings.Join(Usages, ", "), "pass --usages sign,verify")
	}
	seen := map[string]bool{}
	for _, usage := range usages {
		if !Contains(Usages, usage) {
			return refuse(CodeInvalidUsages, fmt.Sprintf("usage %q is not one of %s", usage, strings.Join(Usages, ", ")), HintFixInput)
		}
		if seen[usage] {
			return refuse(CodeInvalidUsages, fmt.Sprintf("usage %q is listed twice", usage), HintFixInput)
		}
		seen[usage] = true
	}
	return nil
}

// validateFormat admits only the format keys the kind allows, each from its
// own vocabulary: key and public-key carry public+signature, certificate
// carries public, secret carries envelope.
func validateFormat(kind string, format Format) error {
	switch kind {
	case KindKey, KindPublicKey:
		if format.Envelope != "" {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.envelope is not allowed for kind %s", kind), "drop --format-envelope; it belongs to kind secret")
		}
		if !Contains(formatsPublic, format.Public) {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.public %q is not one of %s", format.Public, strings.Join(formatsPublic, ", ")), HintFixInput)
		}
		if !Contains(formatsSignature, format.Signature) {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.signature %q is not one of %s", format.Signature, strings.Join(formatsSignature, ", ")), HintFixInput)
		}
	case KindCertificate:
		if format.Signature != "" || format.Envelope != "" {
			return refuse(CodeInvalidFormat, "only format.public is allowed for kind certificate", HintFixInput)
		}
		if !Contains(formatsCertificatePublic, format.Public) {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.public %q is not one of %s for a certificate", format.Public, strings.Join(formatsCertificatePublic, ", ")), HintFixInput)
		}
	case KindSecret:
		if format.Public != "" || format.Signature != "" {
			return refuse(CodeInvalidFormat, "only format.envelope is allowed for kind secret", HintFixInput)
		}
		if !Contains(formatsSecretEnvelope, format.Envelope) {
			return refuse(CodeInvalidFormat, fmt.Sprintf("format.envelope %q is not one of %s", format.Envelope, strings.Join(formatsSecretEnvelope, ", ")), HintFixInput)
		}
	}
	return nil
}

// validateOrigin requires the vault-set provenance: user, host and tool
// present, source either generated or imported:<sha256>.
func validateOrigin(origin Origin) error {
	if origin.User == "" || origin.Host == "" || origin.Tool == "" {
		return refuse(CodeInvalidOrigin, "origin.user, origin.host and origin.tool must be present; the vault sets them", HintFixInput)
	}
	if origin.Source != SourceGenerated && !importedSourcePattern.MatchString(origin.Source) {
		return refuse(CodeInvalidOrigin, fmt.Sprintf("origin.source %q is neither generated nor imported:<sha256>", origin.Source), HintFixInput)
	}
	return nil
}

// ValidateIssuer enforces the kind-specific issuer invariant: only a
// certificate carries an issuer, and then a complete one; every other kind
// must carry null (review F8).
func ValidateIssuer(kind string, issuer *Issuer) error {
	switch kind {
	case KindCertificate:
		if issuer == nil || issuer.DN == "" || issuer.Fingerprint == "" {
			return refuse(CodeInvalidIssuer, "a certificate must carry issuer.dn and issuer.fingerprint", HintFixInput)
		}
	default:
		if issuer != nil {
			return refuse(CodeInvalidIssuer, fmt.Sprintf("issuer must be null for kind %s; only a certificate has an issuer", kind), HintFixInput)
		}
	}
	return nil
}

// validateValidity enforces the kind-specific validity invariant (§2): a
// certificate carries both bounds copied from X.509; every other kind
// carries not_before null and at most a caller-supplied not_after (review
// F13). When both are present not_after must follow not_before.
func validateValidity(kind string, validity Validity) error {
	switch kind {
	case KindCertificate:
		if validity.NotBefore == nil || validity.NotAfter == nil {
			return refuse(CodeInvalidValidity, "a certificate must carry validity.not_before and validity.not_after from its X.509", HintFixInput)
		}
	default:
		if validity.NotBefore != nil {
			return refuse(CodeInvalidValidity, fmt.Sprintf("validity.not_before must be null for kind %s; only a certificate carries not_before", kind), "drop not_before; a key or secret takes only --not-after")
		}
	}
	if validity.NotBefore != nil && validity.NotAfter != nil && !validity.NotAfter.After(validity.NotBefore.Time) {
		return refuse(CodeInvalidValidity, "validity.not_after must be after validity.not_before", HintFixInput)
	}
	return nil
}
