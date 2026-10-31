// Package recordtest is the shared forgery table the keyvault and
// mac-keyvault test suites drive against the per-kind record invariants: one
// forged value per record field on an otherwise valid stored schema-2 key.
// Both suites assert every row is refused by rotate and meta writes
// (metadata_unknown, zero creates, old tag byte-identical) and reported by
// reads (record_invalid:<code>), so a new field or a dropped invariant row
// fails here instead of surfacing as the next review finding.
package recordtest

import (
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// Forgery mutates exactly one field of a valid key record.
type Forgery struct {
	// Name is the sub-test name: "<field> <shape>".
	Name string
	// Field is the record field the forgery touches (matches
	// keyvault.InvariantFields).
	Field string
	// Code is the refusal code the invariant row must raise.
	Code string
	// Mutate applies the forgery.
	Mutate func(*keyvault.Record)
}

// Forgeries lists one or more forged shapes for every field of a schema-2
// key record. schema is forged through the encoder (a schema-3 tag is
// unreadable, not a schema-2 record); label disagreement is covered by
// LabelMismatch because it needs the stored label, not a field.
func Forgeries() []Forgery {
	at := func(unix int64) *keyvault.Time {
		t := keyvault.NewTime(time.Unix(unix, 0))
		return &t
	}
	return []Forgery{
		{"kind unknown", "kind", keyvault.CodeInvalidKind, func(r *keyvault.Record) { r.Kind = "keypair" }},
		{"service uppercase", "service", keyvault.CodeInvalidService, func(r *keyvault.Record) { r.Service = "TEST" }},
		{"purpose slash", "purpose", keyvault.CodeInvalidPurpose, func(r *keyvault.Record) { r.Purpose = "a/b" }},
		{"version zero", "version", keyvault.CodeInvalidVersion, func(r *keyvault.Record) { r.Version = 0 }},
		{"algorithm aes on key", "algorithm", keyvault.CodeInvalidAlgorithm, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmAES256GCM }},
		{"algorithm reserved", "algorithm", keyvault.CodeUnsupportedAlgorithm, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmECP384 }},
		{"algorithm ed25519", "algorithm", keyvault.CodeUnsupportedAlgorithm, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmEd25519 }},
		{"store tpm", "store", keyvault.CodeUnsupportedStore, func(r *keyvault.Record) { r.Store = "tpm" }},
		{"extraction unknown", "extraction", keyvault.CodeInvalidExtraction, func(r *keyvault.Record) { r.Extraction = "always" }},
		{"extraction agent on enclave", "extraction", keyvault.CodeInvalidExtraction, func(r *keyvault.Record) { r.Store = keyvault.StoreEnclave; r.Extraction = keyvault.ExtractionAgent }},
		{"usages empty", "usages", keyvault.CodeInvalidUsages, func(r *keyvault.Record) { r.Usages = nil }},
		{"usages unknown", "usages", keyvault.CodeInvalidUsages, func(r *keyvault.Record) { r.Usages = []string{"sign", "export"} }},
		{"usages duplicate", "usages", keyvault.CodeInvalidUsages, func(r *keyvault.Record) { r.Usages = []string{"sign", "sign"} }},
		{"format envelope on key", "format", keyvault.CodeInvalidFormat, func(r *keyvault.Record) { r.Format.Envelope = "json" }},
		{"format public x509 on key", "format", keyvault.CodeInvalidFormat, func(r *keyvault.Record) { r.Format.Public = "x509-der" }},
		{"format signature empty", "format", keyvault.CodeInvalidFormat, func(r *keyvault.Record) { r.Format.Signature = "" }},
		{"title 81 characters", "title", keyvault.CodeInvalidTitle, func(r *keyvault.Record) { r.Title = string(make81()) }},
		{"created null", "created", keyvault.CodeInvalidCreated, func(r *keyvault.Record) { r.Created = keyvault.Time{} }},
		{"origin user empty", "origin", keyvault.CodeInvalidOrigin, func(r *keyvault.Record) { r.Origin.User = "" }},
		{"origin tool empty", "origin", keyvault.CodeInvalidOrigin, func(r *keyvault.Record) { r.Origin.Tool = "" }},
		{"origin source bogus", "origin", keyvault.CodeInvalidOrigin, func(r *keyvault.Record) { r.Origin.Source = "imported" }},
		{"origin source short digest", "origin", keyvault.CodeInvalidOrigin, func(r *keyvault.Record) { r.Origin.Source = "imported:abcd" }},
		{"issuer on key", "issuer", keyvault.CodeInvalidIssuer, func(r *keyvault.Record) { r.Issuer = &keyvault.Issuer{DN: "CN=forged", Fingerprint: "sha256:00"} }},
		// F13: not_before is certificate-derived and must be null on a key,
		// whether or not not_after is set.
		{"validity not_before on key", "validity", keyvault.CodeInvalidValidity, func(r *keyvault.Record) { r.Validity = keyvault.Validity{NotBefore: at(1_800_000_000)} }},
		{"validity not_before with not_after", "validity", keyvault.CodeInvalidValidity, func(r *keyvault.Record) {
			r.Validity = keyvault.Validity{NotBefore: at(1_800_000_000), NotAfter: at(1_900_000_000)}
		}},
		{"validity inverted", "validity", keyvault.CodeInvalidValidity, func(r *keyvault.Record) {
			r.Validity = keyvault.Validity{NotBefore: at(1_900_000_000), NotAfter: at(1_800_000_000)}
		}},
		{"meta reserved name", "meta", keyvault.CodeInvalidMeta, func(r *keyvault.Record) { r.Meta = map[string]any{"fingerprint": "x"} }},
		{"meta nested value", "meta", keyvault.CodeInvalidMeta, func(r *keyvault.Record) { r.Meta = map[string]any{"owner": map[string]any{"a": 1}} }},
	}
}

// LabelMismatch forges the identity fields so the record no longer names
// the label it is stored under; the expected code is metadata_unknown.
func LabelMismatch(r *keyvault.Record) { r.Version++ }

// PositiveControls are stored key records every gate must admit: both
// validity bounds null, and only a future not_after.
func PositiveControls() map[string]func(*keyvault.Record) {
	return map[string]func(*keyvault.Record){
		"validity both null": func(r *keyvault.Record) { r.Validity = keyvault.Validity{} },
		"validity only not_after": func(r *keyvault.Record) {
			t := keyvault.NewTime(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
			r.Validity = keyvault.Validity{NotAfter: &t}
		},
	}
}

func make81() []rune {
	out := make([]rune, 81)
	for i := range out {
		out[i] = 'x'
	}
	return out
}
