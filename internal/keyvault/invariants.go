package keyvault

import "github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"

// Per-kind record invariants (model v2 §2), one table for every field.
//
// The table itself lives in signerclient/invariants.go so the signer
// client runs the vault's own rows against a describe result (review rev7
// F1); every path that admits a record — Init, Rotate, MetaSet/MetaUnset —
// runs the whole table before any Security call, while every read
// (describe, list) reports a failing row as a finding instead of a refusal.

// Refusal codes raised by rows that no earlier revision named.
const (
	CodeInvalidSchema  = signerclient.CodeInvalidSchema
	CodeInvalidVersion = signerclient.CodeInvalidVersion
	CodeInvalidCreated = signerclient.CodeInvalidCreated
	CodeInvalidOrigin  = signerclient.CodeInvalidOrigin
	// FindingRecordInvalid prefixes a read finding "record_invalid:<code>"
	// for a schema-2 record that violates a row; the item is still listed
	// and described so the operator can see and delete it.
	FindingRecordInvalid = signerclient.FindingRecordInvalid
)

func refuse(code, message, hint string) error {
	return &Refusal{Code: code, Message: message, Hint: hint}
}

// InvariantFields lists the fields the table governs, in table order; the
// table test asserts it against the Record struct so a new field cannot be
// added without a row.
func InvariantFields() []string { return signerclient.InvariantFields() }

// ValidateRecord runs every row against the record and returns the first
// refusal. Nothing here touches Security.framework.
func ValidateRecord(rec Record) error { return signerclient.ValidateRecord(rec) }

// ValidateStored checks a record read back from the keychain: every row
// plus agreement between the record and the label it was stored under. A
// forged or drifted stored record is refused by rotate and meta writes and
// reported as a finding by reads.
func ValidateStored(label string, rec Record) error { return signerclient.ValidateStored(label, rec) }

// validateIssuer is the issuer row of the table (kept callable here for the
// per-kind issuer test).
func validateIssuer(kind string, issuer *Issuer) error {
	return signerclient.ValidateIssuer(kind, issuer)
}
