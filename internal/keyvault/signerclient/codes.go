package signerclient

import "sort"

// Error codes of the mac-keyvault error contract (key-record-model-v2 §8
// and the rows T1–T3 added). This file is the single registry: the CLI
// classifier, the signer server, StreamErrorCodes and the golden coverage
// test all read ErrorContract, and the keyvault package's Code* constants
// are aliases of these, so a code cannot exist in one place and not the
// other. A consumer vendors this package verbatim (stdlib only).
const (
	CodeUsage                = "usage"
	CodeFailure              = "failure"
	CodeNotFound             = "not_found"
	CodeForeignLabel         = "foreign_label"
	CodeDuplicate            = "duplicate"
	CodeConfirmationRequired = "confirmation_required"
	CodeMissingEntitlement   = "missing_entitlement"
	CodeUnsupportedStore     = "unsupported_store"
	CodeSecurity             = "security"
	CodeInvalidSchema        = "invalid_schema"
	CodeInvalidVersion       = "invalid_version"
	CodeInvalidCreated       = "invalid_created"
	CodeInvalidOrigin        = "invalid_origin"
	CodeInvalidService       = "invalid_service"
	CodeInvalidPurpose       = "invalid_purpose"
	CodeInvalidKind          = "invalid_kind"
	CodeUnsupportedKind      = "unsupported_kind"
	CodeInvalidAlgorithm     = "invalid_algorithm"
	CodeUnsupportedAlgorithm = "unsupported_algorithm"
	CodeInvalidUsages        = "invalid_usages"
	CodeInvalidFormat        = "invalid_format"
	CodeInvalidExtraction    = "invalid_extraction"
	CodeInvalidGenerate      = "invalid_generate"
	CodeInvalidMeta          = "invalid_meta"
	CodeInvalidTitle         = "invalid_title"
	CodeInvalidIssuer        = "invalid_issuer"
	CodeInvalidValidity      = "invalid_validity"
	CodeMetadataUnknown      = "metadata_unknown"
	CodeUnsupportedPrimitive = "unsupported_primitive"
	CodeInvalidDigest        = "invalid_digest"
	CodeInvalidSignature     = "invalid_signature"
	CodeSignatureInvalid     = "signature_invalid"
	CodeHighSRefused         = "high_s_refused"
	CodeUsageRefused         = "usage_refused"
	CodeExpired              = "expired"
	CodeInvalidPublicKey     = "invalid_public_key"
	CodeBadRequest           = "bad_request" // signer stream: line is not one JSON object, or a member/parameter is not allowed or malformed for the op
	CodeMissingID            = "missing_id"  // signer stream: id absent, null, or not a string/number
	CodeUnknownOp            = "unknown_op"  // signer stream: op absent, not a string, or outside Ops
)

// Exit classes of the CLI (`--json` envelope and the signer startup hello).
const (
	ExitFailure = 1 // operational failure
	ExitUsage   = 2 // command-line mistake
	ExitRefused = 3 // policy refusal
)

// ErrorCode is one row of the error contract: the stable code, the exit
// class a CLI command answers it with, whether a contract-1 signer stream
// can carry it (Stream — in the startup hello or in a response), and when
// it is produced.
type ErrorCode struct {
	Code   string
	Exit   int
	Stream bool
	When   string
}

// ErrorContract is the §8 table in registry form. Stream marks the codes a
// consumer of `signer serve` can read: every one of them has a byte-exact
// golden fixture under mac-keyvault's testdata/signer-v1 driven through
// its production entry point (the startup ones through the CLI, the rest
// through the server), and the golden coverage test enumerates this table
// against that corpus in both directions.
var ErrorContract = []ErrorCode{
	{CodeUsage, ExitUsage, true, "bad flags/args; signer serve writes it as the startup hello"},
	{CodeFailure, ExitFailure, true, "an I/O or backend error outside the Security.framework status space (lock path, a backend error that is not an OSStatus)"},
	{CodeNotFound, ExitFailure, true, "no record for address/kind/version: the hello when the address does not resolve, a response when the generation vanished after the hello"},
	{CodeForeignLabel, ExitRefused, true, "the address is a raw label or resolves outside the vault prefix (startup hello)"},
	{CodeDuplicate, ExitRefused, false, "(kind, service, purpose, version) exists on init"},
	{CodeConfirmationRequired, ExitRefused, false, "delete without --confirm; ssh-agent unlock not confirmed"},
	{CodeMissingEntitlement, ExitFailure, true, "Security returned -34018 (enclave / data-protection keychain); hello when list fails so, response when sign does"},
	{CodeUnsupportedStore, ExitRefused, false, "a store this revision does not create"},
	{CodeSecurity, ExitFailure, true, "any other Security.framework failure (os_status set), or its output is untrusted: unreadable public half on pub/verify, a signature that does not parse or verify under the key on sign (no os_status)"},
	{CodeInvalidSchema, ExitRefused, false, "record invariant: schema"},
	{CodeInvalidVersion, ExitRefused, false, "record invariant: version"},
	{CodeInvalidCreated, ExitRefused, false, "record invariant: created"},
	{CodeInvalidOrigin, ExitRefused, false, "record invariant: origin"},
	{CodeInvalidService, ExitRefused, true, "service outside [a-z0-9-]{1,40} (startup hello)"},
	{CodeInvalidPurpose, ExitRefused, true, "purpose outside [a-z0-9-]{1,40}, or a negative --version (startup hello)"},
	{CodeInvalidKind, ExitRefused, true, "--kind outside the closed kind vocabulary (startup hello)"},
	{CodeUnsupportedKind, ExitRefused, false, "a kind this revision validates but does not create (init)"},
	{CodeInvalidAlgorithm, ExitRefused, false, "record invariant: algorithm"},
	{CodeUnsupportedAlgorithm, ExitRefused, false, "an algorithm reserved and not created"},
	{CodeInvalidUsages, ExitRefused, false, "record invariant: usages"},
	{CodeInvalidFormat, ExitRefused, false, "record invariant: format"},
	{CodeInvalidExtraction, ExitRefused, false, "record invariant: extraction"},
	{CodeInvalidGenerate, ExitRefused, false, "record invariant: generate"},
	{CodeInvalidMeta, ExitRefused, false, "record invariant: meta"},
	{CodeInvalidTitle, ExitRefused, false, "record invariant: title"},
	{CodeInvalidIssuer, ExitRefused, false, "record invariant: issuer"},
	{CodeInvalidValidity, ExitRefused, false, "record invariant: validity"},
	{CodeMetadataUnknown, ExitRefused, true, "the record is unreadable or fails its invariants; policy unknown, the operation is not performed"},
	{CodeUnsupportedPrimitive, ExitFailure, true, "the record's (kind, algorithm, store) has no registry row"},
	{CodeInvalidDigest, ExitRefused, true, "digest is not DigestSize bytes (sign, verify)"},
	{CodeInvalidSignature, ExitRefused, true, "signature bytes are not strict DER / 64 raw bytes (verify)"},
	{CodeSignatureInvalid, ExitFailure, true, "well-formed signature that does not verify; result.verified is false (verify)"},
	{CodeHighSRefused, ExitRefused, true, "signature s is malleable and allow_high_s is not set (verify)"},
	{CodeUsageRefused, ExitRefused, true, "the record's usages do not admit the operation (sign)"},
	{CodeExpired, ExitRefused, true, "validity.not_after has passed (sign)"},
	{CodeInvalidPublicKey, ExitRefused, true, "the stored public half is not a P-256 SPKI (verify)"},
	{CodeBadRequest, ExitRefused, true, "signer stream only"},
	{CodeMissingID, ExitRefused, true, "signer stream only"},
	{CodeUnknownOp, ExitRefused, true, "signer stream only"},
}

// Lookup returns the registry row of code; ok is false for a code the
// contract does not define.
func Lookup(code string) (row ErrorCode, ok bool) {
	for _, r := range ErrorContract {
		if r.Code == code {
			return r, true
		}
	}
	return ErrorCode{}, false
}

// StreamErrorCodes is the closed set of error codes a contract-1 stream
// can carry — the startup hello and every response included — derived
// from ErrorContract (Stream rows), sorted. A consumer switches on these
// and treats any other code as a contract break.
func StreamErrorCodes() []string {
	var codes []string
	for _, r := range ErrorContract {
		if r.Stream {
			codes = append(codes, r.Code)
		}
	}
	sort.Strings(codes)
	return codes
}

// IsStreamCode reports whether code is one a contract-1 stream may carry.
func IsStreamCode(code string) bool {
	row, ok := Lookup(code)
	return ok && row.Stream
}
