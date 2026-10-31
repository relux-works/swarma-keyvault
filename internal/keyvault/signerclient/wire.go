// Package signerclient is the machine contract between mac-keyvault and a
// consumer that needs signatures from a vault key without touching the
// keychain itself (kvctl's macos-keychain backend). It has no dependency
// outside the standard library so a consumer can vendor it verbatim.
//
// Wire (contract 1): `mac-keyvault signer serve --address <service>/<purpose>
// [--kind key] [--version N]` speaks JSON lines over stdin/stdout. The
// first line the server writes is the hello: {contract: 1, ok: true,
// result: Hello}, or {contract: 1, ok: false, error} when the address does
// not resolve (the process then exits with the CLI exit code). After the
// hello every stdin line is one Request and produces exactly one Response
// line in order (the hello names the generation the server resolved, and
// that generation stays bound for the whole stream — a rotate after the
// hello does not move it, so the hello fingerprint attests every later
// signature): {id, ok, result} or {id, ok: false, error{code, message,
// hint, os_status?}}; verify additionally carries result.verified on a
// false verdict. A malformed line, an unknown op, a missing id or a
// refused operation is answered with an error response and never ends the
// stream; EOF on stdin ends the server with exit 0. The error codes a
// stream can carry — hello and responses — are the Stream rows of
// ErrorContract (codes.go), read through StreamErrorCodes; any other code
// is a contract break. Blank lines are ignored. Requests are served
// sequentially in arrival order. A consumer judges every line by member
// presence and JSON type before it decodes it (the member contract is
// documented at decodeEnvelope in envelope.go): a missing or null ok, a
// null error or result, or an error object without code, message and hint
// is a contract break, not a false / absent / empty value; the read is
// token-level (DecodeObject), and before ANY typed decode the whole line
// takes CheckDocument, one recursive strict pass over every depth
// (objects in objects, objects in arrays), so a repeated member name —
// verbatim or escape-spelt — at any level is a contract break too, on
// both ends: the server answers bad_request under id null, the client
// kills the server with ErrProtocol. And
// every result is judged (checkResult, result.go) against the pending
// request and the accepted hello before a typed helper returns it: the
// hello fingerprint attests the key every pub result must fingerprint
// as, every sign result must verify under, and every verify verdict is
// re-derived under — and a describe result is decoded and judged with
// the vault's own record model (Record, DecodeSingleJSON and the
// per-kind invariant table live in this package, record.go and
// invariants.go, and internal/keyvault aliases them), so the client
// admits exactly the record the vault would.
package signerclient

import "encoding/json"

// Contract is the wire version this package speaks; the server announces
// it in the hello line and a client refuses any other value.
const Contract = 1

// Tool is the value of hello.tool a contract-1 server announces; a client
// refuses any other (the hello would attest a different signer identity).
const Tool = "mac-keyvault"

// KindKey is the record kind bound when --kind is omitted; the hello
// announces the effective kind and a client checks it against the one it
// requested (or KindKey).
const KindKey = "key"

// Operations of contract 1.
const (
	OpDescribe = "describe"
	OpPub      = "pub"
	OpSign     = "sign"
	OpVerify   = "verify"
)

// Ops lists the contract-1 operations in the order the hello announces them.
var Ops = []string{OpDescribe, OpPub, OpSign, OpVerify}

// Public-key and signature representations of contract 1. They are the
// record vocabulary of mac-keyvault; the server refuses any other value
// with code bad_request.
const (
	FormatSPKIDER = "spki-der"        // pub: result.der_base64
	FormatSPKIPEM = "spki-pem"        // pub: result.pem
	FormatDERLowS = "ecdsa-der-low-s" // sign/verify: strict X9.62 DER, s in the low half
	FormatRaw     = "ecdsa-raw"       // sign/verify: 64 bytes r||s
	Hash          = "sha256"          // the only digest the contract signs
	DigestSize    = 32
)

// Request is one stdin line. id is echoed verbatim in the response and must
// be a JSON string or number. Members an op does not take must be absent:
// the server judges presence before value, so an explicit false or ""
// for such a member is bad_request exactly like a member the contract
// does not define (describe takes none; pub takes format; sign takes
// format and digest; verify takes format, digest, signature and
// allow_high_s). The omitempty tags make a Client never send one.
type Request struct {
	ID json.RawMessage `json:"id,omitempty"`
	Op string          `json:"op"`
	// Format: pub takes spki-der (default) or spki-pem; sign and verify
	// take ecdsa-der-low-s or ecdsa-raw (sign defaults to the record's
	// format.signature, verify to ecdsa-der-low-s).
	Format string `json:"format,omitempty"`
	// Digest is the SHA-256 digest as 64 hex characters (sign, verify).
	Digest string `json:"digest,omitempty"`
	// Signature is the signature bytes as hex in the given format (verify).
	Signature string `json:"signature,omitempty"`
	// AllowHighS accepts a malleable (high-S) signature on verify.
	AllowHighS bool `json:"allow_high_s,omitempty"`
}

// Response is one stdout line. Contract is set only on the hello line; ID
// is absent on the hello, otherwise the request's id (null when the
// request carried none).
type Response struct {
	Contract int             `json:"contract,omitempty"`
	ID       json.RawMessage `json:"id,omitempty"`
	OK       bool            `json:"ok"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *Error          `json:"error,omitempty"`
}

// Error is the mac-keyvault error contract: a stable code, a message in the
// caller's terms, a hint that says what to do next, and the OSStatus when
// Security.framework produced the failure.
type Error struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Hint     string `json:"hint"`
	OSStatus int    `json:"os_status,omitempty"`
}

func (e *Error) Error() string {
	if e.OSStatus != 0 {
		return e.Code + ": " + e.Message + " (OSStatus " + itoa(e.OSStatus) + ")"
	}
	return e.Code + ": " + e.Message
}

// Hello is the result of the hello line: what the server is bound to. A
// client accepts it only as one coherent binding: tool == Tool, address ==
// the one requested, kind == the one requested (KindKey when omitted),
// version pinned (never 0) and equal to the requested one when one was,
// label and fingerprint present, ops == Ops exactly; anything else is
// ErrProtocol and the server is reaped.
type Hello struct {
	Tool        string   `json:"tool"`
	ToolVersion string   `json:"tool_version"`
	Address     string   `json:"address"`
	Kind        string   `json:"kind"`
	Version     int      `json:"version"` // the generation bound for the stream (never 0): the newest at hello when 0 was requested
	Label       string   `json:"label"`   // the label of that generation
	Fingerprint string   `json:"fingerprint"`
	Ops         []string `json:"ops"`
}

// Description is the result of describe: the schema-2 record exactly as
// the vault stores it (Record — closed: a member the schema does not
// define is a contract break, the same DisallowUnknownFields rule the
// vault applies to its own persisted tag) plus the five derived members a
// read prints. checkDescribe (result.go) runs the vault's invariant table
// over it and binds it to the hello before Describe returns it.
type Description struct {
	Record
	Label       string      `json:"label"`
	Fingerprint string      `json:"fingerprint"`
	Exposure    string      `json:"exposure"`
	Operations  []Operation `json:"operations"`
	Findings    []string    `json:"findings"`
}

// Operation is one entry of Description.Operations: what the key can do
// right now, derived by the vault from its registry and the record's
// policy. Via names the contract op (or CLI command) that performs it;
// ViaReserved marks one no command performs yet.
type Operation struct {
	Name            string `json:"name"`
	Input           string `json:"input"`
	Output          string `json:"output"`
	Via             string `json:"via"`
	HumanAuthorized bool   `json:"human_authorized,omitempty"`
}

// ViaReserved marks an operation no CLI command performs yet; a consumer
// never assumes it works.
const ViaReserved = "reserved"

// Exposures is the closed vocabulary of Description.Exposure: never and
// process from the registry row, Unknown when the record has no row
// (then Findings carries unsupported_primitive and Operations is empty).
var Exposures = []string{ExposureNever, ExposureProcess, Unknown}

// PublicKey is the result of pub.
type PublicKey struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Format      string `json:"format"`
	DERBase64   string `json:"der_base64,omitempty"`
	PEM         string `json:"pem,omitempty"`
}

// Signature is the result of sign.
type Signature struct {
	Label           string `json:"label"`
	Fingerprint     string `json:"fingerprint"`
	Hash            string `json:"hash"`
	Digest          string `json:"digest"`
	Format          string `json:"format"`
	Signature       string `json:"signature"` // hex
	SignatureBase64 string `json:"signature_base64"`
	LowS            bool   `json:"low_s"`
	Normalized      bool   `json:"normalized"`
}

// Verdict is the result of verify; on a false verdict it travels next to
// the signature_invalid error.
type Verdict struct {
	Label        string `json:"label,omitempty"`       // absent when the signature was refused before the key was read
	Fingerprint  string `json:"fingerprint,omitempty"` // same
	Hash         string `json:"hash"`
	Digest       string `json:"digest"`
	Format       string `json:"format"`
	LowS         bool   `json:"low_s"`
	HighSAllowed bool   `json:"high_s_allowed"`
	Verified     bool   `json:"verified"`
}

func itoa(v int) string {
	b, _ := json.Marshal(v)
	return string(b)
}
