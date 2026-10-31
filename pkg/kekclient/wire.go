package kekclient

import (
	"encoding/json"
	"fmt"
)

// Operations of contract kek-1.
const (
	OpUnwrap = "unwrap"
	OpRebind = "rebind"
)

// Request is the one line a caller sends on the broker's socket.
type Request struct {
	Contract string          `json:"contract"`
	Op       string          `json:"op"`
	Address  string          `json:"address"`
	Envelope json.RawMessage `json:"envelope"`
}

// Response is the one line the broker answers. Exactly one of Result and
// Error is set.
type Response struct {
	Contract string  `json:"contract"`
	OK       bool    `json:"ok"`
	Result   *Result `json:"result,omitempty"`
	Error    *Error  `json:"error,omitempty"`
}

// Result carries the KEK for unwrap and the new envelope for rebind, with
// the key that served it.
type Result struct {
	Address     string          `json:"address"`
	Generation  int             `json:"generation"`
	Fingerprint string          `json:"fingerprint"`
	KEK         []byte          `json:"kek,omitempty"`
	Envelope    json.RawMessage `json:"envelope,omitempty"`
}

// Error is a declared refusal or failure. Code is one of Codes.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("mac-keyvault-kek: %s: %s", e.Code, e.Message) }

// Error codes of contract kek-1. The set is closed: a client treats any
// other code as a protocol failure.
const (
	CodeBadRequest      = "bad_request"
	CodeCallerRefused   = "caller_refused"
	CodeEnvelopeInvalid = "envelope_invalid"
	CodeNotFound        = "not_found"
	CodeExpired         = "expired"
	CodeUsageRefused    = "usage_refused"
	CodeMetadataUnknown = "metadata_unknown"
	CodeRebindRefused   = "rebind_refused"
	CodeUnsupported     = "unsupported_primitive"
	CodeSecurity        = "security"
)

// Codes lists every declared error code.
var Codes = []string{CodeBadRequest, CodeCallerRefused, CodeEnvelopeInvalid, CodeNotFound, CodeExpired, CodeUsageRefused, CodeMetadataUnknown, CodeRebindRefused, CodeUnsupported, CodeSecurity}

func declared(code string) bool {
	for _, c := range Codes {
		if c == code {
			return true
		}
	}
	return false
}
