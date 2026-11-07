// Package publishergate contains the bounded message-admission portion of the
// publisher-call/1 design. It has no native adapter, key access or signing path.
// Parsed requests and message admission are not permission to use a private key.
package publishergate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

const (
	Version         = "publisher-call/1"
	Operation       = "publish-current"
	MaxRequestBytes = 1024
)

// Request is an immutable, syntactically checked message, not an authenticated
// caller. It carries no key, digest, entries, output path or identity assertion.
type Request struct {
	scope string
	epoch uint64
	nonce [32]byte
}

func (r Request) ScopeID() string        { return r.scope }
func (r Request) PolicyEpoch() uint64    { return r.epoch }
func (r Request) RequestNonce() [32]byte { return r.nonce }

// DecodeRequest accepts exactly one flat JSON object with the five design
// fields. JSON is the bounded source codec, not an implemented XPC transport.
// request_nonce is canonical unpadded base64url of exactly 32 bytes. Duplicate
// keys (including escaped spellings), unknown fields, attachments represented
// as fields, trailing messages and nested values are refused. Native attachment
// exclusion and preallocation bounds remain obligations of a future adapter.
func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) > MaxRequestBytes {
		return r, refusal(ResourceLimit)
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return r, refusal(OperationRefused)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return r, refusal(OperationRefused)
	}
	seen := make(map[string]bool, 5)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return Request{}, refusal(OperationRefused)
		}
		switch name {
		case "version", "op", "scope_id", "policy_epoch", "request_nonce":
		default:
			return Request{}, refusal(OperationRefused)
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return Request{}, refusal(OperationRefused)
		}
		switch name {
		case "version":
			if value != Version {
				return Request{}, refusal(OperationRefused)
			}
		case "op":
			if value != Operation {
				return Request{}, refusal(OperationRefused)
			}
		case "scope_id":
			text, ok := value.(string)
			if !ok || !validScope(text) {
				return Request{}, refusal(OperationRefused)
			}
			r.scope = text
		case "policy_epoch":
			number, ok := value.(json.Number)
			if !ok {
				return Request{}, refusal(OperationRefused)
			}
			r.epoch, err = strconv.ParseUint(string(number), 10, 64)
			if err != nil || r.epoch == 0 {
				return Request{}, refusal(OperationRefused)
			}
		case "request_nonce":
			text, ok := value.(string)
			if !ok || len(text) != 43 {
				return Request{}, refusal(OperationRefused)
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
			if err != nil || len(decoded) != len(r.nonce) || base64.RawURLEncoding.EncodeToString(decoded) != text {
				return Request{}, refusal(OperationRefused)
			}
			copy(r.nonce[:], decoded)
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 5 {
		return Request{}, refusal(OperationRefused)
	}
	if _, err := d.Token(); err != io.EOF {
		return Request{}, refusal(OperationRefused)
	}
	return r, nil
}

func validScope(scope string) bool {
	if len(scope) == 0 || len(scope) > 64 {
		return false
	}
	for i := range scope {
		if scope[i] > 127 {
			return false
		}
	}
	return true
}
