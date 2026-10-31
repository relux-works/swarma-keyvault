package kekclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// jsonKind is the JSON type a contract member must have.
type jsonKind int

const (
	kindString jsonKind = iota
	kindNumber
	kindBool
	kindObject
)

// member describes one contract member: its exact name, its type, and
// whether it must be present. No contract member may be null.
type member struct {
	kind     jsonKind
	required bool
}

// shape is the closed member set of one contract object.
type shape map[string]member

var (
	envelopeShape = shape{
		"format": {kindString, true}, "v": {kindNumber, true}, "address": {kindString, true},
		"generation": {kindNumber, true}, "fingerprint": {kindString, true}, "kcv": {kindString, true}, "ecies": {kindString, true},
	}
	payloadShape = shape{
		"v": {kindNumber, true}, "address": {kindString, true}, "generation": {kindNumber, true}, "fingerprint": {kindString, true},
		"requirement": {kindString, true}, "install_path": {kindString, true}, "kcv": {kindString, true}, "kek": {kindString, true},
	}
	requestShape = shape{
		"contract": {kindString, true}, "op": {kindString, true}, "address": {kindString, true}, "envelope": {kindObject, true},
	}
	responseShape = shape{
		"contract": {kindString, true}, "ok": {kindBool, true}, "result": {kindObject, false}, "error": {kindObject, false},
	}
	resultShape = shape{
		"address": {kindString, true}, "generation": {kindNumber, true}, "fingerprint": {kindString, true},
		"kek": {kindString, false}, "envelope": {kindObject, false},
	}
	errorShape = shape{"code": {kindString, true}, "message": {kindString, true}}
)

// objectMembers reads data as exactly one JSON object and nothing after it,
// and returns its members by their exact (unescaped) names. A repeated name
// is refused before any typed decode can let a later value win.
//
// The values are views into data, never copies: data can hold a KEK (an
// answer, a decrypted payload), and the caller clears data, which clears
// every member with it. data is first checked by json.Valid, which neither
// copies nor keeps it; the scan below then only has to find value
// boundaries in valid JSON.
func objectMembers(data []byte) (map[string]json.RawMessage, error) {
	if !json.Valid(data) {
		return nil, errors.New("not valid JSON")
	}
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	i = skipSpace(data, i+1)
	if i < len(data) && data[i] == '}' {
		i++
	} else {
		for {
			if i >= len(data) || data[i] != '"' {
				return nil, errors.New("member name is not a string")
			}
			end := stringEnd(data, i)
			var name string
			if err := json.Unmarshal(data[i:end], &name); err != nil {
				return nil, err
			}
			if _, seen := members[name]; seen {
				return nil, fmt.Errorf("member %q repeated", name)
			}
			i = skipSpace(data, end)
			if i >= len(data) || data[i] != ':' {
				return nil, errors.New("no colon after a member name")
			}
			start := skipSpace(data, i+1)
			stop := valueEnd(data, start)
			members[name] = json.RawMessage(data[start:stop:stop])
			i = skipSpace(data, stop)
			if i < len(data) && data[i] == ',' {
				i = skipSpace(data, i+1)
				continue
			}
			if i < len(data) && data[i] == '}' {
				i++
				break
			}
			return nil, errors.New("malformed object")
		}
	}
	if skipSpace(data, i) != len(data) {
		return nil, errors.New("data after the object")
	}
	return members, nil
}

func skipSpace(data []byte, i int) int {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return i
}

// stringEnd returns the index just past the string that starts at data[i].
func stringEnd(data []byte, i int) int {
	for j := i + 1; j < len(data); j++ {
		switch data[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(data)
}

// valueEnd returns the index just past the value that starts at data[i] in
// valid JSON.
func valueEnd(data []byte, i int) int {
	if i >= len(data) {
		return i
	}
	switch data[i] {
	case '"':
		return stringEnd(data, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(data); j++ {
			switch data[j] {
			case '"':
				j = stringEnd(data, j) - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(data)
	}
	j := i
	for j < len(data) && !bytes.ContainsRune([]byte(" \t\n\r,}]"), rune(data[j])) {
		j++
	}
	return j
}

// checkShape reads data as one object with exactly the members of s: exact
// names (encoding/json would otherwise match names case-insensitively), no
// unknown or missing required member, no null, each of its declared type.
// Nested objects are returned for their own check.
func checkShape(data []byte, s shape) (map[string]json.RawMessage, error) {
	members, err := objectMembers(data)
	if err != nil {
		return nil, err
	}
	for name, value := range members {
		m, ok := s[name]
		if !ok {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		if !hasKind(value, m.kind) {
			return nil, fmt.Errorf("member %q has the wrong type", name)
		}
	}
	for name, m := range s {
		if _, ok := members[name]; m.required && !ok {
			return nil, fmt.Errorf("member %q missing", name)
		}
	}
	return members, nil
}

func hasKind(value json.RawMessage, kind jsonKind) bool {
	v := bytes.TrimSpace(value)
	if len(v) == 0 {
		return false
	}
	switch kind {
	case kindString:
		return v[0] == '"'
	case kindNumber:
		return v[0] == '-' || (v[0] >= '0' && v[0] <= '9')
	case kindBool:
		return bytes.Equal(v, []byte("true")) || bytes.Equal(v, []byte("false"))
	case kindObject:
		return v[0] == '{'
	}
	return false
}

// decodeStrict checks data against s, then decodes it into v. After the
// shape check every name is exact and unique, so the typed decode cannot
// pick a different value than the one checked.
func decodeStrict(data []byte, s shape, v any) (map[string]json.RawMessage, error) {
	members, err := checkShape(data, s)
	if err != nil {
		return nil, err
	}
	return members, json.Unmarshal(data, v)
}

// ParseRequest reads a request line strictly; its envelope is checked by
// ParseEnvelope.
func ParseRequest(data []byte) (Request, Envelope, error) {
	var req Request
	if _, err := decodeStrict(data, requestShape, &req); err != nil {
		return req, Envelope{}, fmt.Errorf("request: %w", err)
	}
	if req.Contract != Contract {
		return req, Envelope{}, fmt.Errorf("request names contract %q, not %s", req.Contract, Contract)
	}
	env, err := ParseEnvelope(req.Envelope)
	return req, env, err
}

// parseResponse reads an answer line strictly, nested result and error
// objects included, and requires exactly one of them, matching ok. Every
// shape, nested ones too, is checked on the raw bytes BEFORE the typed
// decode, so a refused answer never has a KEK decoded at all: a repeated
// or case-aliased "kek" member cannot leave an overwritten, uncleared
// allocation behind.
func parseResponse(data []byte) (Response, error) {
	var resp Response
	members, err := checkShape(data, responseShape)
	if err != nil {
		return resp, err
	}
	ok := bytes.Equal(bytes.TrimSpace(members["ok"]), []byte("true"))
	result, hasResult := members["result"]
	errObj, hasError := members["error"]
	switch {
	case ok && (!hasResult || hasError):
		return resp, errors.New("success without exactly one result")
	case !ok && (hasResult || !hasError):
		return resp, errors.New("refusal without exactly one error")
	}
	if hasResult {
		nested, err := checkShape(result, resultShape)
		if err != nil {
			return resp, fmt.Errorf("result: %w", err)
		}
		if _, ok := nested["kek"]; ok {
			if _, both := nested["envelope"]; both {
				return resp, errors.New("result carries both a KEK and an envelope")
			}
		}
	}
	if hasError {
		if _, err := checkShape(errObj, errorShape); err != nil {
			return resp, fmt.Errorf("error: %w", err)
		}
	}
	return resp, json.Unmarshal(data, &resp)
}

// MarshalWithSecret encodes v, which must hold no secret, and appends the
// member name with the base64 of secret as its value, straight into the
// returned buffer. json.Marshal would leave a copy of any secret it encodes
// in its pooled encoder buffer; the secret here only ever lands in the
// returned slice, which the caller clears after use. v must encode as a
// JSON object.
func MarshalWithSecret(v any, name string, secret []byte) ([]byte, error) {
	obj, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(obj) < 2 || obj[0] != '{' || obj[len(obj)-1] != '}' {
		return nil, errors.New("MarshalWithSecret needs a JSON object")
	}
	key, err := json.Marshal(name)
	if err != nil {
		return nil, err
	}
	n := base64.StdEncoding.EncodedLen(len(secret))
	out := make([]byte, 0, len(obj)+len(key)+n+4)
	out = append(out, obj[:len(obj)-1]...)
	if len(obj) > 2 {
		out = append(out, ',')
	}
	out = append(out, key...)
	out = append(out, ':', '"')
	start := len(out)
	out = out[:start+n]
	base64.StdEncoding.Encode(out[start:], secret)
	return append(out, '"', '}'), nil
}
