package signerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// The raw envelope contract of one stdout line, judged by member PRESENCE
// and JSON type before anything is decoded into Response. A typed decode
// alone is lossy — `OK bool` cannot tell an absent or null ok from false,
// `Error *Error` cannot tell an absent error from null, and a missing
// error.message decodes to "" — so it cannot be the gate; it runs only
// after decodeEnvelope has admitted the line (rev5 review F1).
//
// Members of the hello line: contract, ok, result, error. Members of a
// response line: id, ok, result, error. Any other member is a contract
// break. ok is required and must be the literal true or false; id is
// required on a response (a string or number — the id the request
// carried) and must not appear on the hello; contract must not appear on
// a response (its value on the hello is judged by Start, which reports an
// absent or foreign one as ErrContract). result, when present, must be a
// JSON object: a null result is refused, not read as absent. error, when
// present, must be a JSON object with exactly code, message and hint as
// strings (each present and non-null) and, optionally, os_status as a
// number; a null error is refused, not read as absent. Whether the
// admitted members make a contract-1 envelope (result xor error against
// ok) is checkEnvelope's judgement, after this one.
var (
	helloMembers    = map[string]bool{"contract": true, "ok": true, "result": true, "error": true}
	responseMembers = map[string]bool{"id": true, "ok": true, "result": true, "error": true}
	errorMembers    = map[string]bool{"code": true, "message": true, "hint": true, "os_status": true}
)

// decodeEnvelope is the one gate every stdout line passes — the hello in
// Start and each reply in Call — before the typed Response exists. It
// reads the line through DecodeObject (one object, source order, no
// repeated member name — verbatim or escape-spelt — nothing after it),
// enforces the member contract above (presence, non-null, JSON type, no
// unknown members) and only then unmarshals the typed Response, which is
// therefore faithful: Response.Error is nil exactly when the error member
// is absent, and a present error carries its code, message and hint
// verbatim.
func decodeEnvelope(line []byte, hello bool) (Response, error) {
	allowed, what := responseMembers, "response"
	if hello {
		allowed, what = helloMembers, "hello"
	}
	raw, err := DecodeObject(line)
	if err != nil {
		return Response{}, fmt.Errorf("%s line is not one JSON object: %v", what, err)
	}
	for _, name := range raw.Names() {
		if !allowed[name] {
			return Response{}, fmt.Errorf("%s carries member %q the contract does not define", what, name)
		}
	}
	ok, present := raw.Get("ok")
	switch {
	case !present:
		return Response{}, fmt.Errorf("%s has no ok member", what)
	case !isLiteral(ok, "true") && !isLiteral(ok, "false"):
		return Response{}, fmt.Errorf("%s ok is %s, not a JSON boolean", what, trim(ok))
	}
	if !hello {
		id, present := raw.Get("id")
		switch {
		case !present:
			return Response{}, errors.New("response has no id member")
		case isLiteral(id, "null"):
			return Response{}, errors.New("response id is null")
		case !isScalarID(id):
			return Response{}, fmt.Errorf("response id %s is not a JSON string or number", trim(id))
		}
	}
	if result, present := raw.Get("result"); present && !isObject(result) {
		return Response{}, fmt.Errorf("%s result is %s, not a JSON object", what, trim(result))
	}
	if errMember, present := raw.Get("error"); present {
		if err := checkErrorMember(errMember); err != nil {
			return Response{}, fmt.Errorf("%s error member: %v", what, err)
		}
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("%s line does not decode: %v", what, err)
	}
	return resp, nil
}

// checkErrorMember judges the error object by presence and type: code,
// message and hint are required strings, os_status is an optional number,
// nothing else is allowed, no member is repeated, and the member itself
// must be an object (null is not "no error").
func checkErrorMember(member json.RawMessage) error {
	if isLiteral(member, "null") {
		return errors.New("is null")
	}
	if !isObject(member) {
		return fmt.Errorf("is %s, not a JSON object", trim(member))
	}
	fields, err := DecodeObject(member)
	if err != nil {
		return fmt.Errorf("does not decode: %v", err)
	}
	for _, name := range fields.Names() {
		if !errorMembers[name] {
			return fmt.Errorf("carries member %q the contract does not define", name)
		}
	}
	for _, name := range []string{"code", "message", "hint"} {
		value, present := fields.Get(name)
		switch {
		case !present:
			return fmt.Errorf("has no %s member", name)
		case isLiteral(value, "null"):
			return fmt.Errorf("%s is null", name)
		case !isString(value):
			return fmt.Errorf("%s is %s, not a JSON string", name, trim(value))
		}
	}
	if status, present := fields.Get("os_status"); present && !isNumber(status) {
		return fmt.Errorf("os_status is %s, not a JSON number", trim(status))
	}
	return nil
}

func trim(raw json.RawMessage) []byte { return bytes.TrimSpace(raw) }

func isLiteral(raw json.RawMessage, literal string) bool {
	return bytes.Equal(trim(raw), []byte(literal))
}

func isObject(raw json.RawMessage) bool {
	t := trim(raw)
	return len(t) > 0 && t[0] == '{'
}

func isString(raw json.RawMessage) bool {
	t := trim(raw)
	return len(t) > 0 && t[0] == '"'
}

func isNumber(raw json.RawMessage) bool {
	t := trim(raw)
	return len(t) > 0 && (t[0] == '-' || (t[0] >= '0' && t[0] <= '9'))
}

func isScalarID(raw json.RawMessage) bool {
	return isString(raw) || isNumber(raw)
}
