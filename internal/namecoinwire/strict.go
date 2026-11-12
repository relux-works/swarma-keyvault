package namecoinwire

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodeClosed checks exact member spelling and presence before typed decoding.
// encoding/json alone permits case aliases and replaces unpaired surrogates.
func decodeClosed(raw []byte, dst any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || !pairedEscapes(raw) {
		return ErrInvalidRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	if err := scanValue(d, 0, &nodes); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidRequest
	}
	if err := closedType(raw, reflect.TypeOf(dst)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalidRequest
	}
	return nil
}

func scanValue(d *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 16 || *nodes > 65536 {
		return ErrInvalidRequest
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return ErrInvalidRequest
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok || seen[key] {
					return ErrInvalidRequest
				}
				seen[key] = true
				if err := scanValue(d, depth+1, nodes); err != nil {
					return err
				}
			}
			if t, err := d.Token(); err != nil || t != json.Delim('}') {
				return ErrInvalidRequest
			}
		case '[':
			for d.More() {
				if err := scanValue(d, depth+1, nodes); err != nil {
					return err
				}
			}
			if t, err := d.Token(); err != nil || t != json.Delim(']') {
				return ErrInvalidRequest
			}
		default:
			return ErrInvalidRequest
		}
	case json.Number:
		if s := string(v); s == "-0" || strings.ContainsAny(s, ".eE+") {
			return ErrInvalidRequest
		}
	case string, bool:
	default:
		return ErrInvalidRequest
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

func closedType(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType {
		// Operation-specific raw objects are checked against their concrete
		// discriminated type before the enclosing snapshot can be returned.
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return ErrInvalidRequest
		}
		allowed := make(map[string]bool, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "" || tag[0] == "-" {
				return ErrInvalidRequest
			}
			allowed[tag[0]] = true
			value, exists := object[tag[0]]
			optional := len(tag) == 2 && tag[1] == "omitempty"
			if !exists {
				if optional {
					continue
				}
				return ErrInvalidRequest
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || closedType(value, f.Type) != nil {
				return ErrInvalidRequest
			}
		}
		for k := range object {
			if !allowed[k] {
				return ErrInvalidRequest
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return ErrInvalidRequest
		}
		for _, value := range values {
			if closedType(value, t.Elem()) != nil {
				return ErrInvalidRequest
			}
		}
	}
	return nil
}

// pairedEscapes validates UTF-16 escape pairs without changing the admitted
// spelling or exact once-decoded manifest bytes. JSON syntax is checked above.
func pairedEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if len(raw)-i < 5 {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		i += 4
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if len(raw)-i < 7 || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}
