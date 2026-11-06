package reviewedsession

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// strictObject is a bounded syntax layer, not profile or admission validation.
// Token parsing detects duplicate keys even when their JSON spellings differ.
// All described protocol data strings are ASCII. Rejecting non-ASCII after
// decoding also rejects Go's replacement of unpaired JSON surrogate escapes.
func strictObject(raw []byte, limit int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, errSchema
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	v, err := strictValue(d, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errSchema
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errSchema
	}
	return m, nil
}

func ascii(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func strictValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 16 || *nodes > 16384 {
		return nil, errSchema
	}
	t, err := d.Token()
	if err != nil {
		return nil, errSchema
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := make(map[string]any)
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok || !ascii(key) {
					return nil, errSchema
				}
				if _, exists := m[key]; exists {
					return nil, errSchema
				}
				item, err := strictValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				m[key] = item
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errSchema
			}
			return m, nil
		case '[':
			a := make([]any, 0)
			for d.More() {
				item, err := strictValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				a = append(a, item)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errSchema
			}
			return a, nil
		}
	case string:
		if ascii(v) {
			return v, nil
		}
	case json.Number:
		s := string(v)
		if s == "-0" || strings.ContainsAny(s, ".eE+") {
			return nil, errSchema
		}
		// JSON already rules out leading zeroes. Keep the spelling and check
		// the schema-specific range at the typed extraction boundary.
		return v, nil
	case bool:
		return v, nil
	case nil:
		return nil, nil
	}
	return nil, errSchema
}

func closed(m map[string]any, names ...string) error {
	if len(m) != len(names) {
		return errSchema
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return errSchema
		}
	}
	return nil
}

func text(m map[string]any, name string) (string, error) {
	v, ok := m[name].(string)
	if !ok || v == "" {
		return "", errSchema
	}
	return v, nil
}

func positive(m map[string]any, name string) (uint64, error) {
	n, ok := m[name].(json.Number)
	if !ok {
		return 0, errSchema
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil || u == 0 {
		return 0, errSchema
	}
	return u, nil
}

func digestHex(s string) ([32]byte, error) {
	var result [32]byte
	if len(s) != 64 {
		return result, errSchema
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return result, errSchema
		}
	}
	_, err := hex.Decode(result[:], []byte(s))
	return result, err
}

func byteString(s string, max int) ([]byte, error) {
	if len(s) == 0 || len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, errSchema
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errSchema
	}
	return b, nil
}
