package signerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Member is one name/value pair of a wire object, the value still raw.
type Member struct {
	Name  string
	Value json.RawMessage
}

// Object is one JSON object read token by token in source order: every
// contract-bearing object of the wire — a request line on the server, the
// envelope, its error member and every result on the client — is read
// through DecodeObject before anything typed exists, because a Go map or
// struct decode collapses a repeated member name (identical or
// escape-equivalent, "contract" and "co\u006etract") to one value and a
// gate that runs after that collapse never sees the contradiction
// (review rev6 F1). An Object keeps members in source order and never
// holds two of one name; the members below the top level are judged by
// CheckDocument, which DecodeObject runs first.
type Object []Member

// ErrDuplicateMember marks the refusal of a second member of one decoded
// name; the wrapping error names the member.
var ErrDuplicateMember = errors.New("duplicate member")

// ErrMultipleDocuments marks a second JSON document, token or garbage
// after the first document.
var ErrMultipleDocuments = errors.New("unexpected data after the JSON document")

// CheckDocument is the ONE strict-JSON pass every inbound document takes
// before any typed decode — a request line on the server (DecodeObject),
// the hello and every response line on the client (DecodeObject through
// decodeEnvelope), the persisted record tag and the --meta-json /
// --json-value inputs (DecodeSingleJSON). It walks the whole document
// token by token, at every depth, through objects nested in objects and
// objects nested in arrays, and refuses:
//
//   - two members of one DECODED name in any one object (the decoder
//     resolves escapes before the comparison, so an escape-spelt repeat,
//     "public" and "publ\u0069c", is refused like a verbatim one);
//   - anything that is not exactly one document: empty input, a second
//     document, a trailing token or garbage after the first (surrounding
//     whitespace is not refused).
//
// The same name in two sibling objects or at two depths is not a repeat.
// A duplicate is reported as ErrDuplicateMember naming the member and,
// below the top level, its path (`duplicate member "public" at format`,
// `... at operations[0]`). It exists because encoding/json — a map, a
// struct with DisallowUnknownFields, json.RawMessage — collapses a repeat
// to the LAST value before any gate can see the first, and a gate that
// judged only the object it was handed left every nested object to that
// collapse (review rev6 F1 at the top level, rev8 F1 repeat-of below it).
func CheckDocument(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty input, not a JSON document")
		}
		return err
	}
	if err := walkValue(dec, tok, ""); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrMultipleDocuments
		}
		return err
	}
	return nil
}

// walkValue consumes the value whose first token is tok, descending into
// every object and array; path names the container being read ("" for
// the document, "format", "operations[0]").
func walkValue(dec *json.Decoder, tok json.Token, path string) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			nameTok, err := dec.Token()
			if err != nil {
				return unexpectedEOF(err)
			}
			name, ok := nameTok.(string)
			if !ok {
				return fmt.Errorf("member name %s is not a string", describeToken(nameTok))
			}
			if seen[name] {
				if path == "" {
					return fmt.Errorf("%w %q", ErrDuplicateMember, name)
				}
				return fmt.Errorf("%w %q at %s", ErrDuplicateMember, name, path)
			}
			seen[name] = true
			valueTok, err := dec.Token()
			if err == nil {
				child := name
				if path != "" {
					child = path + "." + name
				}
				err = walkValue(dec, valueTok, child)
			}
			if err != nil {
				if path == "" && !errors.Is(err, ErrDuplicateMember) {
					return fmt.Errorf("member %q: %w", name, unexpectedEOF(err))
				}
				return unexpectedEOF(err)
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			elemTok, err := dec.Token()
			if err != nil {
				return unexpectedEOF(err)
			}
			if err := walkValue(dec, elemTok, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected %q", delim.String())
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return unexpectedEOF(err)
	}
	return nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// DecodeObject reads data as exactly one JSON object: not a scalar, array
// or null, nothing after it, and — through CheckDocument, which runs
// first over the whole document — no two members whose DECODED names are
// equal at any depth. Member values are kept raw and syntactically valid
// JSON; a nested object is read through DecodeObject again by whoever
// judges it, and it has already passed the duplicate gate.
func DecodeObject(data []byte) (Object, error) {
	if err := CheckDocument(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("%s is not a JSON object", describeToken(tok))
	}
	var obj Object
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("member name %s is not a string", describeToken(tok))
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		obj = append(obj, Member{Name: name, Value: value})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	return obj, nil
}

// Get returns the value of the member called name and whether it is
// present; the value is never nil for a present member (a JSON null is
// the literal null).
func (o Object) Get(name string) (json.RawMessage, bool) {
	for _, m := range o {
		if m.Name == name {
			return m.Value, true
		}
	}
	return nil, false
}

// Has reports whether the member is present, null or not.
func (o Object) Has(name string) bool {
	_, ok := o.Get(name)
	return ok
}

// Names lists the member names in source order.
func (o Object) Names() []string {
	names := make([]string, len(o))
	for i, m := range o {
		names[i] = m.Name
	}
	return names
}

func describeToken(tok json.Token) string {
	switch v := tok.(type) {
	case json.Delim:
		return fmt.Sprintf("%q", v.String())
	case nil:
		return "null"
	case json.Number:
		return "number " + v.String()
	case string:
		return fmt.Sprintf("string %q", v)
	case bool:
		return fmt.Sprintf("%v", v)
	}
	return fmt.Sprintf("%v", tok)
}
