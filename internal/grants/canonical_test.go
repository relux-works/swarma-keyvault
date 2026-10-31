package grants

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

//go:embed testdata/lexical_vectors.json
var lexicalVectors []byte

//go:embed testdata/certificate-exact-65536.json
var certificateAtByteLimit []byte

//go:embed testdata/certificate-exact-65537.json
var certificateOverByteLimit []byte

// These fixed independently agreed bytes check encoding only, including every
// original lexical refusal. Canonical unknown/missing/schema-invalid objects
// can pass this phase; this is not a typed-schema, issuer or authority test.
func TestCanonicalLexicalVectors(t *testing.T) {
	var fixtures []struct {
		Name         string `json:"name"`
		Profile      string `json:"profile"`
		RawBase64    string `json:"raw_base64"`
		LexicalError string `json:"lexical_error"`
	}
	if err := json.Unmarshal(lexicalVectors, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 24 {
		t.Fatalf("fixtures: %d, want24", len(fixtures))
	}
	profiles := map[string]wireProfile{"request": requestWire, "certificate": certificateWire, "result": resultWire, "revocation": revocationWire}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			profile, ok := profiles[fixture.Profile]
			if !ok {
				t.Fatal("bad fixture profile")
			}
			raw, err := base64.StdEncoding.DecodeString(fixture.RawBase64)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(raw)
			node, err := parseCanonical(raw, profile)
			if fixture.LexicalError == "bad-encoding" {
				if !errors.Is(err, errBadEncoding) || node != nil {
					t.Fatalf("got node=%v err=%v, want encoding refusal", node, err)
				}
			} else if err != nil || node == nil {
				t.Fatalf("valid lexical control: node=%v err=%v", node, err)
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("received input changed")
			}
		})
	}
}

// Boundary pairs isolate each reachable lexical budget with other budgets held.
// The total-member ceiling is redundant under the token ceiling; its isolated
// counter check below is not a claim that a 2048-member document can fit4096tokens.
func TestCanonicalLexicalBoundaries(t *testing.T) {
	object := func(count int) string {
		var fields []string
		for i := 0; i < count; i++ {
			fields = append(fields, fmt.Sprintf("\"a%02d\":true", i))
		}
		return "{" + strings.Join(fields, ",") + "}"
	}
	depth := func(n int) string { return strings.Repeat("[", n) + "true" + strings.Repeat("]", n) }
	array := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]" }
	sizes := []string{}
	for i := 0; i < 7; i++ {
		sizes = append(sizes, `"`+strings.Repeat("x", 1024)+`"`)
	}
	byteLimit := "[" + strings.Join(append(sizes, `"`+strings.Repeat("x", 999)+`"`), ",") + "]"
	byteOver := "[" + strings.Join(append(sizes, `"`+strings.Repeat("x", 1000)+`"`), ",") + "]"
	if len(byteLimit) != 8192 || len(byteOver) != 8193 {
		t.Fatal("bad byte boundary fixture")
	}
	tests := []struct {
		name, raw string
		profile   wireProfile
		want      error
	}{
		{"depth12", depth(12), requestWire, nil}, {"depth13", depth(13), requestWire, errInputLimit},
		{"members16", object(16), requestWire, nil}, {"members17", object(17), requestWire, errInputLimit},
		{"tokens4096", array(4094), requestWire, nil}, {"tokens4097", array(4095), requestWire, errInputLimit},
		{"string1024", `{"a":"` + strings.Repeat("x", 1024) + `"}`, requestWire, nil},
		{"string1025", `{"a":"` + strings.Repeat("x", 1025) + `"}`, requestWire, errInputLimit},
		{"bytes8192", byteLimit, requestWire, nil}, {"bytes8193", byteOver, requestWire, errInputLimit},
		{"certificate65536", string(certificateAtByteLimit), certificateWire, nil},
		{"certificate65537", string(certificateOverByteLimit), certificateWire, errInputLimit},
		{"envelopePayloadException", `{"payload":"` + strings.Repeat("A", 1025) + `"}`, certificateEnvelopeWire, nil},
		{"ordinaryEnvelopeString", `{"other":"` + strings.Repeat("A", 1025) + `"}`, certificateEnvelopeWire, errInputLimit},
		{"nestedPayloadNotException", `{"a":{"payload":"` + strings.Repeat("A", 1025) + `"}}`, certificateEnvelopeWire, errInputLimit},
		{"signature96", `{"signature":"` + strings.Repeat("A", 96) + `"}`, certificateEnvelopeWire, nil},
		{"signature97", `{"signature":"` + strings.Repeat("A", 97) + `"}`, certificateEnvelopeWire, errInputLimit},
		{"revocationEnvelope5462", `{"payload":"` + strings.Repeat("A", 5462) + `"}`, revocationEnvelopeWire, nil},
		{"revocationEnvelope5463", `{"payload":"` + strings.Repeat("A", 5463) + `"}`, revocationEnvelopeWire, errInputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, err := parseCanonical([]byte(test.raw), test.profile)
			if !errors.Is(err, test.want) || (err != nil && node != nil) {
				t.Fatalf("got node=%v err=%v, want%v", node, err, test.want)
			}
		})
	}
}

// Aliases and malformed forms refuse; nearby integer/bool/escape spellings pass
// only the lexical grammar. Unsupported profiles return no decoded value.
func TestCanonicalLexicalNeighbors(t *testing.T) {
	tests := []struct {
		raw   string
		valid bool
	}{
		{`{"a":0,"b":true,"c":false}`, true}, {`{"a":-1}`, false}, {`{"a":01}`, false},
		{`{"a":1e0}`, false}, {`{"a":1.0}`, false}, {`{"a":null}`, false},
		{`{"a":"/"}`, true}, {`{"a":"\/"}`, false}, {`{"a":"\u0061"}`, false},
		{`{"a":"é"}`, false}, {`{"a":"\n"}`, false}, {`{"b":true,"a":false}`, false},
		{`{"a":true,"a":true}`, false}, {`{"a":true,}`, false}, {`[true,]`, false},
		{`{"a":true} `, false}, {`{"a":true}null`, false}, {``, false}, {`"unterminated`, false},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			node, err := parseCanonical([]byte(test.raw), requestWire)
			if test.valid {
				if err != nil || node == nil {
					t.Fatalf("positive: %v", err)
				}
			} else if !errors.Is(err, errBadEncoding) || node != nil {
				t.Fatalf("forbidden input accepted: node=%v err=%v", node, err)
			}
		})
	}
	if node, err := parseCanonical([]byte(`{}`), wireProfile(255)); !errors.Is(err, errBadEncoding) || node != nil {
		t.Fatal("unsupported profile accepted")
	}
}

// The member counter accepts its last slot and refuses the next without
// changing the accepted count. Other budgets are not exercised by this unit.
func TestCanonicalMemberCounter(t *testing.T) {
	parser := canonicalParser{members: 2047}
	if err := parser.takeMember(); err != nil || parser.members != 2048 {
		t.Fatal("last member slot refused")
	}
	if err := parser.takeMember(); !errors.Is(err, errInputLimit) || parser.members != 2048 {
		t.Fatal("member overflow was not refused atomically")
	}
}
