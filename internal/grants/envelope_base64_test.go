package grants

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Exact decoded-size boundaries use fixed synthetic bytes. Encoded and decoded
// limits combine with AND; an in-limit spelling still must be canonical. These
// bytes are not a certificate/revocation/signature or authorizing credentials.
func TestEnvelopeBase64Boundaries(t *testing.T) {
	cases := []struct {
		field          envelopeField
		limit, encoded int
	}{
		{certificatePayloadField, 65536, 87382},
		{revocationPayloadField, 4096, 5462},
		{signatureField, 72, 96},
		{localRequestPayloadField, 8192, 10923},
	}
	for _, test := range cases {
		exact := bytes.Repeat([]byte{0xab}, test.limit)
		encoded := base64.RawURLEncoding.EncodeToString(exact)
		if len(encoded) != test.encoded {
			t.Fatal("independent fixture boundary", len(encoded), test.encoded)
		}
		out, err := decodeEnvelopeField(encoded, test.field)
		if err != nil || !bytes.Equal(out, exact) {
			t.Fatal("exact boundary refused", test.field, len(out), err)
		}
		// Oversized legal base64 must refuse before allocating its full decode.
		over := base64.RawURLEncoding.EncodeToString(append(bytes.Clone(exact), 0xab))
		if out, e := decodeEnvelopeField(over, test.field); !errors.Is(e, errInputLimit) || out != nil {
			t.Fatal("over limit", test.field, len(out), e)
		}
		if out, e := decodeEnvelopeField(encoded, test.field); e != nil || !bytes.Equal(out, exact) {
			t.Fatal("valid after size refusal", e)
		}
	}
}

// Fixed literal goldens reject padding, whitespace, standard alphabet,
// nonzero unused bits and impossible lengths. Empty is canonical base64 for
// zero bytes here; actual JSON/DER payload interpretation must reject it later.
func TestEnvelopeBase64CanonicalSpellings(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want []byte
	}{
		{"", []byte{}}, {"AA", []byte{0}}, {"AAA", []byte{0, 0}},
		{"AAAA", []byte{0, 0, 0}}, {"_w", []byte{255}}, {"__8", []byte{255, 255}},
		{"AQIDBA", []byte{1, 2, 3, 4}},
	} {
		for _, field := range []envelopeField{certificatePayloadField, revocationPayloadField, signatureField, localRequestPayloadField} {
			got, err := decodeEnvelopeField(test.raw, field)
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("literal %q/%d: %x %v", test.raw, field, got, err)
			}
		}
	}
	for _, raw := range []string{"A", "AAAAA", "AB", "AAB", "_x", "__9", "AA=", "AA==", "AA\n", "A\rA", " AA", "AA ", "/w", "+w", "é", "AA!", "AA\x00"} {
		out, err := decodeEnvelopeField(raw, certificatePayloadField)
		if !errors.Is(err, errBadSchema) || out != nil {
			t.Fatalf("noncanonical %q: %x %v", raw, out, err)
		}
		if valid, e := decodeEnvelopeField("AQIDBA", certificatePayloadField); e != nil || !bytes.Equal(valid, []byte{1, 2, 3, 4}) {
			t.Fatal("valid after spelling refusal", valid, e)
		}
	}
}

// Near the certificate/revocation cap, alternate unused bits decode to the same
// raw bytes in a permissive decoder; this implementation must refuse them.
// This is a representation witness, not a signature/whole-envelope test.
func TestEnvelopeBase64UnusedBitsAtCap(t *testing.T) {
	for _, field := range []envelopeField{certificatePayloadField, revocationPayloadField, localRequestPayloadField} {
		limit := 65536
		if field == revocationPayloadField {
			limit = 4096
		} else if field == localRequestPayloadField {
			limit = 8192
		}
		valid := strings.Repeat("A", base64.RawURLEncoding.EncodedLen(limit))
		alias := valid[:len(valid)-1] + "B"
		permissive, err := base64.RawURLEncoding.DecodeString(alias)
		if err != nil || len(permissive) != limit {
			t.Fatal("bad independent alias witness", len(permissive), err)
		}
		if out, e := decodeEnvelopeField(alias, field); !errors.Is(e, errBadSchema) || out != nil {
			t.Fatal("unused-bit alias accepted", len(out), e)
		}
		if out, e := decodeEnvelopeField(valid, field); e != nil || len(out) != limit {
			t.Fatal("canonical cap neighbor refused", len(out), e)
		}
	}
}

// Unsupported selectors refuse without decoding bytes or returning a value;
// a fixed supported selector remains available immediately afterwards.
func TestEnvelopeBase64UnknownField(t *testing.T) {
	for _, field := range []envelopeField{0, localRequestPayloadField + 1, 255} {
		if out, err := decodeEnvelopeField("AA", field); !errors.Is(err, errBadSchema) || out != nil {
			t.Fatal("unknown selector", out, err)
		}
	}
	if out, err := decodeEnvelopeField("AA", signatureField); err != nil || !bytes.Equal(out, []byte{0}) {
		t.Fatal("known selector", out, err)
	}
}
