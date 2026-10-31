package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// This literal is a minimal DER representation, never a generated signature
// or a cryptographic positive for any payload or issuer.
var envelopeTestDER = []byte{0x30, 6, 2, 1, 1, 2, 1, 1}

func envelopeTestBytes(payload, signature []byte, kind string) []byte {
	return []byte(`{"payload":"` + base64.RawURLEncoding.EncodeToString(payload) + `","signature":"` + base64.RawURLEncoding.EncodeToString(signature) + `","type":"` + kind + `"}`)
}

func envelopeTestKinds() []struct {
	profile wireProfile
	kind    string
	payload string
	domain  digestDomain
} {
	return []struct {
		profile wireProfile
		kind    string
		payload string
		domain  digestDomain
	}{
		{certificateEnvelopeWire, "grants-signed-certificate-1", "grants-certificate-1", certificateDomain},
		{revocationEnvelopeWire, "grants-signed-revocation-1", "grants-revocation-1", revocationDomain},
	}
}

// Exact independent unsigned payload fixtures survive envelope decoding.
// The DER positive proves representation only, with no authentication claim.
func TestEnvelopeProjectionOriginalPayloads(t *testing.T) {
	var fixtures []struct {
		ID        string `json:"id"`
		RawBase64 string `json:"raw_base64"`
		Bytes     int    `json:"byte_count"`
		SHA256    string `json:"sha256"`
	}
	data, err := os.ReadFile("testdata/envelope_payload_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixtures); err != nil || len(fixtures) != 2 {
		t.Fatal("fixture set", len(fixtures), err)
	}
	for i, fixture := range fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			payload, err := base64.StdEncoding.DecodeString(fixture.RawBase64)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(payload)
			if len(payload) != fixture.Bytes || hex.EncodeToString(sum[:]) != fixture.SHA256 {
				t.Fatal("unsigned payload fixture changed")
			}
			kind := envelopeTestKinds()[i]
			raw := envelopeTestBytes(payload, envelopeTestDER, kind.kind)
			got, err := parseEnvelopeProjection(raw, kind.profile)
			if err != nil || got == nil {
				t.Fatal("representation refused", err)
			}
			if got.domain != kind.domain || !bytes.Equal(got.raw, raw) || !bytes.Equal(got.payload, payload) || !bytes.Equal(got.signature, envelopeTestDER) {
				t.Fatal("wrong kind or changed exact bytes")
			}
		})
	}
}

// Every closed outer field is required and string-typed for both versions;
// extra fields never select algorithms or turn an envelope into authority.
func TestEnvelopeProjectionClosedFields(t *testing.T) {
	for _, kind := range envelopeTestKinds() {
		payload := []byte(`{"type":"` + kind.payload + `"}`)
		valid := map[string]any{"payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawURLEncoding.EncodeToString(envelopeTestDER), "type": kind.kind}
		for _, field := range []string{"payload", "signature", "type"} {
			for _, mode := range []string{"missing", "boolean", "integer", "array", "object"} {
				t.Run(kind.kind+"/"+field+"/"+mode, func(t *testing.T) {
					object := make(map[string]any)
					for name, value := range valid {
						object[name] = value
					}
					switch mode {
					case "missing":
						delete(object, field)
					case "boolean":
						object[field] = true
					case "integer":
						object[field] = 1
					case "array":
						object[field] = []any{}
					case "object":
						object[field] = map[string]any{}
					}
					raw, err := json.Marshal(object)
					if err != nil {
						t.Fatal(err)
					}
					got, err := parseEnvelopeProjection(raw, kind.profile)
					if !errors.Is(err, errBadSchema) || got != nil {
						t.Fatal("wrong-type/missing field did not refuse schema without output", got, err)
					}
					if got, err := parseEnvelopeProjection(envelopeTestBytes(payload, envelopeTestDER, kind.kind), kind.profile); err != nil || got == nil {
						t.Fatal("valid representation neighbor refused", err)
					}
				})
			}
		}
		valid["algorithm"] = "none"
		raw, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := parseEnvelopeProjection(raw, kind.profile); !errors.Is(err, errBadSchema) || got != nil {
			t.Fatal("extra algorithm accepted", got, err)
		}
	}
}

// Envelope version, caller profile and decoded payload type must agree.
// A matching type alone deliberately does not validate a complete payload.
func TestEnvelopeProjectionKindIsolation(t *testing.T) {
	for _, kind := range envelopeTestKinds() {
		payload := []byte(`{"type":"` + kind.payload + `"}`)
		raw := envelopeTestBytes(payload, envelopeTestDER, kind.kind)
		for _, profile := range []wireProfile{0, certificateWire, requestWire, resultWire, revocationWire, 255} {
			if got, err := parseEnvelopeProjection(raw, profile); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("unsupported profile accepted", profile, got, err)
			}
		}
		for _, bad := range [][]byte{
			envelopeTestBytes(payload, envelopeTestDER, "grants-signed-certificate-2"),
			envelopeTestBytes([]byte(`{"type":"grants-request-1"}`), envelopeTestDER, kind.kind),
			envelopeTestBytes([]byte(`{}`), envelopeTestDER, kind.kind),
			envelopeTestBytes([]byte(`[]`), envelopeTestDER, kind.kind),
		} {
			if got, err := parseEnvelopeProjection(bad, kind.profile); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("wrong envelope/payload type accepted", got, err)
			}
		}
		for _, other := range envelopeTestKinds() {
			if other.profile == kind.profile {
				continue
			}
			if got, err := parseEnvelopeProjection(raw, other.profile); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("cross-version envelope accepted", got, err)
			}
			wrongPayload := envelopeTestBytes([]byte(`{"type":"`+other.payload+`"}`), envelopeTestDER, kind.kind)
			if got, err := parseEnvelopeProjection(wrongPayload, kind.profile); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("cross-version payload accepted", got, err)
			}
		}
		if got, err := parseEnvelopeProjection(raw, kind.profile); err != nil || got == nil {
			t.Fatal("matching representation refused", err)
		}
	}
}

// Inner encoding and DER errors remain distinct from closed schema refusals;
// all failures return nil and retain a nearby representational positive.
func TestEnvelopeProjectionRepresentations(t *testing.T) {
	// S = floor(P-256 order/2)+1 is in range but forbidden by the fixed low-S policy.
	highS, err := hex.DecodeString("302502010102207fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range envelopeTestKinds() {
		payload := []byte(`{"type":"` + kind.payload + `"}`)
		valid := envelopeTestBytes(payload, envelopeTestDER, kind.kind)
		cases := []struct {
			raw  []byte
			want error
		}{
			{append(append([]byte(nil), valid...), '\n'), errBadEncoding},
			{envelopeTestBytes(append(append([]byte(nil), payload...), '\n'), envelopeTestDER, kind.kind), errBadEncoding},
			{envelopeTestBytes([]byte(`{"type":null}`), envelopeTestDER, kind.kind), errBadEncoding},
			{envelopeTestBytes([]byte(`{"type":"`+kind.payload+`","type":"`+kind.payload+`"}`), envelopeTestDER, kind.kind), errBadEncoding},
			{envelopeTestBytes(nil, envelopeTestDER, kind.kind), errBadEncoding},
			{envelopeTestBytes(payload, nil, kind.kind), errSignatureInvalid},
			{envelopeTestBytes(payload, highS, kind.kind), errSignatureInvalid},
			{envelopeTestBytes(payload, []byte{0x30, 6, 2, 1, 0, 2, 1, 1}, kind.kind), errSignatureInvalid},
			{envelopeTestBytes(payload, append(append([]byte(nil), envelopeTestDER...), 0), kind.kind), errSignatureInvalid},
		}
		for _, test := range cases {
			got, err := parseEnvelopeProjection(test.raw, kind.profile)
			if !errors.Is(err, test.want) || got != nil {
				t.Fatal("wrong representation refusal/partial output", got, err, test.want)
			}
			if got, err := parseEnvelopeProjection(valid, kind.profile); err != nil || got == nil {
				t.Fatal("positive after refusal", err)
			}
		}
		for _, field := range []string{"payload", "signature"} {
			var object map[string]string
			if err := json.Unmarshal(valid, &object); err != nil {
				t.Fatal(err)
			}
			object[field] += "="
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := parseEnvelopeProjection(raw, kind.profile); !errors.Is(err, errBadSchema) || got != nil {
				t.Fatal("padded base64 accepted", got, err)
			}
		}
	}
}

// The outer and decoded field limits apply before a usable projection exists.
// Exact certificate byte controls exercise lexical bounds, not full schema.
func TestEnvelopeProjectionLimits(t *testing.T) {
	for _, test := range []struct {
		profile wireProfile
		maximum int
	}{{certificateEnvelopeWire, 98304}, {revocationEnvelopeWire, 8192}} {
		if got, err := parseEnvelopeProjection([]byte(strings.Repeat(" ", test.maximum+1)), test.profile); !errors.Is(err, errInputLimit) || got != nil {
			t.Fatal("outer max+1", got, err)
		}
	}
	for _, test := range []struct {
		name string
		want error
	}{{"certificate-exact-65536.json", nil}, {"certificate-exact-65537.json", errInputLimit}} {
		payload, err := os.ReadFile("testdata/" + test.name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseEnvelopeProjection(envelopeTestBytes(payload, envelopeTestDER, "grants-signed-certificate-1"), certificateEnvelopeWire)
		if !errors.Is(err, test.want) || (got == nil) != (test.want != nil) {
			t.Fatal("decoded certificate boundary", test.name, got, err)
		}
	}
	for _, kind := range envelopeTestKinds() {
		payload := []byte(`{"type":"` + kind.payload + `"}`)
		if got, err := parseEnvelopeProjection(envelopeTestBytes(payload, make([]byte, 73), kind.kind), kind.profile); !errors.Is(err, errInputLimit) || got != nil {
			t.Fatal("decoded DER max+1", got, err)
		}
		if got, err := parseEnvelopeProjection(envelopeTestBytes(payload, envelopeTestDER, kind.kind), kind.profile); err != nil || got == nil {
			t.Fatal("bounded positive after limit refusal", err)
		}
	}
}

// A successful projection owns all retained byte slices; mutating the caller's
// envelope cannot alter payload/signature/raw and no byte repair is performed.
func TestEnvelopeProjectionOwnsBytes(t *testing.T) {
	for _, kind := range envelopeTestKinds() {
		payload := []byte(`{"type":"` + kind.payload + `"}`)
		raw := envelopeTestBytes(payload, envelopeTestDER, kind.kind)
		original := append([]byte(nil), raw...)
		got, err := parseEnvelopeProjection(raw, kind.profile)
		if err != nil || got == nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, original) {
			t.Fatal("parser modified caller bytes")
		}
		for i := range raw {
			raw[i] = 'x'
		}
		if !bytes.Equal(got.raw, original) || !bytes.Equal(got.payload, payload) || !bytes.Equal(got.signature, envelopeTestDER) {
			t.Fatal("caller mutation altered retained projection")
		}
	}
}
