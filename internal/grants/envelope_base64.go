package grants

import "encoding/base64"

type envelopeField uint8

const (
	certificatePayloadField envelopeField = iota + 1
	revocationPayloadField
	signatureField
)

// decodeEnvelopeField checks only a fixed envelope field's bounded canonical
// unpadded base64url representation. Both limits precede decode allocation;
// the caller already holds value, so this bounds no earlier ingress allocation.
// Empty encodes zero bytes here; JSON/DER interpretation is a separate required
// step. No payload schema, signature validity, issuer or authority is implied.
func decodeEnvelopeField(value string, field envelopeField) ([]byte, error) {
	encodedMaximum, decodedMaximum := 0, 0
	switch field {
	case certificatePayloadField:
		encodedMaximum, decodedMaximum = 87382, 65536
	case revocationPayloadField:
		encodedMaximum, decodedMaximum = 5462, 4096
	case signatureField:
		encodedMaximum, decodedMaximum = 96, 72
	default:
		return nil, errBadSchema
	}
	// The encoded bound is checked first, making the following multiplication
	// bounded too. Impossible lengths/alphabet and unused bits refuse below.
	if len(value) > encodedMaximum || len(value)*6/8 > decodedMaximum {
		return nil, errInputLimit
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errBadSchema
	}
	if len(decoded) > decodedMaximum {
		return nil, errInputLimit
	}
	return decoded, nil
}
