package grants

// envelopeProjection retains an untrusted signed-envelope representation.
// DER parsing proves neither a valid signature nor a trusted issuer. The
// payload's complete typed schema, enrollment, lifecycle and authority must
// be checked separately before any import or operation can be authorized.
type envelopeProjection struct {
	raw       []byte
	payload   []byte
	signature []byte
	domain    digestDomain
}

// parseEnvelopeProjection validates the closed outer shape, fixed version,
// bounded canonical payload bytes and payload type, and strict base64/low-S
// DER representations. It does not validate the complete certificate or
// revocation payload schema, verify ECDSA, select/enroll a key, read a clock,
// or change state. All returned byte slices are owned and exact; no invalid
// received representation is repaired or reserialized into acceptance.
func parseEnvelopeProjection(raw []byte, profile wireProfile) (*envelopeProjection, error) {
	var envelopeType, payloadType string
	var payloadProfile wireProfile
	var payloadField envelopeField
	var domain digestDomain
	switch profile {
	case certificateEnvelopeWire:
		envelopeType, payloadType = "grants-signed-certificate-1", "grants-certificate-1"
		payloadProfile, payloadField, domain = certificateWire, certificatePayloadField, certificateDomain
	case revocationEnvelopeWire:
		envelopeType, payloadType = "grants-signed-revocation-1", "grants-revocation-1"
		payloadProfile, payloadField, domain = revocationWire, revocationPayloadField, revocationDomain
	default:
		return nil, errBadSchema
	}

	node, err := parseCanonical(raw, profile)
	if err != nil {
		return nil, err
	}
	fields, err := closedObject(node, "type", "payload", "signature")
	if err != nil {
		return nil, err
	}
	for _, field := range fields {
		if field == nil || field.kind != stringValue {
			return nil, errBadSchema
		}
	}
	if fields["type"].text != envelopeType {
		return nil, errBadSchema
	}
	payload, err := decodeEnvelopeField(fields["payload"].text, payloadField)
	if err != nil {
		return nil, err
	}
	signature, err := decodeEnvelopeField(fields["signature"].text, signatureField)
	if err != nil {
		return nil, err
	}
	payloadNode, err := parseCanonical(payload, payloadProfile)
	if err != nil {
		return nil, err
	}
	kind, err := memberText(payloadNode, "type")
	if err != nil || kind != payloadType {
		return nil, errBadSchema
	}
	if _, _, err := parseLowSSignatureDER(signature); err != nil {
		return nil, err
	}
	return &envelopeProjection{
		raw:       append([]byte(nil), raw...),
		payload:   payload,
		signature: signature,
		domain:    domain,
	}, nil
}
