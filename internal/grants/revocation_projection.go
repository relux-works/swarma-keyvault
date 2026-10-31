package grants

import "time"

// A revocationProjection is untrusted public data. It is neither a verified
// signature nor a lifecycle command; effective time, retained target authority,
// immutable ID binding and atomic revocation remain the verifier's obligations.
type revocationProjection struct {
	raw                                     []byte
	revocationID, certificateID, reasonCode string
	issuer                                  *issuerProjection
	effectiveAt                             time.Time
}

func parseRevocationProjection(raw []byte) (*revocationProjection, error) {
	node, err := parseCanonical(raw, revocationWire)
	if err != nil {
		return nil, err
	}
	fields, err := closedObject(node, "type", "revocation_id", "certificate_id", "issuer", "effective_at", "reason_code")
	if err != nil {
		return nil, err
	}
	for name, field := range fields {
		if name != "issuer" && (field == nil || field.kind != stringValue) {
			return nil, errBadSchema
		}
	}
	if fields["type"].text != "grants-revocation-1" || !oneOf(fields["reason_code"].text, "owner-revoked", "superseded", "compromised") {
		return nil, errBadSchema
	}
	revocation, err := parseOpaqueID(fields["revocation_id"].text)
	if err != nil {
		return nil, err
	}
	certificate, err := parseOpaqueID(fields["certificate_id"].text)
	if err != nil {
		return nil, err
	}
	issuer, err := parseIssuerNode(fields["issuer"])
	if err != nil {
		return nil, err
	}
	effective, err := parseWireTime(fields["effective_at"].text)
	if err != nil {
		return nil, err
	}
	return &revocationProjection{raw: append([]byte(nil), raw...), revocationID: revocation, certificateID: certificate, reasonCode: fields["reason_code"].text, issuer: issuer, effectiveAt: effective}, nil
}
