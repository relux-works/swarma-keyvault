package grants

import "time"

// A requestProjection is untrusted representation. Its identities, schedule,
// resource/instance/receipt and expiry still require binding to the same actual
// admitted certificate, qualified receiver, clock and durable use transaction.
type requestProjection struct {
	raw                                                                []byte
	requestID, certificateID, entryID, cycleID, operationUseID, action string
	subject                                                            *subjectProjection
	audience                                                           *audienceProjection
	createTarget                                                       *createTargetProjection
	deleteTarget                                                       *deleteRequestTargetProjection
	expiresAt                                                          time.Time
}

func parseRequestProjection(raw []byte) (*requestProjection, error) {
	node, err := parseCanonical(raw, requestWire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "type", "request_id", "certificate_id", "entry_id", "cycle_id", "operation_use_id", "subject", "audience", "action", "target", "expires_at")
	if err != nil {
		return nil, err
	}
	for name, field := range f {
		if name != "subject" && name != "audience" && name != "target" && (field == nil || field.kind != stringValue) {
			return nil, errBadSchema
		}
	}
	if f["type"].text != "grants-request-1" || !oneOf(f["action"].text, "repository.create", "repository.delete") {
		return nil, errBadSchema
	}
	value := &requestProjection{action: f["action"].text}
	for _, field := range []struct {
		name        string
		destination *string
	}{{"request_id", &value.requestID}, {"certificate_id", &value.certificateID}, {"entry_id", &value.entryID}, {"cycle_id", &value.cycleID}, {"operation_use_id", &value.operationUseID}} {
		parsed, e := parseOpaqueID(f[field.name].text)
		if e != nil {
			return nil, e
		}
		*field.destination = parsed
	}
	value.subject, err = parseSubjectNode(f["subject"])
	if err != nil {
		return nil, err
	}
	value.audience, err = parseAudienceNode(f["audience"])
	if err != nil {
		return nil, err
	}
	value.expiresAt, err = parseWireTime(f["expires_at"].text)
	if err != nil {
		return nil, err
	}
	if value.action == "repository.create" {
		value.createTarget, err = parseCreateTargetNode(f["target"])
	} else {
		value.deleteTarget, err = parseDeleteRequestTargetNode(f["target"])
	}
	if err != nil {
		return nil, err
	}
	value.raw = append([]byte(nil), raw...)
	return value, nil
}
