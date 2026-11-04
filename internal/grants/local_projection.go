package grants

// A local subject is a declaration associated with an enrolled P-256 key. It
// has no Ed25519 field and authenticates no Matrix device or channel.
type localSubjectProjection struct{ accountMXID, deviceID string }

type localCertificateProjection struct {
	*certificateProjection
	subject       *localSubjectProjection
	requesterHash [32]byte
}

type localOperationProjection struct {
	*requestProjection
	subject *localSubjectProjection
}

func parseLocalSubjectNode(node *wireValue) (*localSubjectProjection, error) {
	f, err := subobjectTexts(node, "account_mxid", "device_id")
	if err != nil {
		return nil, err
	}
	account, err := parseMatrixAccountRepresentation(f["account_mxid"])
	if err != nil {
		return nil, err
	}
	device, err := parseDeviceIDRepresentation(f["device_id"])
	if err != nil {
		return nil, err
	}
	return &localSubjectProjection{accountMXID: account, deviceID: device}, nil
}

func parseLocalCertificateProjection(raw []byte) (*localCertificateProjection, error) {
	node, err := parseCanonical(raw, localCertificateWire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "type", "certificate_id", "issuer", "subject", "requester_spki_sha256", "audience", "not_before", "expires_at", "supersedes", "cycles", "entries")
	if err != nil {
		return nil, err
	}
	kind, err := memberText(node, "type")
	if err != nil || kind != "grants-local-certificate-1" {
		return nil, errBadSchema
	}
	subject, err := parseLocalSubjectNode(f["subject"])
	if err != nil {
		return nil, err
	}
	text, err := memberText(node, "requester_spki_sha256")
	if err != nil {
		return nil, err
	}
	hash, err := parseWireDigest(text)
	if err != nil {
		return nil, err
	}
	body, err := parseCertificateBody(raw, f)
	if err != nil {
		return nil, err
	}
	return &localCertificateProjection{certificateProjection: body, subject: subject, requesterHash: hash}, nil
}

func parseLocalOperationProjection(raw []byte) (*localOperationProjection, error) {
	node, err := parseCanonical(raw, localOperationWire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "type", "request_id", "certificate_id", "entry_id", "cycle_id", "operation_use_id", "subject", "audience", "action", "target", "expires_at")
	if err != nil {
		return nil, err
	}
	kind, err := memberText(node, "type")
	if err != nil || kind != "grants-local-operation-1" {
		return nil, errBadSchema
	}
	subject, err := parseLocalSubjectNode(f["subject"])
	if err != nil {
		return nil, err
	}
	body, err := parseRequestBody(raw, f)
	if err != nil {
		return nil, err
	}
	return &localOperationProjection{requestProjection: body, subject: subject}, nil
}

func localOperationDigest(raw []byte) [32]byte {
	digest, _ := domainDigest(localOperationDomain, raw)
	return digest
}
