package grants

import (
	"sort"
	"strings"
	"time"
)

type projectedRepository struct {
	organization string
	name         string
	repositoryID uint64
}

// resultProjection is decoded public data, NEVER an authenticated receipt,
// reservation handle, provider capability, or proof of observed state/time.
// All bindings to a durable record and protected result boundary remain the
// consumer's separate obligation. No parser path performs a state transition.
type resultProjection struct {
	raw                   []byte
	kind                  string
	state                 string
	code                  string
	requestDigest         [32]byte
	inputDigest           [32]byte
	certificateID         string
	entryID               string
	cycleID               string
	operationUseID        string
	action                string
	reservationID         string
	observedAt            time.Time
	auditSequence         uint64
	dispatchID            string
	providerReceiptDigest [32]byte
	repository            *projectedRepository
}

// closedObject consumes the scanner's sorted, duplicate-free object and
// requires exactly the declared fields, including recursively used schemas.
func closedObject(node *wireValue, names ...string) (map[string]*wireValue, error) {
	if node == nil || node.kind != objectValue || len(node.members) != len(names) {
		return nil, errBadSchema
	}
	sort.Strings(names)
	fields := make(map[string]*wireValue, len(names))
	for i, name := range names {
		if node.members[i].name != name {
			return nil, errBadSchema
		}
		fields[name] = node.members[i].value
	}
	return fields, nil
}
func memberText(node *wireValue, name string) (string, error) {
	if node == nil || node.kind != objectValue {
		return "", errBadSchema
	}
	for _, member := range node.members {
		if member.name == name {
			if member.value == nil || member.value.kind != stringValue {
				return "", errBadSchema
			}
			return member.value.text, nil
		}
	}
	return "", errBadSchema
}
func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if item == value {
			return true
		}
	}
	return false
}
func refusalCode(value string) bool {
	return oneOf(value, "bad-encoding", "bad-schema", "issuer-untrusted", "signature-invalid", "subject-mismatch", "receiver-unavailable", "receiver-unverified", "audience-mismatch", "schedule-mismatch", "resource-mismatch", "not-yet-valid", "expired", "lifetime-exceeded", "certificate-revoked", "certificate-superseded", "request-id-collision", "use-already-reserved", "paired-create-unavailable", "instance-mismatch", "provider-instance-capability-unavailable", "required-state-unavailable", "clock-unavailable", "certificate-id-collision", "revocation-id-collision", "predecessor-unavailable", "predecessor-authority-mismatch", "bad-lifecycle-reference", "lifecycle-reference-limit", "predecessor-obligations-unsettled", "input-limit-exceeded", "state-capacity-exceeded")
}

// parseResultProjection checks NEW result/error canonical bytes, closed tagged
// fields and individual field values only. It cannot establish truth, freshness
// or origin. It retains an owned copy of the exact validated bytes; it never
// repairs invalid input or converts a model/file projection into authority.
func parseResultProjection(raw []byte) (*resultProjection, error) {
	node, err := parseCanonical(raw, resultWire)
	if err != nil {
		return nil, err
	}
	kind, err := memberText(node, "type")
	if err != nil {
		return nil, err
	}
	state := ""
	var names []string
	switch kind {
	case "grants-error-1":
		names = []string{"type", "code", "input_sha256"}
	case "grants-result-1":
		state, err = memberText(node, "state")
		if err != nil {
			return nil, err
		}
		names = strings.Fields("type state request_digest certificate_id entry_id cycle_id operation_use_id action reservation_id observed_at audit_sequence")
		switch state {
		case "reserved":
		case "blocked":
			names = append(names, "code")
		case "succeeded":
			names = append(names, "dispatch_id", "provider_receipt_digest", "repository")
		case "failed":
			names = append(names, "dispatch_id", "provider_receipt_digest", "code")
		case "unknown":
			names = append(names, "dispatch_id", "code")
		case "refused":
			names = []string{"type", "state", "input_sha256", "code", "observed_at"}
		default:
			return nil, errBadSchema
		}
	default:
		return nil, errBadSchema
	}
	fields, err := closedObject(node, names...)
	if err != nil {
		return nil, err
	}
	for name, value := range fields {
		if name != "repository" && (value == nil || value.kind != stringValue) {
			return nil, errBadSchema
		}
	}
	value := &resultProjection{kind: kind, state: state}
	if field, exists := fields["code"]; exists {
		value.code = field.text
	}
	if kind == "grants-error-1" {
		if !oneOf(value.code, "clock-unavailable", "receiver-unavailable", "issuer-unavailable", "store-unavailable", "provider-unavailable", "result-boundary-unavailable") {
			return nil, errBadSchema
		}
		value.inputDigest, err = parseWireDigest(fields["input_sha256"].text)
		if err != nil {
			return nil, err
		}
		value.raw = append([]byte(nil), raw...)
		return value, nil
	}
	value.observedAt, err = parseWireTime(fields["observed_at"].text)
	if err != nil {
		return nil, err
	}
	if state == "refused" {
		if !refusalCode(value.code) {
			return nil, errBadSchema
		}
		value.inputDigest, err = parseWireDigest(fields["input_sha256"].text)
		if err != nil {
			return nil, err
		}
		value.raw = append([]byte(nil), raw...)
		return value, nil
	}
	switch state {
	case "blocked":
		if !oneOf(value.code, "expired", "certificate-revoked", "certificate-superseded", "required-state-unavailable", "clock-unavailable", "provider-instance-capability-unavailable") {
			return nil, errBadSchema
		}
	case "failed":
		if value.code != "provider-refused-no-effect" {
			return nil, errBadSchema
		}
	case "unknown":
		if !oneOf(value.code, "dispatch-outcome-unknown", "required-audit-unknown", "cleanup-unknown") {
			return nil, errBadSchema
		}
	}
	value.action = fields["action"].text
	if !oneOf(value.action, "repository.create", "repository.delete") {
		return nil, errBadSchema
	}
	value.requestDigest, err = parseWireDigest(fields["request_digest"].text)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name        string
		destination *string
	}{
		{"certificate_id", &value.certificateID}, {"entry_id", &value.entryID}, {"cycle_id", &value.cycleID}, {"operation_use_id", &value.operationUseID}, {"reservation_id", &value.reservationID},
	} {
		parsed, e := parseOpaqueID(fields[field.name].text)
		if e != nil {
			return nil, e
		}
		*field.destination = parsed
	}
	value.auditSequence, err = parsePositiveDecimal(fields["audit_sequence"].text)
	if err != nil {
		return nil, err
	}
	if state == "succeeded" || state == "failed" || state == "unknown" {
		value.dispatchID, err = parseOpaqueID(fields["dispatch_id"].text)
		if err != nil {
			return nil, err
		}
	}
	if state == "succeeded" || state == "failed" {
		value.providerReceiptDigest, err = parseWireDigest(fields["provider_receipt_digest"].text)
		if err != nil {
			return nil, err
		}
	}
	if state == "succeeded" {
		repo, err := closedObject(fields["repository"], "provider", "repository_id", "organization", "name", "visibility")
		if err != nil {
			return nil, err
		}
		for _, field := range repo {
			if field == nil || field.kind != stringValue {
				return nil, errBadSchema
			}
		}
		if repo["provider"].text != "github" || repo["visibility"].text != "private" {
			return nil, errBadSchema
		}
		id, err := parsePositiveDecimal(repo["repository_id"].text)
		if err != nil {
			return nil, err
		}
		// Organization/name bytes are retained for actual resource/receipt
		// binding. This decoder does not prove provider identity or syntax.
		value.repository = &projectedRepository{organization: repo["organization"].text, name: repo["name"].text, repositoryID: id}
	}
	value.raw = append([]byte(nil), raw...)
	return value, nil
}
