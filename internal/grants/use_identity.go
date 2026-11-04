package grants

// logicalUseKey preserves the signed plan's (certificate, entry, use)
// uniqueness namespace. Separate exact fields avoid delimiter ambiguity.
// A use ID is unique within its entry; its signed cycle is a separately checked
// binding, never another allowance. Request/event IDs are correlation only.
// This comparable representation is not a reservation or an authority token.
type logicalUseKey struct {
	certificateID  string
	entryID        string
	operationUseID string
}

// logicalUseKey derives representation identity from a complete parsed request.
// It does not check certificate membership, cycle, signature, current state,
// time or receiver/receipt authenticity. Callers still need those gates and an
// admitted durable transaction before any use reservation or provider effect.
func (request *requestProjection) logicalUseKey() logicalUseKey {
	return logicalUseKey{
		certificateID:  request.certificateID,
		entryID:        request.entryID,
		operationUseID: request.operationUseID,
	}
}
