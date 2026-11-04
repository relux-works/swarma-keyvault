package grants

import (
	"errors"
	"time"
)

var (
	errSubjectMismatch  = errors.New("subject-mismatch")
	errAudienceMismatch = errors.New("audience-mismatch")
	errScheduleMismatch = errors.New("schedule-mismatch")
	errResourceMismatch = errors.New("resource-mismatch")
)

// checkSignedRequestMatch verifies the complete signed certificate under the
// explicit public pin, then matches the request against exactly that verified
// payload. The caller cannot substitute a separate unsigned certificate.
// Nil establishes public signature and declaration agreement only, with the
// same enrollment, lifecycle, receiver, clock, state and effect limits as the
// two underlying checks. No dispatch capability or private operation results.
func checkSignedRequestMatch(envelopeRaw, requestRaw []byte, pin publicIssuerPin, runtime, channel string, observedAt time.Time) error {
	envelope, err := checkSignedRecordWithPin(envelopeRaw, certificateEnvelopeWire, pin)
	if err != nil {
		return err
	}
	return checkDeclaredRequestMatch(envelope.payload, requestRaw, runtime, channel, observedAt)
}

// checkDeclaredRequestMatch checks only predicates declared in two untrusted
// canonical documents and an explicitly supplied runtime/channel/time sample.
// Nil means the declarations match, never that either document or context is
// authentic or that an operation is authorized. It returns no capability.
// Issuer enrollment/signatures, receiver identity/origin, qualified clock,
// current lifecycle, durable audit/use and actual paired CREATE receipt remain
// separate requirements. In particular, DELETE instance and receipt fields
// are parsed here but are NOT authenticated against a retained provider result.
// No clock, state, key, network or provider is accessed; inputs are not changed.
func checkDeclaredRequestMatch(certificateRaw, requestRaw []byte, runtime, channel string, observedAt time.Time) error {
	certificate, err := parseCertificateProjection(certificateRaw)
	if err != nil {
		return err
	}
	request, err := parseRequestProjection(requestRaw)
	if err != nil {
		return err
	}
	if certificate.certificateID != request.certificateID {
		return errScheduleMismatch
	}
	if certificate.subject.accountMXID != request.subject.accountMXID ||
		certificate.subject.deviceID != request.subject.deviceID ||
		certificate.subject.deviceEd25519 != request.subject.deviceEd25519 {
		return errSubjectMismatch
	}
	if *certificate.audience != *request.audience {
		return errAudienceMismatch
	}
	var cycle *cycleProjection
	for _, candidate := range certificate.cycles {
		if candidate.cycleID == request.cycleID {
			cycle = candidate
			break
		}
	}
	if cycle == nil || cycle.runtime != runtime || cycle.channel != channel {
		return errScheduleMismatch
	}
	var entry *entryProjection
	for _, candidate := range certificate.entries {
		if candidate.entryID == request.entryID {
			entry = candidate
			break
		}
	}
	if entry == nil || !entryDeclaresUse(entry, request.cycleID, request.operationUseID) {
		return errScheduleMismatch
	}
	if entry.action != request.action {
		return errResourceMismatch
	}
	switch request.action {
	case "repository.create":
		if *entry.createTarget != *request.createTarget {
			return errResourceMismatch
		}
	case "repository.delete":
		if entry.deleteTarget.resourceTargetText != request.deleteTarget.resourceTargetText {
			return errResourceMismatch
		}
		// Require the paired entry explicitly even though the complete
		// decoder also checks its existence. Its actual provider outcome
		// remains a separate authenticated custody requirement.
		if !pairedCreateDeclaresUse(certificate.entries, entry.deleteTarget.pairedCreateEntry, request.cycleID, request.deleteTarget.createOperationUseID) {
			return errScheduleMismatch
		}
	}
	// A structurally valid request may not extend the certificate's interval.
	// Such a declaration is a schedule mismatch, independently of current time.
	if request.expiresAt.After(certificate.expiresAt) {
		return errScheduleMismatch
	}
	if err := CheckIntervalAt(certificate.notBefore, certificate.expiresAt, observedAt); err != nil {
		return err
	}
	if !observedAt.Before(request.expiresAt) {
		return ErrExpired
	}
	return nil
}

func pairedCreateDeclaresUse(entries []*entryProjection, entryID, cycleID, operationUseID string) bool {
	for _, entry := range entries {
		if entry.entryID == entryID {
			return entry.action == "repository.create" && entryDeclaresUse(entry, cycleID, operationUseID)
		}
	}
	return false
}

func entryDeclaresUse(entry *entryProjection, cycleID, operationUseID string) bool {
	for _, use := range entry.uses {
		if use.cycleID == cycleID && use.operationUseID == operationUseID {
			return true
		}
	}
	return false
}
