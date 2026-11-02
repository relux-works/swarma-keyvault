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
		// The certificate decoder already establishes exactly one paired
		// CREATE use in this cycle. Bind the request to THAT declared use;
		// a later custody gate must still authenticate its actual outcome.
		for _, paired := range certificate.entries {
			if paired.entryID == entry.deleteTarget.pairedCreateEntry &&
				!entryDeclaresUse(paired, request.cycleID, request.deleteTarget.createOperationUseID) {
				return errScheduleMismatch
			}
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

func entryDeclaresUse(entry *entryProjection, cycleID, operationUseID string) bool {
	for _, use := range entry.uses {
		if use.cycleID == cycleID && use.operationUseID == operationUseID {
			return true
		}
	}
	return false
}
