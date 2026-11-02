package grants

import (
	"bytes"
	"errors"
	"time"
)

var (
	errCertificateIDCollision   = errors.New("certificate-id-collision")
	errRevocationIDCollision    = errors.New("revocation-id-collision")
	errRequiredStateUnavailable = errors.New("required-state-unavailable")
)

// checkRevocationAgainstCertificate verifies the complete public signatures,
// exact target ID and retained certificate's exact lifecycle signing authority.
// A generally pinned different key is insufficient, even under the same owner.
// Initial revocations cannot schedule a future effective instant relative to
// the supplied sample. No clock is read or qualified here, and nil performs no
// revocation, immutable insert, audit commit, use change or other state write.
func checkRevocationAgainstCertificate(revocationRaw, retainedCertificateRaw []byte, revokerPin, certificatePin publicIssuerPin, observedAt time.Time) error {
	certificateEnvelope, err := checkSignedRecordWithPin(retainedCertificateRaw, certificateEnvelopeWire, certificatePin)
	if err != nil {
		return err
	}
	revocationEnvelope, err := checkSignedRecordWithPin(revocationRaw, revocationEnvelopeWire, revokerPin)
	if err != nil {
		return err
	}
	// Both complete schemas were checked above. Retain the defensive errors
	// while extracting typed fields instead of selecting caller-supplied IDs.
	certificate, err := parseCertificateProjection(certificateEnvelope.payload)
	if err != nil {
		return err
	}
	revocation, err := parseRevocationProjection(revocationEnvelope.payload)
	if err != nil {
		return err
	}
	if *certificate.issuer != *revocation.issuer {
		return errIssuerUntrusted
	}
	if certificate.certificateID != revocation.certificateID {
		return errBadLifecycleReference
	}
	if !supportedYear(observedAt.UTC()) {
		return ErrInvalidObservation
	}
	if revocation.effectiveAt.After(observedAt) {
		return errBadSchema
	}
	return nil
}

// checkImmutableSignedReplay compares an incoming record with the retained
// record selected for that SAME typed ID. Both complete signatures are checked
// against their separately supplied public pins before comparing exact bounded
// payload/envelope bytes. A new valid signature over identical payload bytes is
// a collision, not a replay. A different ID means the retained lookup is wrong.
// Certificate and revocation profiles are explicit, disjoint namespaces.
//
// Nil means exact public-record equality only. It never inserts, reactivates,
// refreshes time, consumes or releases a use, or authenticates current lifecycle,
// state epoch, enrollment or storage. The caller must read CURRENT protected
// state for even an expired/revoked/superseded replay; absence/unavailability
// cannot be inferred from this helper or represented by missing retained bytes.
func checkImmutableSignedReplay(candidateRaw, retainedRaw []byte, profile wireProfile, candidatePin, retainedPin publicIssuerPin) error {
	candidate, err := checkSignedRecordWithPin(candidateRaw, profile, candidatePin)
	if err != nil {
		return err
	}
	retained, err := checkSignedRecordWithPin(retainedRaw, profile, retainedPin)
	if err != nil {
		return err
	}
	var candidateID, retainedID string
	var collision error
	switch profile {
	case certificateEnvelopeWire:
		c, err := parseCertificateProjection(candidate.payload)
		if err != nil {
			return err
		}
		r, err := parseCertificateProjection(retained.payload)
		if err != nil {
			return err
		}
		candidateID, retainedID, collision = c.certificateID, r.certificateID, errCertificateIDCollision
	case revocationEnvelopeWire:
		c, err := parseRevocationProjection(candidate.payload)
		if err != nil {
			return err
		}
		r, err := parseRevocationProjection(retained.payload)
		if err != nil {
			return err
		}
		candidateID, retainedID, collision = c.revocationID, r.revocationID, errRevocationIDCollision
	default:
		return errBadSchema
	}
	if candidateID != retainedID {
		return errRequiredStateUnavailable
	}
	if !bytes.Equal(candidate.raw, retained.raw) || !bytes.Equal(candidate.payload, retained.payload) {
		return collision
	}
	return nil
}
