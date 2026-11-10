package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"time"
)

// LocalEnrollment comes from a separately installed custodian configuration,
// never request fields. Same-UID processes can replace this local trust file.
// Its subject association does not attest Matrix device enrollment or transport.
type LocalEnrollment struct {
	owner            publicIssuerPin
	requesterDER     []byte
	subject          *localSubjectProjection
	audience         *audienceProjection
	cycle            *cycleProjection
	stateDir, ghPath string
	epoch            [32]byte
}

func ParseLocalEnrollment(raw []byte) (*LocalEnrollment, error) {
	node, err := parseCanonical(raw, localEnrollment2Wire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "type", "owner_mxid", "owner_spki", "requester_spki", "subject", "audience", "cycle", "organization", "name", "state_dir", "gh_path")
	if err != nil {
		return nil, err
	}
	texts := map[string]string{}
	for _, name := range []string{"type", "owner_mxid", "owner_spki", "requester_spki", "organization", "name", "state_dir", "gh_path"} {
		if f[name] == nil || f[name].kind != stringValue {
			return nil, errBadSchema
		}
		texts[name] = f[name].text
	}
	if texts["type"] != "grants-local-enrollment-2" || ValidateOwnerPrincipal(texts["owner_mxid"]) != nil || texts["organization"] != LocalOrganization || texts["name"] != LocalRepository {
		return nil, errResourceMismatch
	}
	public := func(value string) ([]byte, error) {
		if len(value) > 1366 || len(value)*6/8 > 1024 {
			return nil, errInputLimit
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
			return nil, errBadEncoding
		}
		if _, err := localPublicKey(raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	ownerDER, err := public(texts["owner_spki"])
	if err != nil {
		return nil, err
	}
	requesterDER, err := public(texts["requester_spki"])
	if err != nil {
		return nil, err
	}
	if bytes.Equal(ownerDER, requesterDER) {
		return nil, errIssuerUntrusted
	}
	subject, err := parseLocalSubjectNode(f["subject"])
	if err != nil {
		return nil, err
	}
	audience, err := parseAudienceNode(f["audience"])
	if err != nil {
		return nil, err
	}
	cycle, err := parseCycleNode(f["cycle"])
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"state_dir", "gh_path"} {
		path := texts[name]
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 512 {
			return nil, errBadSchema
		}
	}
	return &LocalEnrollment{owner: publicIssuerPin{ownerMXID: texts["owner_mxid"], spkiDER: ownerDER}, requesterDER: requesterDER,
		subject: subject, audience: audience, cycle: cycle, stateDir: texts["state_dir"], ghPath: texts["gh_path"], epoch: sha256.Sum256(append([]byte("swarma-grants/local-state/2\n"), raw...))}, nil
}

// checkedLocalCreate is immutable outside this package. The provider consumes
// this same object after verification and durable intent, never unchecked argv.
type checkedLocalCreate struct {
	certificate, attestation []byte
	request                  *localOperationProjection
	certificateID            string
	correlation              [32]byte
	observedAt               time.Time
}

// LocalVerification contains detached public facts from a stateless check.
// ValidAt is the observation checked; ExpiresAt is the request's exclusive
// expiry (which check requires to be no later than the certificate's expiry).
// This observation is not a reservation, lifecycle check or dispatch capability.
type LocalVerification struct {
	CertificateID string                  `json:"certificate_id"`
	RequestID     string                  `json:"request_id"`
	Action        string                  `json:"action"`
	Target        LocalVerificationTarget `json:"target"`
	ValidAt       time.Time               `json:"valid_at"`
	ExpiresAt     time.Time               `json:"expires_at"`
}

// LocalVerificationTarget is a value copy, with no retained request payload.
type LocalVerificationTarget struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	Visibility   string `json:"visibility"`
}

// Verify performs exactly the same authority check used by Execute before
// opening state. It accesses no execution state, provider or private key and
// preserves the check's errors and precedence without translating them.
func (e *LocalEnrollment) Verify(certificate, request []byte, observedAt time.Time) (*LocalVerification, error) {
	checked, err := e.check(certificate, request, observedAt)
	if err != nil {
		return nil, err
	}
	q := checked.request
	return &LocalVerification{
		CertificateID: checked.certificateID, RequestID: q.requestID, Action: q.action,
		Target: LocalVerificationTarget{Organization: q.createTarget.organization,
			Name: q.createTarget.name, Visibility: q.createTarget.visibility},
		ValidAt: checked.observedAt, ExpiresAt: q.expiresAt,
	}, nil
}

func (e *LocalEnrollment) check(certificateRaw, requestRaw []byte, observedAt time.Time) (*checkedLocalCreate, error) {
	if e == nil {
		return nil, errIssuerUntrusted
	}
	envelope, err := checkSignedRecordWithPin(certificateRaw, localCertificateEnvelopeWire, e.owner)
	if err != nil {
		return nil, err
	}
	if _, err := NewLocalRepositoryIssuance(envelope.payload, e.owner.ownerMXID, e.owner.spkiDER, e.requesterDER, LocalOrganization, LocalRepository); err != nil {
		return nil, err
	}
	attestation, err := parseLocalAttestation(requestRaw)
	if err != nil {
		return nil, err
	}
	public, err := localPublicKey(e.requesterDER)
	if err != nil {
		return nil, err
	}
	if err := verifyP256Signature(public, localRequestDigest(attestation.request.raw), attestation.signature); err != nil {
		return nil, err
	}
	request := attestation.request
	if *request.subject != *e.subject {
		return nil, errSubjectMismatch
	}
	if *request.audience != *e.audience {
		return nil, errAudienceMismatch
	}
	if request.cycleID != e.cycle.cycleID {
		return nil, errScheduleMismatch
	}
	if request.action != "repository.create" || request.createTarget.organization != LocalOrganization || request.createTarget.name != LocalRepository {
		return nil, errResourceMismatch
	}
	certificate, err := parseLocalCertificateProjection(envelope.payload)
	if err != nil {
		return nil, err
	}
	if *certificate.subject != *request.subject {
		return nil, errSubjectMismatch
	}
	if err := checkRequestBodyMatch(certificate.certificateProjection, request.requestProjection, e.cycle.runtime, e.cycle.channel, observedAt); err != nil {
		return nil, err
	}
	correlation := localOperationDigest(request.raw)
	return &checkedLocalCreate{certificate: bytes.Clone(certificateRaw), attestation: bytes.Clone(requestRaw), request: request,
		certificateID: request.certificateID, correlation: correlation, observedAt: observedAt.UTC()}, nil
}
