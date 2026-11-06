package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

type localVerifyCase struct {
	name string
	want error
}

// Each named case has a signed valid neighbor and an explicit existing-code oracle.
var localVerifyCases = []localVerifyCase{
	{"malformed-certificate", errBadEncoding},
	{"malformed-request", errBadEncoding},
	{"unsigned-certificate", errBadSchema},
	{"certificate-signature", errSignatureInvalid},
	{"owner-pin", errIssuerUntrusted},
	{"requester-pin", errRequesterMismatch},
	{"attestation", errBadSchema},
	{"request-signature", errSignatureInvalid},
	{"subject", errSubjectMismatch},
	{"audience", errAudienceMismatch},
	{"cycle", errScheduleMismatch},
	{"use", errScheduleMismatch},
	{"target", errResourceMismatch},
	{"action", errResourceMismatch},
	{"certificate-expired", ErrExpired},
	{"certificate-not-yet-valid", ErrNotYetValid},
	{"request-expired", ErrExpired},
	{"request-not-yet-valid", ErrNotYetValid},
	{"request-independent-not-before", errBadSchema},
	{"owner-before-signature", errIssuerUntrusted},
	{"certificate-before-request", errSignatureInvalid},
	{"requester-before-attestation", errRequesterMismatch},
	{"signature-before-scope-time", errSignatureInvalid},
	{"subject-before-audience", errSubjectMismatch},
	{"audience-before-cycle", errAudienceMismatch},
	{"cycle-before-target", errScheduleMismatch},
	{"scope-before-time", errResourceMismatch},
	{"schedule-before-time", errScheduleMismatch},
}

func localVerifyInputs(t *testing.T, mode string) (*LocalEnrollment, []byte, []byte, time.Time) {
	t.Helper()
	f := localTestFixture(t)
	now := f.now
	switch mode {
	case "owner-pin", "owner-before-signature":
		_, der, _ := certificateSignatureFixture(t)
		f.config["owner_spki"] = base64.RawURLEncoding.EncodeToString(der)
	case "requester-pin", "requester-before-attestation":
		_, der, _ := certificateSignatureFixture(t)
		f.config["requester_spki"] = base64.RawURLEncoding.EncodeToString(der)
	case "subject", "subject-before-audience":
		f.request["subject"] = map[string]any{"account_mxid": "@other:example.invalid", "device_id": "DEVICE-A"}
	case "audience", "audience-before-cycle":
		f.request["audience"] = map[string]any{"deployment_id": "other", "executor_id": "executor-A"}
	case "cycle", "cycle-before-target":
		f.request["cycle_id"] = "claude-dm"
	case "use":
		f.request["operation_use_id"] = "other"
	case "target", "scope-before-time", "signature-before-scope-time":
		f.request["target"].(map[string]any)["name"] = "other"
	case "action":
		f.request["action"], f.request["entry_id"] = "repository.delete", "repo-delete"
		f.request["target"] = map[string]any{"organization": LocalOrganization, "name": LocalRepository, "repository_id": "42", "create_operation_use_id": "codex-dm/create", "create_result_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	case "request-independent-not-before":
		// The existing request has no not_before field: its lower bound is the certificate's.
		f.request["not_before"] = "2026-11-02T11:01:00Z"
	case "schedule-before-time":
		f.request["expires_at"] = "2026-11-02T12:00:01Z"
	}
	switch mode {
	case "subject-before-audience":
		f.request["audience"] = map[string]any{"deployment_id": "other", "executor_id": "executor-A"}
	case "audience-before-cycle":
		f.request["cycle_id"] = "claude-dm"
	case "cycle-before-target":
		f.request["target"].(map[string]any)["name"] = "other"
	}
	switch mode {
	case "certificate-expired", "scope-before-time", "signature-before-scope-time":
		now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	case "certificate-not-yet-valid", "request-not-yet-valid", "schedule-before-time":
		now = time.Date(2026, 11, 2, 9, 59, 59, 0, time.UTC)
	case "request-expired":
		now = time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)
	}
	switch mode {
	case "certificate-signature", "owner-before-signature", "certificate-before-request":
		f.owner = f.requester // Keep the bound issuer unchanged; sign with another synthetic key.
	case "request-signature", "signature-before-scope-time":
		f.requester = f.owner
	}
	c, q := f.envelopes(t)
	switch mode {
	case "malformed-certificate":
		c = append(c, '\n')
	case "unsigned-certificate":
		c = requestTestBytes(t, f.certificate)
	case "malformed-request", "certificate-before-request", "requester-before-attestation":
		q = append(q, '\n')
	case "attestation":
		var outer map[string]any
		if err := json.Unmarshal(q, &outer); err != nil {
			t.Fatal(err)
		}
		outer["type"] = "grants-signed-certificate-1"
		q = requestTestBytes(t, outer)
	}
	e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
	if err != nil {
		t.Fatal("enrollment fixture", err)
	}
	return e, c, q, now
}

func requireLocalVerifyAccepted(t *testing.T, e *LocalEnrollment, c, q []byte, at time.Time) *LocalVerification {
	t.Helper()
	facts, err := e.Verify(c, q, at)
	if err != nil || facts == nil {
		t.Fatal("valid neighbor refused", err)
	}
	want := LocalVerification{CertificateID: "certificate-A", RequestID: "request-A", Action: "repository.create",
		Target:  LocalVerificationTarget{Organization: LocalOrganization, Name: LocalRepository, Visibility: "private"},
		ValidAt: at.UTC(), ExpiresAt: time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)}
	if *facts != want {
		t.Fatalf("bound facts: got %+v, want %+v", *facts, want)
	}
	return facts
}

// Claim: Verify accepts valid authority and returns detached facts without changing caller bytes or enrollment.
func TestLocalVerifyAcceptedFacts(t *testing.T) {
	e, c, q, at := localVerifyInputs(t, "valid")
	beforeC, beforeQ := bytes.Clone(c), bytes.Clone(q)
	facts := requireLocalVerifyAccepted(t, e, c, q, at)
	facts.Target.Name, facts.RequestID = "changed", "changed"
	requireLocalVerifyAccepted(t, e, c, q, at)
	if !bytes.Equal(c, beforeC) || !bytes.Equal(q, beforeQ) {
		t.Fatal("verification changed caller bytes")
	}
	c[0], q[0] = 'x', 'x'
	if facts.CertificateID != "certificate-A" || facts.Action != "repository.create" {
		t.Fatal("facts alias input")
	}
}

// Claim: Every refusal and multi-fault precedence matches the unchanged pre-state check, beside accepted controls.
func TestLocalVerifyRefusals(t *testing.T) {
	for _, tc := range localVerifyCases {
		t.Run(tc.name, func(t *testing.T) {
			good, gc, gq, ga := localVerifyInputs(t, "valid")
			requireLocalVerifyAccepted(t, good, gc, gq, ga)
			e, c, q, at := localVerifyInputs(t, tc.name)
			if facts, err := e.Verify(c, q, at); facts != nil || err != tc.want {
				t.Fatalf("refusal assertion: got facts=%+v error=%v; want %v", facts, err, tc.want)
			}
			if checked, err := e.check(c, q, at); checked != nil || err != tc.want {
				t.Fatalf("underlying check oracle: %v, want %v", err, tc.want)
			}
			requireLocalVerifyAccepted(t, good, gc, gq, ga)
		})
	}
}

// Claim: Nil enrollment retains issuer-untrusted and the interval endpoints remain inclusive/exclusive at subsecond precision.
func TestLocalVerifyBoundaries(t *testing.T) {
	var absent *LocalEnrollment
	if facts, err := absent.Verify(nil, nil, time.Time{}); facts != nil || err != errIssuerUntrusted {
		t.Fatal("nil enrollment", facts, err)
	}
	e, c, q, _ := localVerifyInputs(t, "valid")
	for _, tc := range []struct {
		at   time.Time
		want error
	}{
		{time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), nil},
		{time.Date(2026, 11, 2, 9, 59, 59, 999999999, time.UTC), ErrNotYetValid},
		{time.Date(2026, 11, 2, 11, 29, 59, 999999999, time.UTC), nil},
		{time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC), ErrExpired},
	} {
		facts, err := e.Verify(c, q, tc.at)
		if err != tc.want || (facts == nil) != (tc.want != nil) {
			t.Fatalf("boundary %s: %v, want %v", tc.at, err, tc.want)
		}
	}
}
