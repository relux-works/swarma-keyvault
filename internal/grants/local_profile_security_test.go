package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A different valid requester key cannot replace enrollment or the signed
// constraint. Both refusals precede state open/writes and provider dispatch.
func TestLocalRequesterPinSubstitutionPreState(t *testing.T) {
	for _, mode := range []string{"signed-constraint", "enrollment-key"} {
		t.Run(mode, func(t *testing.T) {
			f, m, p, _, _ := localMediatorFixture(t)
			key, public, _ := certificateSignatureFixture(t)
			if mode == "signed-constraint" {
				pin := sha256.Sum256(public)
				f.certificate["requester_spki_sha256"] = hex.EncodeToString(pin[:])
			} else {
				m.enrollment.requesterDER = public
				f.requester = key
			}
			c, q := f.envelopes(t)
			opened := 0
			original := m.open
			m.open = func(e *LocalEnrollment) (*localState, error) { opened++; return original(e) }
			if out, err := m.Execute(context.Background(), c, q); out != nil || !errors.Is(err, errRequesterMismatch) || opened != 0 || p.calls != 0 {
				t.Fatal("requester substitution", out, err, opened, p.calls)
			}
			entries, err := os.ReadDir(m.enrollment.stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("requester substitution touched state", err)
			}
			_, valid, vp, vc, vq := localMediatorFixture(t)
			if _, err := valid.Execute(context.Background(), vc, vq); err != nil || vp.calls != 1 {
				t.Fatal("valid neighbor", err, vp.calls)
			}
		})
	}
}

// Independent signatures prove both domain-confusion directions reject while
// the same complete payloads and keys under their correct domains succeed.
func TestLocalCertificateDomainSeparation(t *testing.T) {
	f := localTestFixture(t)
	c, _ := f.envelopes(t)
	pin := publicIssuerPin{ownerMXID: LocalOwnerMXID, spkiDER: f.ownerDER}
	if _, err := checkSignedRecordWithPin(c, localCertificateEnvelopeWire, pin); err != nil {
		t.Fatal("local positive", err)
	}
	var outer map[string]any
	wrong := signedCertificateFixture(t, f.owner, f.certificate, "swarma-grants/certificate/1")
	if err := json.Unmarshal(wrong, &outer); err != nil {
		t.Fatal(err)
	}
	outer["type"] = "grants-signed-local-certificate-1"
	if _, err := checkSignedRecordWithPin(requestTestBytes(t, outer), localCertificateEnvelopeWire, pin); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("Matrix domain in local certificate", err)
	}
	matrix, _ := declaredMatchFixture("repository.create", "codex-dm")
	matrix["issuer"] = f.certificate["issuer"]
	valid := signedCertificateFixture(t, f.owner, matrix, "swarma-grants/certificate/1")
	if _, err := checkSignedRecordWithPin(valid, certificateEnvelopeWire, pin); err != nil {
		t.Fatal("Matrix positive", err)
	}
	wrong = signedCertificateFixture(t, f.owner, matrix, "swarma-grants/local-certificate/1")
	if _, err := checkSignedRecordWithPin(wrong, certificateEnvelopeWire, pin); !errors.Is(err, errSignatureInvalid) {
		t.Fatal("local domain in Matrix certificate", err)
	}
}

// The public-only fixed requester descriptor proves the exact full pin and
// honesty sentence survive rendering; no actual requester signature is used.
func TestLocalReviewPublicRequesterLiteral(t *testing.T) {
	f := localTestFixture(t)
	public, err := base64.RawURLEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEanOwoyNZpkb87n4F4MvDahltHvr5LcjwxM4MdXPsU0JcEaeXwzO49wnW4jy0-7FI8whJA9vb6GqLvborvutm-g")
	if err != nil {
		t.Fatal(err)
	}
	const expected = "0cb871af2e9a110aca6366bf3a41248141779b8c500798ff977c0d3e78429499"
	hash := sha256.Sum256(public)
	if hex.EncodeToString(hash[:]) != expected {
		t.Fatal("fixed public fixture pin")
	}
	f.certificate["requester_spki_sha256"] = expected
	plan, err := NewLocalRepositoryIssuance(requestTestBytes(t, f.certificate), LocalOwnerMXID, f.ownerDER, public, LocalOrganization, LocalRepository)
	if err != nil {
		t.Fatal(err)
	}
	const sentence = "Ни одно устройство Matrix не аутентифицировано. encrypted-dm — только заявленная метка; этот локальный путь ничего не шифрует и не доставляет через Matrix."
	if !bytes.Contains([]byte(plan.Review()), []byte(sentence+"\n")) || !bytes.Contains([]byte(plan.Review()), []byte("Requester SPKI SHA256: "+expected+"\n")) {
		t.Fatal("exact public pin/disclosure missing")
	}
}

// The actual checked object passed to dispatch carries the independently
// specified exact local correlation, not the signature or Matrix digest.
func TestLocalCheckedCorrelationPlumbing(t *testing.T) {
	f, m, p, c, q := localMediatorFixture(t)
	want := sha256.Sum256(append([]byte("swarma-grants/local-operation/1\n"), requestTestBytes(t, f.request)...))
	p.check = func(checked *checkedLocalCreate) {
		if checked.correlation != want {
			t.Errorf("dispatch correlation %x want %x", checked.correlation, want)
		}
	}
	if _, err := m.Execute(context.Background(), c, q); err != nil || p.calls != 1 {
		t.Fatal(err, p.calls)
	}
}

// Old config/envelopes refuse before state/provider; an old-domain journal
// epoch refuses without rewriting bytes or replenishing the old allowance.
func TestLocalR2RefusesWithoutMigration(t *testing.T) {
	for _, mode := range []string{"config", "envelope", "state"} {
		t.Run(mode, func(t *testing.T) {
			_, valid, vp, vc, vq := localMediatorFixture(t)
			if _, err := valid.Execute(context.Background(), vc, vq); err != nil || vp.calls != 1 {
				t.Fatal("valid neighbor", err)
			}
			f, m, p, c, q := localMediatorFixture(t)
			oldConfig := subobjectCopy(f.config)
			oldConfig["type"] = "grants-local-enrollment-1"
			_, oldRequest := declaredMatchFixture("repository.create", "codex-dm")
			oldConfig["subject"] = oldRequest["subject"]
			oldRaw := requestTestBytes(t, oldConfig)
			if mode == "config" {
				if got, err := ParseLocalEnrollment(oldRaw); got != nil || !errors.Is(err, errResourceMismatch) {
					t.Fatal("old config", err)
				}
				return
			}
			if mode == "envelope" {
				var outer map[string]string
				if err := json.Unmarshal(q, &outer); err != nil {
					t.Fatal(err)
				}
				outer["type"] = "grants-local-request-1"
				if _, err := m.Execute(context.Background(), c, requestTestBytes(t, outer)); !errors.Is(err, errBadSchema) || p.calls != 0 {
					t.Fatal("old envelope", err, p.calls)
				}
				files, err := os.ReadDir(m.enrollment.stateDir)
				if err != nil || len(files) != 0 {
					t.Fatal("old envelope touched state", err)
				}
				return
			}
			epoch := sha256.Sum256(append([]byte("swarma-grants/local-state/1\n"), oldRaw...))
			// The physical epoch check happens before typed reservation decoding.
			frame, err := encodeJournalFrame(journalReservation, journalFrameLink{sequence: 1, epoch: epoch}, []byte("retained-old-reservation"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.enrollment.stateDir, "local.journal")
			if err := os.WriteFile(path, frame, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.enrollment.stateDir, "local.lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Execute(context.Background(), c, q); !errors.Is(err, ErrLocalState) || p.calls != 0 {
				t.Fatal("old epoch", err, p.calls)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, frame) {
				t.Fatal("old journal changed", err)
			}
		})
	}
}
