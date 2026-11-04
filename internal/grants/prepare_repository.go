package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// UnsignedCertificate is an authoring result, not an enrolled issuer, signed
// grant, active authority or dispatch capability. Review describes Payload in
// full; Digest covers the certificate domain, LF and exactly Payload.
type UnsignedCertificate struct {
	Payload []byte
	Digest  [sha256.Size]byte
	Review  string
}

// PrepareRepositoryCertificate authors a first-issue private CREATE and paired
// DELETE certificate from an explicit bounded canonical draft and public key.
// It accesses no key store, clock, receiver, lifecycle state or provider. The
// supplied owner/SPKI are authoring inputs; this does not enroll either one.
func PrepareRepositoryCertificate(draft []byte, ownerMXID string, spkiDER []byte) (*UnsignedCertificate, error) {
	return prepareRepositoryCertificate(draft, ownerMXID, spkiDER, nil, false)
}

// PrepareLocalRepositoryCertificate authors the distinct local certificate
// with an explicit requester DER, not a Matrix device or a verifier selector.
func PrepareLocalRepositoryCertificate(draft []byte, ownerMXID string, spkiDER, requesterDER []byte) (*UnsignedCertificate, error) {
	return prepareRepositoryCertificate(draft, ownerMXID, spkiDER, requesterDER, true)
}

func prepareRepositoryCertificate(draft []byte, ownerMXID string, spkiDER, requesterDER []byte, local bool) (*UnsignedCertificate, error) {
	profile, domain := certificateWire, certificateDomain
	if local {
		profile, domain = localCertificateWire, localCertificateDomain
	}

	node, err := parseCanonical(draft, profile)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "audience", "certificate_id", "cycles", "expires_at", "name", "not_before", "organization", "subject")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"certificate_id", "expires_at", "name", "not_before", "organization"} {
		if f[name] == nil || f[name].kind != stringValue || f[name].text == "" {
			return nil, errBadSchema
		}
	}
	if local {
		if _, err := parseLocalSubjectNode(f["subject"]); err != nil {
			return nil, err
		}
		if _, err := localPublicKey(requesterDER); err != nil {
			return nil, err
		}
		if bytes.Equal(spkiDER, requesterDER) {
			return nil, errRequesterMismatch
		}
	} else if _, err := parseSubjectNode(f["subject"]); err != nil {
		return nil, err
	}
	if _, err := parseAudienceNode(f["audience"]); err != nil {
		return nil, err
	}
	cycles, err := boundedWireArray(f["cycles"], 16, true)
	if err != nil {
		return nil, err
	}
	createUses, deleteUses := make([]any, 0, len(cycles)), make([]any, 0, len(cycles))
	for _, value := range cycles {
		cycle, err := parseCycleNode(value)
		if err != nil {
			return nil, err
		}
		createUses = append(createUses, map[string]any{"cycle_id": cycle.cycleID, "operation_use_id": cycle.cycleID + "/create"})
		deleteUses = append(deleteUses, map[string]any{"cycle_id": cycle.cycleID, "operation_use_id": cycle.cycleID + "/delete"})
	}
	if _, err := parseMatrixAccountRepresentation(ownerMXID); err != nil {
		return nil, err
	}
	if len(spkiDER) == 0 || len(spkiDER) > 1024 {
		return nil, errIssuerUntrusted
	}
	key, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, errIssuerUntrusted
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errIssuerUntrusted
	}
	// Every draft field has already passed the duplicate-preserving bounded
	// scanner and its closed schema. This decode is only an authoring projection;
	// it never repairs an invalid received certificate or signed payload.
	var plan map[string]any
	if err := json.Unmarshal(draft, &plan); err != nil {
		return nil, errBadSchema
	}
	pin := sha256.Sum256(spkiDER)
	certificate := map[string]any{
		"type": "grants-certificate-1", "certificate_id": plan["certificate_id"],
		"issuer":  map[string]any{"owner_mxid": ownerMXID, "key_id": "sha256:" + hex.EncodeToString(pin[:]), "purpose": "grants-owner-v1"},
		"subject": plan["subject"], "audience": plan["audience"],
		"not_before": plan["not_before"], "expires_at": plan["expires_at"],
		"supersedes": []any{}, "cycles": plan["cycles"],
		"entries": []any{
			map[string]any{"entry_id": "repo-create", "action": "repository.create", "target": map[string]any{"organization": plan["organization"], "name": plan["name"], "visibility": "private"}, "uses": createUses},
			map[string]any{"entry_id": "repo-delete", "action": "repository.delete", "target": map[string]any{"organization": plan["organization"], "name": plan["name"], "paired_create_entry": "repo-create"}, "uses": deleteUses},
		},
	}
	if local {
		certificate["type"] = "grants-local-certificate-1"
		hash := sha256.Sum256(requesterDER)
		certificate["requester_spki_sha256"] = hex.EncodeToString(hash[:])
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(certificate); err != nil {
		return nil, errBadSchema
	}
	// Encoder appends exactly one LF. The signed payload has none.
	payload := bytes.Clone(encoded.Bytes()[:encoded.Len()-1])
	if local {
		if _, err := parseLocalCertificateProjection(payload); err != nil {
			return nil, err
		}
	} else if _, err := parseCertificateProjection(payload); err != nil {
		return nil, err
	}
	digest, err := domainDigest(domain, payload)
	if err != nil {
		return nil, err
	}
	var display bytes.Buffer
	if err := json.Indent(&display, payload, "", "  "); err != nil {
		return nil, errBadEncoding
	}
	review := fmt.Sprintf("UNSIGNED certificate; no rights are active.\nDomain: swarma-grants/certificate/1\nSHA256(domain + LF + exact payload): %x\n%s\n", digest, display.Bytes())
	if local {
		text, err := localRepositoryReview(payload, digest, plan["organization"].(string), plan["name"].(string))
		if err != nil {
			return nil, err
		}
		review = "UNSIGNED certificate; no rights are active.\n" + text
	}
	return &UnsignedCertificate{Payload: payload, Digest: digest, Review: review}, nil
}
