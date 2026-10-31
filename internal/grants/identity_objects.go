package grants

import (
	"crypto/sha256"
	"strings"
)

// Public representation projections are never enrolled/trusted identities.
type issuerProjection struct{ ownerMXID, keyID, purpose string }
type subjectProjection struct {
	accountMXID, deviceID string
	deviceEd25519         [32]byte
	deviceFingerprint     [32]byte
}

func parseIssuerNode(node *wireValue) (*issuerProjection, error) {
	f, err := subobjectTexts(node, "owner_mxid", "key_id", "purpose")
	if err != nil {
		return nil, err
	}
	owner, err := parseMatrixAccountRepresentation(f["owner_mxid"])
	if err != nil {
		return nil, err
	}
	key := f["key_id"]
	if len(key) != 71 || !strings.HasPrefix(key, "sha256:") || f["purpose"] != "grants-owner-v1" {
		return nil, errBadSchema
	}
	if _, err := parseWireDigest(key[7:]); err != nil {
		return nil, err
	}
	return &issuerProjection{ownerMXID: owner, keyID: key, purpose: f["purpose"]}, nil
}
func parseSubjectNode(node *wireValue) (*subjectProjection, error) {
	f, err := subobjectTexts(node, "account_mxid", "device_id", "device_ed25519")
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
	public, err := parseDevicePublicBytes(f["device_ed25519"])
	if err != nil {
		return nil, err
	}
	return &subjectProjection{accountMXID: account, deviceID: device, deviceEd25519: public, deviceFingerprint: sha256.Sum256(public[:])}, nil
}
