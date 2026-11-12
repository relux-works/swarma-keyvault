package rootqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrReceipt = errors.New("public qualification receipt refused")

// ValidateReceiptDigest checks public syntax only, never owner consent,
// receipt existence or native item authority.
func ValidateReceiptDigest(digest string) error {
	if !validSHA256(digest) {
		return ErrReceipt
	}
	return nil
}

// Candidate records independently observed actual artifacts. Parsing these
// public fields is not signature verification or build/source admission.
type Candidate struct {
	SourceHead string   `json:"source_head"`
	SourceTree string   `json:"source_tree"`
	Vault      Artifact `json:"vault"`
	Helper     Artifact `json:"helper"`
	Foreign    Artifact `json:"foreign"`
}
type Artifact struct {
	SHA256 string `json:"sha256"`
	CDHash string `json:"cdhash"`
}

func lowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c Candidate) Validate() error {
	if !lowerHex(c.SourceHead, 40) || !lowerHex(c.SourceTree, 40) {
		return ErrReceipt
	}
	for _, a := range []Artifact{c.Vault, c.Helper, c.Foreign} {
		if !validSHA256(a.SHA256) || !(lowerHex(a.CDHash, 40) || lowerHex(a.CDHash, 64)) {
			return ErrReceipt
		}
	}
	if c.Vault.SHA256 == c.Helper.SHA256 || c.Vault.SHA256 == c.Foreign.SHA256 || c.Helper.SHA256 == c.Foreign.SHA256 || c.Vault.CDHash == c.Helper.CDHash || c.Vault.CDHash == c.Foreign.CDHash || c.Helper.CDHash == c.Foreign.CDHash {
		return ErrReceipt
	}
	return nil
}

// PendingIdentity binds the original immutable reservation and dedicated
// directory across processes. An equal-content replacement is not the same
// reservation. Native item identity remains the actual persistent reference.
type PendingIdentity struct {
	DirectoryDevice uint64 `json:"directory_device"`
	DirectoryInode  uint64 `json:"directory_inode"`
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	UID             uint32 `json:"uid"`
	GID             uint32 `json:"gid"`
	SHA256          string `json:"sha256"`
}

type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type creationRecord struct {
	Schema              string          `json:"schema"`
	State               string          `json:"state"`
	UTC                 string          `json:"utc"`
	Namespace           string          `json:"namespace"`
	Account             string          `json:"account"`
	ItemClass           string          `json:"item_class"`
	MarkerSHA256        string          `json:"marker_sha256"`
	Candidate           Candidate       `json:"candidate"`
	ReservationID       string          `json:"reservation_id"`
	Pending             PendingIdentity `json:"pending"`
	CreatedIdentity     FileIdentity    `json:"created_identity"`
	PersistentReference string          `json:"persistent_reference"`
	Before              *Projection     `json:"before"`
	BeforeSHA256        string          `json:"before_sha256"`
	After               *Projection     `json:"after"`
	AfterSHA256         string          `json:"after_sha256"`
}

func markerSHA256() string { h := sha256.Sum256([]byte(PublicMarker)); return hex.EncodeToString(h[:]) }
func canonicalRecord(r creationRecord) ([]byte, error) {
	if validateRecord(r) != nil {
		return nil, ErrReceipt
	}
	b, err := json.Marshal(r)
	if err != nil || len(b)+1 > 1048576 {
		return nil, ErrReceipt
	}
	return append(b, '\n'), nil
}
func validateRecord(r creationRecord) error {
	t, err := time.Parse(time.RFC3339Nano, r.UTC)
	if err != nil || t.IsZero() || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != r.UTC {
		return ErrReceipt
	}
	if r.Schema != "keyvault-root-acl-qualification-created/1" || r.Namespace != Namespace || r.Account != Account || r.ItemClass != ItemClass || r.MarkerSHA256 != markerSHA256() || r.Candidate.Validate() != nil || !lowerHex(r.ReservationID, 32) || r.Pending.DirectoryInode == 0 || r.Pending.Inode == 0 || !validSHA256(r.Pending.SHA256) || r.CreatedIdentity.Inode == 0 || r.CreatedIdentity.UID != r.Pending.UID || r.CreatedIdentity.GID != r.Pending.GID {
		return ErrReceipt
	}
	if r.State != "created" && r.State != "refused" && r.State != "unknown" {
		return ErrReceipt
	}
	ref, err := base64.StdEncoding.Strict().DecodeString(r.PersistentReference)
	defer clear(ref)
	if err != nil || len(ref) > MaxReference || base64.StdEncoding.EncodeToString(ref) != r.PersistentReference {
		return ErrReceipt
	}
	for _, p := range []struct {
		projection *Projection
		digest     string
	}{{r.Before, r.BeforeSHA256}, {r.After, r.AfterSHA256}} {
		if p.projection == nil {
			// An unknown attempt may retain a raw-frame fingerprint whose
			// projection could not be decoded. It remains audit only.
			if p.digest != "" && (r.State != "unknown" || !validSHA256(p.digest)) {
				return ErrReceipt
			}
			continue
		}
		digest, err := ProjectionSHA256(*p.projection)
		if err != nil || digest != p.digest {
			return ErrReceipt
		}
		// Receipts carry the actual decoder's complete representation. Reject
		// JSON null lists in place of its explicit empty lists; native NULL
		// application subjects remain represented by ApplicationsState.
		frame, err := EncodeNativeProjection(*p.projection)
		if err != nil {
			return ErrReceipt
		}
		decoded, err := DecodeNativeProjection(frame)
		if err != nil {
			return ErrReceipt
		}
		observed, _ := json.Marshal(p.projection)
		normalized, _ := json.Marshal(decoded)
		if !bytes.Equal(observed, normalized) {
			return ErrReceipt
		}
	}
	if r.State == "created" && (len(ref) == 0 || r.Before == nil || r.After == nil) {
		return ErrReceipt
	}
	if r.State == "refused" && (len(ref) > 0 || r.After != nil) {
		return ErrReceipt
	}
	return nil
}

// decodeRecord accepts the complete closed canonical file, including LF.
// Exact equality rejects missing/extra/duplicate fields, aliases, alternate
// base64, NULL/empty normalization, reordering and uncommitted whitespace.
func decodeRecord(raw []byte) (creationRecord, error) {
	var r creationRecord
	if len(raw) < 1 || len(raw) > 1048576 || json.Unmarshal(raw, &r) != nil {
		return creationRecord{}, ErrReceipt
	}
	want, err := canonicalRecord(r)
	if err != nil || !bytes.Equal(raw, want) {
		return creationRecord{}, ErrReceipt
	}
	return r, nil
}

func recordFromNative(utc time.Time, candidate Candidate, reservation string, pending PendingIdentity, n NativeCreation, created FileIdentity) (creationRecord, error) {
	state := "unknown"
	switch n.Outcome {
	case CreationReadback:
		state = "created"
	case CreationRefused:
		state = "refused"
	case CreationUnknown:
	default:
		return creationRecord{}, ErrReceipt
	}
	r := creationRecord{Schema: "keyvault-root-acl-qualification-created/1", State: state, UTC: utc.UTC().Format(time.RFC3339Nano), Namespace: Namespace, Account: Account, ItemClass: ItemClass, MarkerSHA256: markerSHA256(), Candidate: candidate, ReservationID: reservation, Pending: pending, CreatedIdentity: created, PersistentReference: base64.StdEncoding.EncodeToString(n.Reference), Before: n.Before, BeforeSHA256: n.BeforeSHA256, After: n.After, AfterSHA256: n.AfterSHA256}
	if validateRecord(r) != nil {
		return creationRecord{}, ErrReceipt
	}
	return r, nil
}

func requestFromRecord(r creationRecord, digest string) (Request, error) {
	if r.State != "created" || validateRecord(r) != nil || !validSHA256(digest) {
		return Request{}, ErrReceipt
	}
	ref, err := base64.StdEncoding.Strict().DecodeString(r.PersistentReference)
	defer clear(ref)
	if err != nil {
		return Request{}, ErrReceipt
	}
	return NewRequest(ref, digest)
}
