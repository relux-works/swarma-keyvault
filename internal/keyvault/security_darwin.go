//go:build darwin && cgo

package keyvault

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "security_darwin.h"
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	_ "github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

// SecurityStore is the production Backend over the login keychain through the
// Security.framework cgo bridge in security_darwin.c.
type SecurityStore struct{}

// NewSecurityStore returns the login-keychain backend.
func NewSecurityStore() *SecurityStore {
	return &SecurityStore{}
}

func (s *SecurityStore) Create(opts CreateOptions) (Item, error) {
	label := C.CString(opts.Label)
	tag := C.CString(string(opts.Tag))
	defer C.free(unsafe.Pointer(label))
	defer C.free(unsafe.Pointer(tag))
	var point *C.uchar
	var pointLen C.size_t
	status := int(C.MacKeyVaultCreate(label, tag, cBool(opts.Store == StoreEnclave), cBool(opts.UserPresence), &point, &pointLen))
	if status != 0 {
		return Item{}, &StatusError{Op: "create", Status: status}
	}
	defer C.free(unsafe.Pointer(point))
	spki, err := spkiFromPoint(C.GoBytes(unsafe.Pointer(point), C.int(pointLen)))
	if err != nil {
		return Item{}, fmt.Errorf("create %s: %w", opts.Label, err)
	}
	return Item{Label: opts.Label, Tag: opts.Tag, SPKI: spki}, nil
}

func (s *SecurityStore) List() ([]Item, error) {
	prefix := C.CString(LabelPrefix)
	defer C.free(unsafe.Pointer(prefix))
	var out *C.char
	var outLen C.size_t
	status := int(C.MacKeyVaultList(prefix, &out, &outLen))
	if status != 0 {
		return nil, &StatusError{Op: "list", Status: status}
	}
	if out == nil {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(out))
	return parseListRecords(C.GoBytes(unsafe.Pointer(out), C.int(outLen)))
}

func (s *SecurityStore) Delete(label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	status := int(C.MacKeyVaultDelete(cLabel))
	if status == errSecItemNotFound {
		return ErrNotFound
	}
	if status != 0 {
		return &StatusError{Op: "delete", Status: status}
	}
	return nil
}

func cBool(v bool) C.int {
	if v {
		return 1
	}
	return 0
}

// parseListRecords decodes label US tag US pointStatus US point RS records.
// A key whose public point could not be read is still listed with an empty
// SPKI so the caller reports the fingerprint as unknown instead of hiding it.
func parseListRecords(raw []byte) ([]Item, error) {
	var keys []Item
	for _, record := range bytes.Split(raw, []byte{C.MacKeyVaultRecordSeparator}) {
		if len(record) == 0 {
			continue
		}
		fields := bytes.SplitN(record, []byte{C.MacKeyVaultFieldSeparator}, 4)
		if len(fields) != 4 {
			return nil, fmt.Errorf("list: malformed bridge record")
		}
		key := Item{Label: string(fields[0]), Tag: append([]byte(nil), fields[1]...)}
		if pointStatus, err := strconv.Atoi(string(fields[2])); err == nil && pointStatus == 0 {
			point, err := hex.DecodeString(string(fields[3]))
			if err != nil {
				return nil, fmt.Errorf("list %s: malformed public key hex", key.Label)
			}
			spki, err := spkiFromPoint(point)
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", key.Label, err)
			}
			key.SPKI = spki
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// UpdateTag replaces the application tag (the stored record) of the private
// half under label. ErrNotFound when no such key exists.
func (s *SecurityStore) UpdateTag(label string, tag []byte) error {
	cLabel := C.CString(label)
	cTag := C.CString(string(tag))
	defer C.free(unsafe.Pointer(cLabel))
	defer C.free(unsafe.Pointer(cTag))
	status := int(C.MacKeyVaultUpdateTag(cLabel, cTag))
	if status == errSecItemNotFound {
		return ErrNotFound
	}
	if status != 0 {
		return &StatusError{Op: "update", Status: status}
	}
	return nil
}

// Sign asks Security.framework for an ECDSA signature over digest with the
// private half under label (kSecKeyAlgorithmECDSASignatureDigestX962SHA256:
// the digest is signed as given, never re-hashed). The result is X9.62 DER
// as corecrypto emits it; low-S normalisation is the Manager's job.
func (s *SecurityStore) Sign(label string, digest []byte) ([]byte, error) {
	if len(digest) != DigestSize {
		// Belt and braces: the Manager gate runs first, but the bridge
		// never signs a mis-sized digest either.
		return nil, ValidateDigest(digest)
	}
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var out *C.uchar
	var outLen C.size_t
	status := int(C.MacKeyVaultSign(cLabel, (*C.uchar)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)), &out, &outLen))
	if status == errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		return nil, &StatusError{Op: "sign", Status: status}
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// Decrypt opens an ECIES envelope (cofactor, X9.63 SHA-256, AES-GCM,
// variable IV) with the private half under label. The C buffer that held the
// plaintext is zeroed before it is freed.
func (s *SecurityStore) Decrypt(label string, envelope []byte) ([]byte, error) {
	if len(envelope) == 0 {
		return nil, &StatusError{Op: "decrypt", Status: errSecParam}
	}
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var out *C.uchar
	var outLen C.size_t
	status := int(C.MacKeyVaultDecrypt(cLabel, (*C.uchar)(unsafe.Pointer(&envelope[0])), C.size_t(len(envelope)), &out, &outLen))
	if status == errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		return nil, &StatusError{Op: "decrypt", Status: status}
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outLen))
	plain := bytes.Clone(raw)
	clear(raw)
	C.free(unsafe.Pointer(out))
	return plain, nil
}

// DisableKeychainUI makes every later Keychain call of this process fail
// instead of raising a dialog.
func DisableKeychainUI() error {
	if status := int(C.MacKeyVaultDisableUI()); status != 0 {
		return &StatusError{Op: "disable keychain UI", Status: status}
	}
	return nil
}

// ExportProbe is the outcome of trying to pull private material out of a
// keychain item through both Security.framework export paths.
type ExportProbe struct {
	// RepresentationStatus is the SecKeyCopyExternalRepresentation error code.
	RepresentationStatus int
	// ExportStatus is the SecItemExport(kSecFormatWrappedPKCS8) OSStatus.
	ExportStatus int
	// LeakedBytes counts private bytes either path handed back; must be 0.
	LeakedBytes int
}

// ProbeExport attempts to export the private half under label and reports
// what Security.framework answered. It exists for the attestation tests; a
// zero status from either path means the key is extractable.
func (s *SecurityStore) ProbeExport(label string) (ExportProbe, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var rep, exp C.int
	var leaked C.size_t
	status := int(C.MacKeyVaultProbeExport(cLabel, &rep, &exp, &leaked))
	if status == errSecItemNotFound {
		return ExportProbe{}, ErrNotFound
	}
	if status != 0 {
		return ExportProbe{}, &StatusError{Op: "probe-export", Status: status}
	}
	return ExportProbe{RepresentationStatus: int(rep), ExportStatus: int(exp), LeakedBytes: int(leaked)}, nil
}

// ACLEntry is one entry of the legacy SecAccess installed on a private key.
type ACLEntry struct {
	Authorizations []string
	// AnyApplication is true when the entry trusts every application.
	AnyApplication bool
	// Applications lists the trusted binaries by path; empty with
	// AnyApplication false means no application is trusted (prompt always).
	Applications []string
}

// DescribeACL reads back the ACL of the private half under label.
func (s *SecurityStore) DescribeACL(label string) ([]ACLEntry, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var out *C.char
	var outLen C.size_t
	status := int(C.MacKeyVaultCopyACL(cLabel, &out, &outLen))
	if status == errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		return nil, &StatusError{Op: "describe-acl", Status: status}
	}
	defer C.free(unsafe.Pointer(out))
	return parseACLRecords(C.GoBytes(unsafe.Pointer(out), C.int(outLen))), nil
}

func parseACLRecords(raw []byte) []ACLEntry {
	var entries []ACLEntry
	for _, record := range bytes.Split(raw, []byte{C.MacKeyVaultRecordSeparator}) {
		if len(record) == 0 {
			continue
		}
		auths, apps, _ := bytes.Cut(record, []byte{'|'})
		entry := ACLEntry{}
		if len(auths) > 0 {
			entry.Authorizations = strings.Split(string(auths), ",")
		}
		switch {
		case string(apps) == "*":
			entry.AnyApplication = true
		case len(apps) > 0:
			entry.Applications = strings.Split(string(apps), ";")
		}
		entries = append(entries, entry)
	}
	return entries
}

// NostrSecurityStore is the dedicated signed-binary-only generic-password store.
// No method returns a private scalar, and there is no fallback backend.
type NostrSecurityStore struct{}

func NewNostrSecurityStore() *NostrSecurityStore { return &NostrSecurityStore{} }

func (*NostrSecurityStore) Create(request NostrRecord) (NostrRecord, error) {
	record, secret, err := newNostrMaterial(request)
	if err != nil {
		return NostrRecord{}, err
	}
	defer clear(secret)
	metadata, _ := json.Marshal(record)
	account := C.CString(record.Account())
	tag := C.CString(string(metadata))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(tag))
	status := int(C.MacKeyVaultNostrCreate(account, tag, (*C.uchar)(unsafe.Pointer(&secret[0]))))
	if status == -25299 {
		return NostrRecord{}, nostrRefuse("duplicate")
	}
	if status != 0 {
		return NostrRecord{}, &StatusError{Op: "nostr create", Status: status}
	}
	return record, nil
}

func (*NostrSecurityStore) List() ([]NostrRecord, error) {
	var raw *C.char
	var length C.size_t
	status := int(C.MacKeyVaultNostrList(&raw, &length))
	if status != 0 {
		return nil, &StatusError{Op: "nostr list", Status: status}
	}
	if raw == nil {
		return []NostrRecord{}, nil
	}
	defer C.free(unsafe.Pointer(raw))
	if length > 4*1024*1024 {
		return nil, nostrRefuse("invalid_record")
	}
	return parseNostrList(C.GoBytes(unsafe.Pointer(raw), C.int(length)))
}

func (*NostrSecurityStore) Sign(record NostrRecord, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, nostrRefuse("invalid_digest")
	}
	if err := validateNostrRecord(record); err != nil {
		return nil, err
	}
	metadata, _ := json.Marshal(record)
	account := C.CString(record.Account())
	tag := C.CString(string(metadata))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(tag))
	secret := make([]byte, 32)
	defer clear(secret)
	status := int(C.MacKeyVaultNostrRead(account, tag, (*C.uchar)(unsafe.Pointer(&secret[0]))))
	if status == errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		return nil, &StatusError{Op: "nostr sign", Status: status}
	}
	return signNostrSecret(record, secret, digest)
}
