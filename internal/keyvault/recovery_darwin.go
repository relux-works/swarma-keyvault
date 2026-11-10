//go:build darwin && cgo

package keyvault

/*
#include <stdlib.h>
#include "security_darwin.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"unsafe"
)

func verifyRecoveryCode(pid int, pin []byte) error {
	var pointer *C.uchar
	if len(pin) > 0 {
		pointer = (*C.uchar)(unsafe.Pointer(&pin[0]))
	}
	if status := int(C.MacKeyVaultRecoveryCode(C.int(pid), pointer, C.size_t(len(pin)))); status != 0 {
		refusal := recoveryRefuse("code_not_admitted").(*Refusal)
		refusal.Status = status
		return refusal
	}
	return nil
}

func recoveryNativeRows() ([]NostrRecord, []RecoveryRecord, error) {
	var raw *C.char
	var length C.size_t
	status := int(C.MacKeyVaultNostrList(&raw, &length))
	if status != 0 {
		return nil, nil, &StatusError{Op: "recovery metadata", Status: status}
	}
	if raw == nil {
		return []NostrRecord{}, []RecoveryRecord{}, nil
	}
	defer C.free(unsafe.Pointer(raw))
	if length > 4*1024*1024 {
		return nil, nil, recoveryRefuse("invalid_record")
	}
	return recoveryRows(C.GoBytes(unsafe.Pointer(raw), C.int(length)))
}

func (*NostrSecurityStore) RecoveryList() ([]RecoveryRecord, error) {
	_, groups, err := recoveryNativeRows()
	return groups, err
}

func (*NostrSecurityStore) RecoveryStore(r RecoveryRecord, encrypted []byte) error {
	if _, err := parseRecoveryCiphertext(encrypted, r); err != nil {
		return &RecoveryNotAppliedError{Err: err}
	}
	metadata, _ := json.Marshal(r)
	account := C.CString(r.Account())
	tag := C.CString(string(metadata))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(tag))
	var attempted C.int
	status := int(C.MacKeyVaultRecoveryCreate(account, tag, (*C.uchar)(unsafe.Pointer(&encrypted[0])), C.size_t(len(encrypted)), &attempted))
	return recoveryNativeMutationError("recovery create", status, attempted != 0)
}

func recoveryNativeRead(r RecoveryRecord) (recoveryCiphertext, error) {
	if validateRecoveryRecord(r) != nil {
		return recoveryCiphertext{}, recoveryRefuse("invalid_record")
	}
	metadata, _ := json.Marshal(r)
	account := C.CString(r.Account())
	tag := C.CString(string(metadata))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(tag))
	var raw *C.uchar
	var length C.size_t
	status := int(C.MacKeyVaultRecoveryRead(account, tag, &raw, &length))
	if status != 0 {
		return recoveryCiphertext{}, &StatusError{Op: "recovery read", Status: status}
	}
	if raw == nil {
		return recoveryCiphertext{}, recoveryRefuse("invalid_envelope")
	}
	defer C.free(unsafe.Pointer(raw))
	if length > recoveryMaxCiphertext {
		return recoveryCiphertext{}, recoveryRefuse("invalid_envelope")
	}
	return parseRecoveryCiphertext(C.GoBytes(unsafe.Pointer(raw), C.int(length)), r)
}

func (*NostrSecurityStore) RecoveryDelete(r RecoveryRecord) error {
	if validateRecoveryRecord(r) != nil {
		return &RecoveryNotAppliedError{Err: recoveryRefuse("invalid_record")}
	}
	metadata, _ := json.Marshal(r)
	return recoveryNativeDelete(r.Account(), metadata)
}

func (*NostrSecurityStore) NostrDelete(r NostrRecord) error {
	if validateNostrRecord(r) != nil || r.Storage != "keychain-acl" {
		return recoveryRefuse("invalid_record")
	}
	metadata, _ := json.Marshal(r)
	return recoveryNativeDelete(r.Account(), metadata)
}

func recoveryNativeDelete(accountText string, metadata []byte) error {
	account := C.CString(accountText)
	tag := C.CString(string(metadata))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(tag))
	var attempted C.int
	status := int(C.MacKeyVaultNostrDelete(account, tag, &attempted))
	return recoveryNativeMutationError("exact item deletion", status, attempted != 0)
}

func (s *NostrSecurityStore) signRecovery(record NostrRecord, digest []byte) ([]byte, error) {
	groups, err := s.RecoveryList()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		projected := g.NostrRecord()
		if projected.Account() != record.Account() {
			continue
		}
		a, _ := json.Marshal(projected)
		b, _ := json.Marshal(record)
		if !bytes.Equal(a, b) {
			return nil, recoveryRefuse("invalid_record")
		}
		envelope, err := recoveryNativeRead(g)
		if err != nil {
			return nil, err
		}
		plain, err := newRecoveryHelper().UnwrapNostr(envelope.Nostr)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		secret, err := recoveryNostrPlain(g, plain)
		if err != nil {
			return nil, err
		}
		return signNostrSecret(record, secret, digest)
	}
	return nil, ErrNotFound
}
