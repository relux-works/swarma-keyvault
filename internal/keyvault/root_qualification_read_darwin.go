//go:build darwin && cgo

package keyvault

/*
#include "security_darwin.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"unsafe"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// RootQualificationCode checks the actual running parent/child, fixed full
// certificate policy and independently observed artifact CDHash. It performs
// no Keychain lookup and accepts no caller-selected requirement expression.
func RootQualificationCode(role codesignpolicy.Role, pid int, pin string) error {
	if pid < 0 || int64(pid) > 2147483647 {
		return rootqualification.ErrReceipt
	}
	if !((pid == 0 && role == codesignpolicy.Vault) || (pid > 0 && (role == codesignpolicy.Helper || role == codesignpolicy.Qualification))) {
		return rootqualification.ErrReceipt
	}
	b, err := hex.DecodeString(pin)
	if err != nil || (len(b) != 20 && len(b) != 32) || hex.EncodeToString(b) != pin {
		return rootqualification.ErrReceipt
	}
	if C.MacKeyVaultRootQualificationCode(C.int(role), C.int(pid), (*C.uchar)(unsafe.Pointer(&b[0])), C.size_t(len(b))) != 0 {
		return rootqualification.ErrReceipt
	}
	return nil
}

// RootQualificationMarkerRead runs only the fixed public test-item control.
// A well-formed native startup/metadata failure is Unqualified, never an ACL
// refusal. Only actual native marker-read denial can produce AccessRefused.
// This neither creates an item nor supplies an owning-vault cleanup interface.
func RootQualificationMarkerRead(role codesignpolicy.Role, request rootqualification.Request) (rootqualification.Result, error) {
	if role != codesignpolicy.Vault && role != codesignpolicy.Helper && role != codesignpolicy.Qualification {
		return rootqualification.Unqualified, rootqualification.ErrProtocol
	}
	reference := request.Reference()
	defer clear(reference)
	if len(reference) < 1 || len(reference) > rootqualification.MaxReference {
		return rootqualification.Unqualified, rootqualification.ErrProtocol
	}
	var result C.int = 3
	if C.MacKeyVaultRootQualificationRead(C.int(role), (*C.uchar)(unsafe.Pointer(&reference[0])), C.size_t(len(reference)), &result) != 0 {
		return rootqualification.Unqualified, nil
	}
	switch result {
	case 1:
		return rootqualification.AccessRefused, nil
	case 2:
		return rootqualification.UnexpectedAccess, nil
	default:
		return rootqualification.Unqualified, nil
	}
}

// RootQualificationSnapshot reads only the fixed marker item as the actual
// owning vault. A decoded observation is never a root-storage allowlist.
func RootQualificationSnapshot(request rootqualification.Request) (rootqualification.Projection, error) {
	reference := request.Reference()
	defer clear(reference)
	if len(reference) < 1 || len(reference) > rootqualification.MaxReference {
		return rootqualification.Projection{}, rootqualification.ErrProtocol
	}
	var raw *C.uchar
	var size C.size_t
	status := C.MacKeyVaultRootQualificationSnapshot((*C.uchar)(unsafe.Pointer(&reference[0])), C.size_t(len(reference)), &raw, &size)
	if raw != nil {
		defer C.free(unsafe.Pointer(raw))
	}
	if status != 0 || raw == nil || size < 1 || size > 1048576 {
		return rootqualification.Projection{}, rootqualification.ErrProjection
	}
	return rootqualification.DecodeNativeProjection(C.GoBytes(unsafe.Pointer(raw), C.int(size)))
}

// RootQualificationCreate consumes one real receipt reservation before the
// actual fixed-certificate owning-vault create-only native operation.
func RootQualificationCreate(reservation *rootqualification.CreationReservation) (rootqualification.NativeCreation, error) {
	result := rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused}
	if err := reservation.ConsumeForNativeCreate(); err != nil {
		return result, err
	}
	var reference, before, after *C.uchar
	var referenceSize, beforeSize, afterSize C.size_t
	var outcome C.int = 3
	var stage, osStatus C.int
	status := C.MacKeyVaultRootQualificationCreate(&reference, &referenceSize, &before, &beforeSize, &after, &afterSize, &outcome, &stage, &osStatus)
	for _, p := range []*C.uchar{reference, before, after} {
		if p != nil {
			defer C.free(unsafe.Pointer(p))
		}
	}
	if outcome == 1 {
		result.Outcome = rootqualification.CreationRefused
	} else {
		result.Outcome = rootqualification.CreationUnknown
	}
	// The first failing step and its OSStatus are public diagnostics only: they are
	// admitted through the closed stage table and never change Outcome or the error.
	result.Diagnostic = rootqualification.DiagnosticFromNative(int(stage), int(osStatus))
	if referenceSize > 16384 || beforeSize > 1048576 || afterSize > 1048576 || (referenceSize > 0 && reference == nil) || (beforeSize > 0 && before == nil) || (afterSize > 0 && after == nil) {
		return result, rootqualification.ErrProjection
	}
	if referenceSize > 0 {
		result.Reference = C.GoBytes(unsafe.Pointer(reference), C.int(referenceSize))
	}
	if beforeSize > 0 {
		raw := C.GoBytes(unsafe.Pointer(before), C.int(beforeSize))
		h := sha256.Sum256(raw)
		result.BeforeSHA256 = hex.EncodeToString(h[:])
		p, err := rootqualification.DecodeNativeProjection(raw)
		if err != nil {
			return result, err
		}
		result.Before = &p
	}
	if afterSize > 0 {
		raw := C.GoBytes(unsafe.Pointer(after), C.int(afterSize))
		h := sha256.Sum256(raw)
		result.AfterSHA256 = hex.EncodeToString(h[:])
		p, err := rootqualification.DecodeNativeProjection(raw)
		if err != nil {
			return result, err
		}
		result.After = &p
	}
	if status == 0 && outcome == 2 && len(result.Reference) > 0 && result.Before != nil && result.After != nil {
		result.Outcome = rootqualification.CreationReadback
		return result, nil
	}
	return result, rootqualification.ErrProjection
}

// RootQualificationDelete consumes only a reserved, independently pinned
// original test-item receipt. The native boundary rechecks the full current
// raw ACL projection and exact public marker immediately before one delete.
func RootQualificationDelete(reservation *rootqualification.CleanupReservation) (rootqualification.CleanupOutcome, error) {
	request, expected, err := reservation.ConsumeForNativeDelete()
	if err != nil {
		return rootqualification.CleanupRefused, err
	}
	defer request.Clear()
	reference := request.Reference()
	defer clear(reference)
	digest, err := hex.DecodeString(expected)
	if err != nil || len(digest) != 32 || len(reference) < 1 || len(reference) > 16384 {
		return rootqualification.CleanupRefused, rootqualification.ErrReceipt
	}
	var outcome C.int = 3
	status := C.MacKeyVaultRootQualificationDelete((*C.uchar)(unsafe.Pointer(&reference[0])), C.size_t(len(reference)), (*C.uchar)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)), &outcome)
	if status == 0 && outcome == 2 {
		return rootqualification.CleanupDeleted, nil
	}
	if outcome == 1 {
		return rootqualification.CleanupRefused, rootqualification.ErrReceipt
	}
	return rootqualification.CleanupUnknown, rootqualification.ErrReceipt
}

// nativeStageIDs returns the id compiled into the native unit for every reported
// stage. A test compares it with the Go table, so a stage id cannot drift or shift
// by one between the two without a failing test.
func nativeStageIDs() map[rootqualification.Stage]int {
	return map[rootqualification.Stage]int{
		rootqualification.StageResolve:                       int(C.KVQ_STAGE_RESOLVE),
		rootqualification.StageSelfCode:                      int(C.KVQ_STAGE_SELF_CODE),
		rootqualification.StageLoginInteraction:              int(C.KVQ_STAGE_LOGIN_INTERACTION),
		rootqualification.StageLoginAccountPath:              int(C.KVQ_STAGE_LOGIN_ACCOUNT_PATH),
		rootqualification.StageLoginOpen:                     int(C.KVQ_STAGE_LOGIN_OPEN),
		rootqualification.StageLoginPathCheck:                int(C.KVQ_STAGE_LOGIN_PATH_CHECK),
		rootqualification.StageLoginStatus:                   int(C.KVQ_STAGE_LOGIN_STATUS),
		rootqualification.StageLoginLocked:                   int(C.KVQ_STAGE_LOGIN_LOCKED),
		rootqualification.StageAccessRequirement:             int(C.KVQ_STAGE_ACCESS_REQUIREMENT),
		rootqualification.StageAccessApplication:             int(C.KVQ_STAGE_ACCESS_APPLICATION),
		rootqualification.StageAccessApplicationExact:        int(C.KVQ_STAGE_ACCESS_APPLICATION_EXACT),
		rootqualification.StageAccessCreate:                  int(C.KVQ_STAGE_ACCESS_CREATE),
		rootqualification.StageAccessACLList:                 int(C.KVQ_STAGE_ACCESS_ACL_LIST),
		rootqualification.StageAccessPartitionDescription:    int(C.KVQ_STAGE_ACCESS_PARTITION_DESCRIPTION),
		rootqualification.StageAccessACLWalk:                 int(C.KVQ_STAGE_ACCESS_ACL_WALK),
		rootqualification.StageAccessPartitionACL:            int(C.KVQ_STAGE_ACCESS_PARTITION_ACL),
		rootqualification.StageBindACLList:                   int(C.KVQ_STAGE_BIND_ACL_LIST),
		rootqualification.StageBindACLRead:                   int(C.KVQ_STAGE_BIND_ACL_READ),
		rootqualification.StageBindReleaseCount:              int(C.KVQ_STAGE_BIND_RELEASE_COUNT),
		rootqualification.StageBindReleaseRequirementRead:    int(C.KVQ_STAGE_BIND_RELEASE_REQUIREMENT_READ),
		rootqualification.StageBindReleaseRequirementDiffers: int(C.KVQ_STAGE_BIND_RELEASE_REQUIREMENT_DIFFERS),
		rootqualification.StageBindPartition:                 int(C.KVQ_STAGE_BIND_PARTITION),
		rootqualification.StageBindCounts:                    int(C.KVQ_STAGE_BIND_COUNTS),
		rootqualification.StageBeforeOwnerACL:                int(C.KVQ_STAGE_BEFORE_OWNER_ACL),
		rootqualification.StageBeforeACLAuthorizations:       int(C.KVQ_STAGE_BEFORE_ACL_AUTHORIZATIONS),
		rootqualification.StageBeforeACLContents:             int(C.KVQ_STAGE_BEFORE_ACL_CONTENTS),
		rootqualification.StageBeforeACLRawContents:          int(C.KVQ_STAGE_BEFORE_ACL_RAW_CONTENTS),
		rootqualification.StageBeforeACLApplications:         int(C.KVQ_STAGE_BEFORE_ACL_APPLICATIONS),
		rootqualification.StageBeforeCopy:                    int(C.KVQ_STAGE_BEFORE_COPY),
		rootqualification.StageAddPrepare:                    int(C.KVQ_STAGE_ADD_PREPARE),
		rootqualification.StageAdd:                           int(C.KVQ_STAGE_ADD),
		rootqualification.StageReadbackRef:                   int(C.KVQ_STAGE_READBACK_REFERENCE),
		rootqualification.StageReadbackFind:                  int(C.KVQ_STAGE_READBACK_FIND),
		rootqualification.StageReadbackMarker:                int(C.KVQ_STAGE_READBACK_MARKER),
		rootqualification.StageReadbackAccess:                int(C.KVQ_STAGE_READBACK_ACCESS),
		rootqualification.StageReadbackCopy:                  int(C.KVQ_STAGE_READBACK_COPY),
		rootqualification.StageAfterOwnerACL:                 int(C.KVQ_STAGE_AFTER_OWNER_ACL),
		rootqualification.StageAfterACLAuth:                  int(C.KVQ_STAGE_AFTER_ACL_AUTHORIZATIONS),
		rootqualification.StageAfterACLContents:              int(C.KVQ_STAGE_AFTER_ACL_CONTENTS),
		rootqualification.StageAfterACLRaw:                   int(C.KVQ_STAGE_AFTER_ACL_RAW_CONTENTS),
		rootqualification.StageAfterACLApps:                  int(C.KVQ_STAGE_AFTER_ACL_APPLICATIONS),
	}
}
