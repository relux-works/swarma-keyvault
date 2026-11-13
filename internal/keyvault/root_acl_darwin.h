#ifndef MAC_KEYVAULT_ROOT_ACL_DARWIN_H
#define MAC_KEYVAULT_ROOT_ACL_DARWIN_H

// Shared root-item ACL unit (root_acl_darwin.c). Native-only header: it exposes
// Security.framework types and is never included by a Go cgo preamble.
#include "security_darwin.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stddef.h>

// Signatures are from the source-pinned Security SecTrustedApplicationPriv.h.
// Both symbols must exist BEFORE any Keychain query, even for a read control.
typedef OSStatus (*KVQCreateRequirement)(const char *, SecRequirementRef, SecTrustedApplicationRef *);
typedef OSStatus (*KVQCopyRequirement)(SecTrustedApplicationRef, SecRequirementRef *);
typedef struct { KVQCreateRequirement create; KVQCopyRequirement copy; } KVQSymbols;

// Both SPI symbols must resolve BEFORE any Keychain query (1 = resolved).
int KVQResolve(KVQSymbols *out);
// Fixed role -> code identifier (1 vault, 2 helper, 4 foreign); NULL for any other.
const char *KVQRole(int role);
// Checks the ACTUAL running code (pid 0, role 1 only) or one live child against
// the fixed full certificate policy and, when hashLength != 0, its CDHash.
OSStatus KVQCode(int role, int pid, const unsigned char *expectedHash, size_t hashLength);
OSStatus KVQSelf(int role);
// Opens the OS account's login keychain with user interaction disabled.
OSStatus KVQLogin(SecKeychainRef *out);
// Complete public KVQP1 projection of an access object (owner, every ACL).
OSStatus KVQProject(SecAccessRef access, KVQSymbols symbols, CFDataRef *out);
// The single root-item access constructor: sole trusted application is the fixed
// vault requirement, plus the exact partition ACL. Fails closed on any deviation.
// descriptor (the access name shown in system dialogs, also the description of the
// projected ACLs) and applicationLabel are fixed strings owned by each caller.
OSStatus KVQIntendedAccess(KVQSymbols symbols, const char *descriptor, const char *applicationLabel, SecAccessRef *out);

// Failure diagnostics of the functions of this unit (stage ids: security_darwin.h).
// The FIRST failure recorded on the calling thread wins; later statuses never
// overwrite it. One cgo call runs on one thread, so a caller resets before its
// first step and takes the record before it returns. The record holds a stage id
// and the Security OSStatus only; it never carries item data.
void KVQDiagReset(void);
void KVQDiagNote(int stage, OSStatus status);
// Returns 1 and the recorded failure, or 0 when nothing failed.
int KVQDiagTake(int *stage, OSStatus *status);
// Maps a recorded KVQ_STAGE_PROJECT_* id to the id family starting at base
// (KVQ_STAGE_BEFORE_OWNER_ACL or KVQ_STAGE_AFTER_OWNER_ACL); any other id is kept.
void KVQDiagRetagProjection(int base);

#endif
