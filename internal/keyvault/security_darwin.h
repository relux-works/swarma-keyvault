#ifndef MAC_KEYVAULT_SECURITY_DARWIN_H
#define MAC_KEYVAULT_SECURITY_DARWIN_H

#include <stddef.h>

enum {
    MacKeyVaultUnknownError = -1,
    MacKeyVaultPublicKeyUnavailable = -2,
    MacKeyVaultFieldSeparator = 0x1f,
    MacKeyVaultRecordSeparator = 0x1e,
};

// Public failure-stage ids of the public-marker qualification create call. They are
// fixed integers reported next to the Security OSStatus of the failing step; they
// carry no item data. The values are a public contract: never renumber or reuse an
// id, only append. The KVQ_STAGE_PROJECT_* ids are internal to the projection and
// are always mapped to a BEFORE or AFTER id before they leave the create call;
// KVQ_STAGE_RESERVED is never reported.
enum {
    KVQ_STAGE_NONE = 0,
    KVQ_STAGE_RESOLVE = 1,
    KVQ_STAGE_SELF_CODE = 2,
    KVQ_STAGE_LOGIN_INTERACTION = 3,
    KVQ_STAGE_LOGIN_ACCOUNT_PATH = 4,
    KVQ_STAGE_LOGIN_OPEN = 5,
    KVQ_STAGE_LOGIN_PATH_CHECK = 6,
    KVQ_STAGE_LOGIN_STATUS = 7,
    KVQ_STAGE_LOGIN_LOCKED = 8,
    KVQ_STAGE_ACCESS_REQUIREMENT = 10,
    KVQ_STAGE_ACCESS_APPLICATION = 11,
    KVQ_STAGE_ACCESS_APPLICATION_EXACT = 12,
    KVQ_STAGE_ACCESS_CREATE = 13,
    KVQ_STAGE_ACCESS_ACL_LIST = 14,
    KVQ_STAGE_ACCESS_PARTITION_DESCRIPTION = 15,
    KVQ_STAGE_ACCESS_ACL_WALK = 16,
    KVQ_STAGE_ACCESS_PARTITION_ACL = 17,
    KVQ_STAGE_BIND_ACL_LIST = 20,
    KVQ_STAGE_BIND_ACL_READ = 21,
    KVQ_STAGE_BIND_RELEASE_COUNT = 22,
    KVQ_STAGE_BIND_RELEASE_REQUIREMENT_READ = 23,
    KVQ_STAGE_BIND_RELEASE_REQUIREMENT_DIFFERS = 24,
    KVQ_STAGE_BIND_PARTITION = 25,
    KVQ_STAGE_BIND_COUNTS = 26,
    KVQ_STAGE_BEFORE_OWNER_ACL = 30,
    KVQ_STAGE_BEFORE_ACL_AUTHORIZATIONS = 31,
    KVQ_STAGE_BEFORE_ACL_CONTENTS = 32,
    KVQ_STAGE_BEFORE_ACL_RAW_CONTENTS = 33,
    KVQ_STAGE_BEFORE_ACL_APPLICATIONS = 34,
    KVQ_STAGE_BEFORE_COPY = 35,
    KVQ_STAGE_ADD_PREPARE = 40,
    KVQ_STAGE_ADD = 41,
    KVQ_STAGE_READBACK_REFERENCE = 42,
    KVQ_STAGE_READBACK_FIND = 43,
    KVQ_STAGE_READBACK_MARKER = 44,
    KVQ_STAGE_READBACK_ACCESS = 45,
    KVQ_STAGE_READBACK_COPY = 46,
    KVQ_STAGE_AFTER_OWNER_ACL = 50,
    KVQ_STAGE_AFTER_ACL_AUTHORIZATIONS = 51,
    KVQ_STAGE_AFTER_ACL_CONTENTS = 52,
    KVQ_STAGE_AFTER_ACL_RAW_CONTENTS = 53,
    KVQ_STAGE_AFTER_ACL_APPLICATIONS = 54,
    KVQ_STAGE_PROJECT_OWNER_ACL = 70,
    KVQ_STAGE_PROJECT_AUTHORIZATIONS = 71,
    KVQ_STAGE_PROJECT_CONTENTS = 72,
    KVQ_STAGE_PROJECT_RAW_CONTENTS = 73,
    KVQ_STAGE_PROJECT_APPLICATIONS = 74,
    KVQ_STAGE_RESERVED = 99,
};

int MacKeyVaultCreate(const char *label, const char *tag, int enclave, int userPresence,
                      unsigned char **outPub, size_t *outPubLen);
int MacKeyVaultList(const char *prefix, char **out, size_t *outLen);
int MacKeyVaultDelete(const char *label);
int MacKeyVaultUpdateTag(const char *label, const char *tag);
int MacKeyVaultProbeExport(const char *label, int *repStatus, int *exportStatus, size_t *leaked);
int MacKeyVaultSign(const char *label, const unsigned char *digest, size_t digestLen,
                    unsigned char **out, size_t *outLen);
int MacKeyVaultCopyACL(const char *label, char **out, size_t *outLen);
int MacKeyVaultDecrypt(const char *label, const unsigned char *in, size_t inLen,
                       unsigned char **out, size_t *outLen);
int MacKeyVaultDisableUI(void);

// Dedicated Nostr generic-password records; metadata calls never request data.
int MacKeyVaultNostrCreate(const char *account, const char *metadata, const unsigned char *secret);
int MacKeyVaultNostrList(char **out, size_t *outLen);
int MacKeyVaultNostrRead(const char *account, const char *metadata, unsigned char *secret);
int MacKeyVaultRecoveryCreate(const char *account, const char *metadata, const unsigned char *data, size_t length, int *mutationAttempted);
int MacKeyVaultRecoveryRead(const char *account, const char *metadata, unsigned char **out, size_t *length);
int MacKeyVaultNostrDelete(const char *account, const char *metadata, int *mutationAttempted);
int MacKeyVaultRecoveryCode(int pid, const unsigned char *expectedHash, size_t hashLength);

// Fixed public-marker qualification only; result1 denied,2 access,3 unknown.
// No raw Keychain value/status or caller-selected namespace is returned.
int MacKeyVaultRootQualificationRead(int role, const unsigned char *reference, size_t length, int *result);
int MacKeyVaultRootQualificationCode(int role, int pid, const unsigned char *hash, size_t length);
int MacKeyVaultRootQualificationSnapshot(const unsigned char *reference, size_t length, unsigned char **out, size_t *outLength);
// stage and osStatus report the first failing step (KVQ_STAGE_*) and its Security
// OSStatus; both are zero on success. They never change outcome or the return value.
int MacKeyVaultRootQualificationCreate(unsigned char **reference, size_t *referenceLength,
    unsigned char **before, size_t *beforeLength, unsigned char **after, size_t *afterLength, int *outcome,
    int *stage, int *osStatus);
int MacKeyVaultRootQualificationDelete(const unsigned char *reference, size_t referenceLength,
    const unsigned char *expectedProjectionSHA256, size_t digestLength, int *outcome);

// Private finite paired-item adoption bridge; no public dispatcher or consent.
// Inspect owns one process-local snapshot. Apply consumes it once; Close is
// mandatory on every path. Results: 0 verified, 1 pre-mutation refusal, 2 UNKNOWN.
typedef struct MacKeyVaultRecoveryAdoption MacKeyVaultRecoveryAdoption;
int MacKeyVaultRecoveryAdoptionInspect(const char *account, const unsigned char *metadata, size_t metadataLength,
    const unsigned char *sealed, size_t sealedLength, const unsigned char *persistent, size_t persistentLength,
    const char *oldPath, const unsigned char *oldHash, size_t oldHashLength, const char *newPath, const unsigned char *newHash, size_t newHashLength,
    MacKeyVaultRecoveryAdoption **out, unsigned char **frame, size_t *frameLength);
int MacKeyVaultRecoveryAdoptionApply(MacKeyVaultRecoveryAdoption *plan, const unsigned char *reviewedFrame, size_t reviewedLength, int *mutationAttempted);
void MacKeyVaultRecoveryAdoptionClose(MacKeyVaultRecoveryAdoption *plan);

#endif

// Finite recovery hardening representation; no root-item authority.
int MacKeyVaultRecoveryCodeFlags(unsigned int flags);
