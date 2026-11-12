#ifndef MAC_KEYVAULT_SECURITY_DARWIN_H
#define MAC_KEYVAULT_SECURITY_DARWIN_H

#include <stddef.h>

enum {
    MacKeyVaultUnknownError = -1,
    MacKeyVaultPublicKeyUnavailable = -2,
    MacKeyVaultFieldSeparator = 0x1f,
    MacKeyVaultRecordSeparator = 0x1e,
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
int MacKeyVaultRootQualificationCreate(unsigned char **reference, size_t *referenceLength,
    unsigned char **before, size_t *beforeLength, unsigned char **after, size_t *afterLength, int *outcome);
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
