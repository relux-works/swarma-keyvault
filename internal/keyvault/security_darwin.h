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

#endif
