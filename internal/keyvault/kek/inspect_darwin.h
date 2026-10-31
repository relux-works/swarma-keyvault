#ifndef MAC_KEYVAULT_KEK_INSPECT_H
#define MAC_KEYVAULT_KEK_INSPECT_H

typedef struct {
    int valid;
    int status;
    char cdhash[41];
    char identifier[256];
    char certificateSHA1[41];
    unsigned int flags;
    int getTaskAllow;
} KekCode;

int KekInspectPeer(int fd, KekCode *out);
int KekInspectFile(const char *path, KekCode *out);

#endif
