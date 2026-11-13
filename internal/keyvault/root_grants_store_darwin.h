#ifndef MAC_KEYVAULT_ROOT_GRANTS_STORE_DARWIN_H
#define MAC_KEYVAULT_ROOT_GRANTS_STORE_DARWIN_H

#include <stddef.h>

// Production root-grants item operations (root_grants_store_darwin.c). Go-visible
// header: no Security.framework types. Every function first resolves the ACL SPI
// and verifies the ACTUAL running vault before any Keychain query. No function
// reads an item VALUE, updates or deletes an item. The only mutation is one
// create-only SecItemAdd of an access object that Go has already admitted.

// Fixed namespace literal; a Go test compares it with RootGrantsNamespace.
const char *MacKeyVaultRootGrantsNamespace(void);

// SPI symbols plus the running vault code check; no Keychain access. 0 = admitted.
int MacKeyVaultRootGrantsStartup(void);

// Attribute-only inventories. Row framing is the existing recovery one:
// account 0x1f metadata 0x1e, repeated. *out may be NULL for an empty inventory.
// Return 0 or an OSStatus. The pair list is the existing paired-record namespace.
int MacKeyVaultRootGrantsPairList(char **out, size_t *outLength);
int MacKeyVaultRootGrantsList(char **out, size_t *outLength);

// Two-phase create-only add. Prepare builds the intended access object with the
// shared constructor and returns its public KVQP1 projection; Commit adds the
// item with exactly THAT object, so the admitted object is the added object.
// Prepare returns 0, 1 (running code or SPI not admitted), 2 (access object could
// not be built/projected) or 3 (allocation/argument). Commit returns 0 or an
// OSStatus and sets *attempted immediately before the single SecItemAdd; every
// earlier failure leaves it 0. Close is mandatory on every path.
typedef struct MacKeyVaultRootGrantsAdd MacKeyVaultRootGrantsAdd;
int MacKeyVaultRootGrantsAddPrepare(MacKeyVaultRootGrantsAdd **plan, unsigned char **frame, size_t *frameLength);
int MacKeyVaultRootGrantsAddCommit(MacKeyVaultRootGrantsAdd *plan, const char *account, const char *metadata,
    const unsigned char *envelope, size_t envelopeLength, int *attempted);
void MacKeyVaultRootGrantsAddClose(MacKeyVaultRootGrantsAdd *plan);

// Metadata-only readback of exactly one item: its comment attribute and the full
// KVQP1 projection of its actual ACL. The item value is never requested.
int MacKeyVaultRootGrantsReadback(const char *account, unsigned char **metadata, size_t *metadataLength,
    unsigned char **frame, size_t *frameLength);

#endif
