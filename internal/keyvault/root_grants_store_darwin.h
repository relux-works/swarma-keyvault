#ifndef MAC_KEYVAULT_ROOT_GRANTS_STORE_DARWIN_H
#define MAC_KEYVAULT_ROOT_GRANTS_STORE_DARWIN_H

#include <stddef.h>

// Production root-grants item operations (root_grants_store_darwin.c). Go-visible
// header: no Security.framework types. Every function first resolves the ACL SPI
// and verifies the ACTUAL running vault before any Keychain query or value read.
// The only value read is a one-shot second phase on the exact item reference
// returned by ReadPrepare, after Go admits its actual ACL and public bindings. No
// function updates or deletes an item. The only mutation is one create-only
// SecItemAdd of an access object that Go has already admitted.

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
// earlier failure leaves it 0. A plan is one-shot: the first commit consumes it,
// and any further commit on it refuses without touching the Keychain. Close is
// mandatory on every path.
typedef struct MacKeyVaultRootGrantsAdd MacKeyVaultRootGrantsAdd;
int MacKeyVaultRootGrantsAddPrepare(MacKeyVaultRootGrantsAdd **plan, unsigned char **frame, size_t *frameLength);
int MacKeyVaultRootGrantsAddCommit(MacKeyVaultRootGrantsAdd *plan, const char *account, const char *metadata,
    const unsigned char *envelope, size_t envelopeLength, int *attempted);
void MacKeyVaultRootGrantsAddClose(MacKeyVaultRootGrantsAdd *plan);

// Metadata-only readback of exactly one item: its comment attribute and the full
// KVQP1 projection of its actual ACL. The item value is never requested.
int MacKeyVaultRootGrantsReadback(const char *account, unsigned char **metadata, size_t *metadataLength,
    unsigned char **frame, size_t *frameLength);

// Two-phase read of one exact stored root item. ReadPrepare queries only the
// exact account's attributes and item reference and returns canonical metadata
// plus the actual ACL projection; it never requests the item value. It returns
// 0, 1 for a startup/code refusal, or an OSStatus. ReadValue consumes the plan
// before its one SecKeychainItemCopyContent call and is only safe after the caller
// has admitted the returned ACL and checked its metadata/pair pins. The opaque
// plan retains that same SecKeychainItemRef from selection through value read.
// ReadValue returns 0, 1 for a startup/code refusal, or an OSStatus. ReadClose is
// mandatory on every successful prepare path. The returned value is the exact
// sealed envelope bytes; it is never decrypted here.
typedef struct MacKeyVaultRootGrantsRead MacKeyVaultRootGrantsRead;
int MacKeyVaultRootGrantsReadPrepare(const char *account, MacKeyVaultRootGrantsRead **plan,
    unsigned char **metadata, size_t *metadataLength, unsigned char **frame, size_t *frameLength);
int MacKeyVaultRootGrantsReadValue(MacKeyVaultRootGrantsRead *plan, unsigned char **value, size_t *valueLength);
void MacKeyVaultRootGrantsReadClose(MacKeyVaultRootGrantsRead *plan);

#endif
