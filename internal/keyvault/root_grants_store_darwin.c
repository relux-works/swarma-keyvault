#include "root_grants_store_darwin.h"
#include "root_acl_darwin.h"
#include "security_darwin.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// The file-based Keychain ACL API is intentionally the supported mechanism.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Keep this literal in agreement with RootGrantsNamespace in root_grants_record.go.
static const char *KVRGNamespace = "works.relux.mac-keyvault.root-grants.v1";

struct MacKeyVaultRootGrantsAdd { SecAccessRef access; };

const char *MacKeyVaultRootGrantsNamespace(void) { return KVRGNamespace; }

// Note 55: both SPI symbols resolve and the ACTUAL running vault is verified
// BEFORE any Keychain query of the root operation. The access object, the code
// check and the projection come from the same shared unit as the public-marker
// qualification lane.
static int KVRGStartup(KVQSymbols *symbols) {
    return KVQResolve(symbols) && KVQSelf(1) == errSecSuccess;
}

int MacKeyVaultRootGrantsStartup(void) {
    KVQSymbols symbols = {0};
    return KVRGStartup(&symbols) ? 0 : 1;
}

static int KVRGCopy(const void *bytes, size_t length, unsigned char **out, size_t *outLength) {
    unsigned char *copy = malloc(length ? length : 1);
    if (!copy) return 0;
    if (length) memcpy(copy, bytes, length);
    *out = copy;
    *outLength = length;
    return 1;
}

// Serializes attribute rows as account 0x1f comment 0x1e. A row that is not a
// dictionary with two string attributes is a decode failure, never skipped.
static OSStatus KVRGRows(CFTypeRef found, char **out, size_t *outLength) {
    if (!found || CFGetTypeID(found) != CFArrayGetTypeID()) return errSecDecode;
    CFMutableDataRef buffer = CFDataCreateMutable(NULL, 0);
    if (!buffer) return errSecAllocate;
    OSStatus status = errSecSuccess;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount((CFArrayRef)found); i++) {
        CFTypeRef row = CFArrayGetValueAtIndex((CFArrayRef)found, i);
        if (!row || CFGetTypeID(row) != CFDictionaryGetTypeID()) { status = errSecDecode; break; }
        CFTypeRef fields[2] = { CFDictionaryGetValue((CFDictionaryRef)row, kSecAttrAccount), CFDictionaryGetValue((CFDictionaryRef)row, kSecAttrComment) };
        for (int f = 0; f < 2 && status == errSecSuccess; f++) {
            if (!fields[f] || CFGetTypeID(fields[f]) != CFStringGetTypeID() || CFStringGetLength((CFStringRef)fields[f]) > 32768) { status = errSecDecode; break; }
            CFDataRef text = CFStringCreateExternalRepresentation(NULL, (CFStringRef)fields[f], kCFStringEncodingUTF8, 0);
            if (!text) { status = errSecDecode; break; }
            CFDataAppendBytes(buffer, CFDataGetBytePtr(text), CFDataGetLength(text));
            CFRelease(text);
            UInt8 separator = f == 0 ? 0x1f : 0x1e;
            CFDataAppendBytes(buffer, &separator, 1);
        }
        if (status == errSecSuccess && CFDataGetLength(buffer) > 4 * 1024 * 1024) status = errSecDecode;
    }
    if (status == errSecSuccess) {
        size_t length = (size_t)CFDataGetLength(buffer);
        char *copy = malloc(length + 1);
        if (!copy) status = errSecAllocate;
        else { memcpy(copy, CFDataGetBytePtr(buffer), length); copy[length] = 0; *out = copy; *outLength = length; }
    }
    CFRelease(buffer);
    return status;
}

// Class, fixed service, optional exact account and the login keychain as the
// only search list. Attributes are requested; the item value never is.
static CFMutableDictionaryRef KVRGQuery(SecKeychainRef keychain, const char *account, int wantRef) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFArrayRef search = CFArrayCreate(NULL, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
    CFStringRef service = CFStringCreateWithCString(NULL, KVRGNamespace, kCFStringEncodingUTF8);
    CFStringRef accountString = account ? CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8) : NULL;
    int ok = query && search && service && (!account || accountString);
    if (ok) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        if (accountString) CFDictionarySetValue(query, kSecAttrAccount, accountString);
        CFDictionarySetValue(query, kSecMatchSearchList, search);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
        if (wantRef) CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    }
    if (search) CFRelease(search);
    if (service) CFRelease(service);
    if (accountString) CFRelease(accountString);
    if (!ok && query) { CFRelease(query); query = NULL; }
    return query;
}

// The paired-record namespace, attributes only, through the existing list. The
// root attach needs it for the retained pair record and its public pins.
int MacKeyVaultRootGrantsPairList(char **out, size_t *outLength) {
    if (!out || !outLength) return errSecParam;
    *out = NULL; *outLength = 0;
    KVQSymbols symbols = {0};
    if (!KVRGStartup(&symbols)) return errSecAuthFailed;
    return MacKeyVaultNostrList(out, outLength);
}

int MacKeyVaultRootGrantsList(char **out, size_t *outLength) {
    if (!out || !outLength) return errSecParam;
    *out = NULL; *outLength = 0;
    KVQSymbols symbols = {0};
    if (!KVRGStartup(&symbols)) return errSecAuthFailed;
    SecKeychainRef keychain = NULL;
    OSStatus status = KVQLogin(&keychain);
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = KVRGQuery(keychain, NULL, 0);
    CFTypeRef found = NULL;
    status = query ? SecItemCopyMatching(query, &found) : errSecAllocate;
    if (status == errSecItemNotFound) status = errSecSuccess; // empty inventory
    else if (status == errSecSuccess) status = KVRGRows(found, out, outLength);
    if (found) CFRelease(found);
    if (query) CFRelease(query);
    CFRelease(keychain);
    return (int)status;
}

int MacKeyVaultRootGrantsAddPrepare(MacKeyVaultRootGrantsAdd **plan, unsigned char **frame, size_t *frameLength) {
    if (!plan || !frame || !frameLength) return 3;
    *plan = NULL; *frame = NULL; *frameLength = 0;
    KVQSymbols symbols = {0};
    if (!KVRGStartup(&symbols)) return 1;
    SecAccessRef access = NULL;
    CFDataRef projection = NULL;
    OSStatus status = KVQIntendedAccess(symbols, &access);
    if (status == errSecSuccess) status = KVQProject(access, symbols, &projection);
    if (status == errSecSuccess && (!projection || CFDataGetLength(projection) <= 0 || CFDataGetLength(projection) > 1048576)) status = errSecDecode;
    int result = status == errSecSuccess ? 0 : 2;
    if (result == 0) {
        MacKeyVaultRootGrantsAdd *prepared = calloc(1, sizeof(*prepared));
        unsigned char *copy = NULL;
        size_t copyLength = 0;
        if (!prepared || !KVRGCopy(CFDataGetBytePtr(projection), (size_t)CFDataGetLength(projection), &copy, &copyLength)) {
            free(prepared);
            result = 3;
        } else {
            prepared->access = access;
            access = NULL; // owned by the plan until Close
            *plan = prepared;
            *frame = copy;
            *frameLength = copyLength;
        }
    }
    if (projection) CFRelease(projection);
    if (access) CFRelease(access);
    return result;
}

// The sole native mutation of the root attach: one create-only SecItemAdd. The
// attempted flag is set IMMEDIATELY before the call; any failure before it is a
// definite no-effect refusal. No update, delete, retry or value read exists here.
int MacKeyVaultRootGrantsAddCommit(MacKeyVaultRootGrantsAdd *plan, const char *account, const char *metadata,
    const unsigned char *envelope, size_t envelopeLength, int *attempted) {
    if (!attempted) return errSecParam;
    *attempted = 0;
    if (!plan || !plan->access || !account || !metadata || !envelope || envelopeLength == 0 || envelopeLength > 65536 ||
        strlen(account) == 0 || strlen(account) > 256 || strlen(metadata) == 0 || strlen(metadata) > 32768) return errSecParam;
    KVQSymbols symbols = {0};
    if (!KVRGStartup(&symbols)) return errSecAuthFailed;
    SecKeychainRef keychain = NULL;
    OSStatus status = KVQLogin(&keychain);
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef service = CFStringCreateWithCString(NULL, KVRGNamespace, kCFStringEncodingUTF8);
    CFStringRef accountString = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef metadataString = CFStringCreateWithCString(NULL, metadata, kCFStringEncodingUTF8);
    // No-copy input: Go owns and clears this buffer after the synchronous call.
    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, envelope, (CFIndex)envelopeLength, kCFAllocatorNull);
    status = query && service && accountString && metadataString && data ? errSecSuccess : errSecAllocate;
    if (status == errSecSuccess) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, accountString);
        CFDictionarySetValue(query, kSecAttrLabel, accountString);
        CFDictionarySetValue(query, kSecAttrComment, metadataString);
        CFDictionarySetValue(query, kSecUseKeychain, keychain);
        CFDictionarySetValue(query, kSecAttrAccess, plan->access);
        CFDictionarySetValue(query, kSecValueData, data);
        *attempted = 1;
        status = SecItemAdd(query, NULL); // SecItemAdd is atomic and never updates an existing item.
    }
    if (data) CFRelease(data);
    if (metadataString) CFRelease(metadataString);
    if (accountString) CFRelease(accountString);
    if (service) CFRelease(service);
    if (query) CFRelease(query);
    CFRelease(keychain);
    return (int)status;
}

void MacKeyVaultRootGrantsAddClose(MacKeyVaultRootGrantsAdd *plan) {
    if (!plan) return;
    if (plan->access) CFRelease(plan->access);
    free(plan);
}

// Exactly one item, attributes and ACL only. SecKeychainItemCopyAccess reads the
// access object, never the protected value. Zero or several matches fail.
int MacKeyVaultRootGrantsReadback(const char *account, unsigned char **metadata, size_t *metadataLength,
    unsigned char **frame, size_t *frameLength) {
    if (!account || !metadata || !metadataLength || !frame || !frameLength) return errSecParam;
    *metadata = NULL; *metadataLength = 0; *frame = NULL; *frameLength = 0;
    if (strlen(account) == 0 || strlen(account) > 256) return errSecParam;
    KVQSymbols symbols = {0};
    if (!KVRGStartup(&symbols)) return errSecAuthFailed;
    SecKeychainRef keychain = NULL;
    OSStatus status = KVQLogin(&keychain);
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = KVRGQuery(keychain, account, 1);
    CFTypeRef found = NULL;
    SecAccessRef access = NULL;
    CFDataRef projection = NULL, text = NULL;
    status = query ? SecItemCopyMatching(query, &found) : errSecAllocate;
    if (status == errSecSuccess && (!found || CFGetTypeID(found) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)found) != 1)) status = errSecDecode;
    CFDictionaryRef row = NULL;
    if (status == errSecSuccess) {
        CFTypeRef candidate = CFArrayGetValueAtIndex((CFArrayRef)found, 0);
        if (!candidate || CFGetTypeID(candidate) != CFDictionaryGetTypeID()) status = errSecDecode;
        else row = (CFDictionaryRef)candidate;
    }
    if (status == errSecSuccess) {
        CFTypeRef rowAccount = CFDictionaryGetValue(row, kSecAttrAccount);
        CFTypeRef comment = CFDictionaryGetValue(row, kSecAttrComment);
        CFTypeRef reference = CFDictionaryGetValue(row, kSecValueRef);
        CFStringRef expected = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
        if (!expected || !rowAccount || CFGetTypeID(rowAccount) != CFStringGetTypeID() || !CFEqual(rowAccount, expected) ||
            !comment || CFGetTypeID(comment) != CFStringGetTypeID() || CFStringGetLength((CFStringRef)comment) < 1 || CFStringGetLength((CFStringRef)comment) > 32768 ||
            !reference || CFGetTypeID(reference) != SecKeychainItemGetTypeID()) status = errSecDecode;
        if (expected) CFRelease(expected);
        if (status == errSecSuccess) {
            text = CFStringCreateExternalRepresentation(NULL, (CFStringRef)comment, kCFStringEncodingUTF8, 0);
            if (!text || CFDataGetLength(text) <= 0 || CFDataGetLength(text) > 32768) status = errSecDecode;
        }
        if (status == errSecSuccess) status = SecKeychainItemCopyAccess((SecKeychainItemRef)reference, &access);
        if (status == errSecSuccess && !access) status = errSecDecode;
        if (status == errSecSuccess) status = KVQProject(access, symbols, &projection);
        if (status == errSecSuccess && (!projection || CFDataGetLength(projection) <= 0 || CFDataGetLength(projection) > 1048576)) status = errSecDecode;
    }
    if (status == errSecSuccess && !KVRGCopy(CFDataGetBytePtr(text), (size_t)CFDataGetLength(text), metadata, metadataLength)) status = errSecAllocate;
    if (status == errSecSuccess && !KVRGCopy(CFDataGetBytePtr(projection), (size_t)CFDataGetLength(projection), frame, frameLength)) {
        free(*metadata);
        *metadata = NULL; *metadataLength = 0;
        status = errSecAllocate;
    }
    if (projection) CFRelease(projection);
    if (text) CFRelease(text);
    if (access) CFRelease(access);
    if (found) CFRelease(found);
    if (query) CFRelease(query);
    CFRelease(keychain);
    return (int)status;
}
