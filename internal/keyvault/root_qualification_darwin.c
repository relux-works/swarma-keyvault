#include "security_darwin.h"
#include "root_acl_darwin.h"
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// The file-based Keychain ACL API is intentionally the supported mechanism.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// This translation unit has no constructor, private vault interface, caller
// namespace, item update, Enclave or user-presence operation. Deletion is a
// separate finite function restricted to this created public-marker item.
static const char *KVQService = "works.relux.mac-keyvault.root-acl-qualification.v1";
static const char *KVQAccount = "public-marker@1";
// The access descriptor and application label of the public-marker item. Both are
// part of the ACL observed by the qualification lane and are never used by the
// production root-grants item.
static const char *KVQDescriptor = "Root ACL public qualification";
static const char *KVQApplicationLabel = "keyvault-root-acl-qualification:/vault";

// The access constructor, running-code check, login-keychain selection and ACL
// projection live in the shared root_acl_darwin.c unit; this file keeps only the
// fixed public-marker namespace and its lane operations.

// Parent verifies its actual runtime against the observed vault artifact, or
// one live child against the observed helper/foreign artifact BEFORE sending
// the public request. Roles and certificate policy are fixed, never DR input.
int MacKeyVaultRootQualificationCode(int role, int pid, const unsigned char *hash, size_t length) {
    if (!hash || (length != 20 && length != 32) ||
        !((pid == 0 && role == 1) || (pid > 0 && (role == 2 || role == 4)))) return 1;
    return KVQCode(role, pid, hash, length) == errSecSuccess ? 0 : 1;
}

static int KVQAttribute(const SecKeychainAttribute *attribute, UInt32 tag, const char *expected) {
    size_t length = strlen(expected);
    return attribute->tag == tag && attribute->length == length && attribute->data && memcmp(attribute->data, expected, length) == 0;
}

// Metadata lookup searches only the fixed class/service/account in the actual
// login Keychain and THEN matches the supplied public persistent reference.
// kSecMatchItemList deliberately avoids the direct-reference useItems path.
// No marker/data read occurs unless returned metadata is an exact match.
static OSStatus KVQFind(SecKeychainRef keychain, const unsigned char *reference, size_t length, SecKeychainItemRef *out) {
    *out = NULL;
    CFDataRef ref = CFDataCreate(NULL, reference, (CFIndex)length);
    CFArrayRef items = ref ? CFArrayCreate(NULL, (const void **)&ref, 1, &kCFTypeArrayCallBacks) : NULL;
    CFArrayRef search = CFArrayCreate(NULL, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus status = ref && items && search && query ? errSecSuccess : errSecAllocate;
    if (status == errSecSuccess) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, CFSTR("works.relux.mac-keyvault.root-acl-qualification.v1"));
        CFDictionarySetValue(query, kSecAttrAccount, CFSTR("public-marker@1"));
        CFDictionarySetValue(query, kSecMatchSearchList, search);
        CFDictionarySetValue(query, kSecMatchItemList, items);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFTypeRef item = NULL;
        status = SecItemCopyMatching(query, &item);
        if (status == errSecSuccess && (!item || CFGetTypeID(item) != SecKeychainItemGetTypeID())) status = errSecDecode;
        if (status == errSecSuccess) *out = (SecKeychainItemRef)item;
        else if (item) CFRelease(item);
    }
    if (query) CFRelease(query);
    if (search) CFRelease(search);
    if (items) CFRelease(items);
    if (ref) CFRelease(ref);
    if (status != errSecSuccess) return status;
    UInt32 tags[] = { kSecServiceItemAttr, kSecAccountItemAttr };
    UInt32 formats[] = { CSSM_DB_ATTRIBUTE_FORMAT_STRING, CSSM_DB_ATTRIBUTE_FORMAT_STRING };
    SecKeychainAttributeInfo info = { 2, tags, formats };
    SecKeychainAttributeList *attributes = NULL;
    SecItemClass itemClass = 0;
    status = SecKeychainItemCopyAttributesAndData(*out, &info, &itemClass, &attributes, NULL, NULL);
    if (status == errSecSuccess && (itemClass != kSecGenericPasswordItemClass || !attributes || attributes->count != 2 || !attributes->attr ||
        !KVQAttribute(&attributes->attr[0], tags[0], KVQService) || !KVQAttribute(&attributes->attr[1], tags[1], KVQAccount))) status = errSecDecode;
    if (attributes) SecKeychainItemFreeAttributesAndData(attributes, NULL);
    if (status != errSecSuccess) { CFRelease(*out); *out = NULL; }
    return status;
}

// Only an intended denial at the ACTUAL marker-data read is access-refused.
// Startup/metadata/not-found/unknown failures are unqualified, never a pass.
// The raw value and OS status never leave this function through public output.
int MacKeyVaultRootQualificationRead(int role, const unsigned char *reference, size_t length, int *result) {
    if (!result) return 1;
    *result = 3;
    if (!reference || length < 1 || length > 16384 || !KVQRole(role)) return 1;
    KVQSymbols symbols = {0};
    if (!KVQResolve(&symbols) || KVQSelf(role) != errSecSuccess) return 1;
    SecKeychainRef keychain = NULL;
    if (KVQLogin(&keychain) != errSecSuccess) return 1;
    SecKeychainItemRef item = NULL;
    OSStatus status = KVQFind(keychain, reference, length, &item);
    if (status == errSecSuccess) {
        UInt32 dataLength = 0;
        void *data = NULL;
        status = SecKeychainItemCopyAttributesAndData(item, NULL, NULL, NULL, &dataLength, &data);
        if (status == errSecAuthFailed || status == errSecInteractionNotAllowed) *result = 1;
        else if (status == errSecSuccess) *result = 2; // ANY unexpected access fails; never print its value.
        if (data) {
            // Even unexpected non-marker bytes are cleared before OS release.
            if (dataLength && memset_s(data, dataLength, 0, dataLength) != 0) abort();
            SecKeychainItemFreeAttributesAndData(NULL, data);
        }
    }
    if (item) CFRelease(item);
    CFRelease(keychain);
    return 0;
}

static OSStatus KVQOwnMarker(SecKeychainItemRef item) {
    UInt32 length = 0; void *data = NULL;
    OSStatus status = SecKeychainItemCopyAttributesAndData(item, NULL, NULL, NULL, &length, &data);
    const char *marker = "keyvault-root-acl-qualification/1";
    if (status == errSecSuccess && (!data || length != strlen(marker) || memcmp(data, marker, length) != 0)) status = errSecDecode;
    if (data) {
        if (length && memset_s(data, length, 0, length) != 0) abort();
        SecKeychainItemFreeAttributesAndData(NULL, data);
    }
    return status;
}

// Owning-vault readback only: exact fixed item/marker, then full public ACL
// projection. It returns no value or arbitrary item metadata on any path.
int MacKeyVaultRootQualificationSnapshot(const unsigned char *reference, size_t length, unsigned char **out, size_t *outLength) {
    if (!out || !outLength) return 1;
    *out = NULL; *outLength = 0;
    if (!reference || length < 1 || length > 16384) return 1;
    KVQSymbols symbols = {0};
    if (!KVQResolve(&symbols) || KVQSelf(1) != errSecSuccess) return 1;
    SecKeychainRef keychain = NULL;
    if (KVQLogin(&keychain) != errSecSuccess) return 1;
    SecKeychainItemRef item = NULL;
    SecAccessRef access = NULL;
    CFDataRef frame = NULL;
    OSStatus status = KVQFind(keychain, reference, length, &item);
    if (status == errSecSuccess) status = KVQOwnMarker(item);
    if (status == errSecSuccess) status = SecKeychainItemCopyAccess(item, &access);
    if (status == errSecSuccess && !access) status = errSecDecode;
    if (status == errSecSuccess) status = KVQProject(access, symbols, &frame);
    if (status == errSecSuccess && (!frame || CFDataGetLength(frame) <= 0 || CFDataGetLength(frame) > 1048576)) status = errSecDecode;
    if (status == errSecSuccess) {
        *out = malloc((size_t)CFDataGetLength(frame));
        if (!*out) status = errSecAllocate;
        else { *outLength = (size_t)CFDataGetLength(frame); memcpy(*out, CFDataGetBytePtr(frame), *outLength); }
    }
    if (frame) CFRelease(frame);
    if (access) CFRelease(access);
    if (item) CFRelease(item);
    CFRelease(keychain);
    return status == errSecSuccess ? 0 : 1;
}

static int KVQCopyPublicData(CFDataRef value, unsigned char **out, size_t *length, size_t max) {
    if (!value || CFGetTypeID(value) != CFDataGetTypeID() || CFDataGetLength(value) <= 0 || (size_t)CFDataGetLength(value) > max) return 0;
    *out = malloc((size_t)CFDataGetLength(value));
    if (!*out) return 0;
    *length = (size_t)CFDataGetLength(value);
    memcpy(*out, CFDataGetBytePtr(value), *length);
    return 1;
}

// One create-only fixed PUBLIC-marker item. Outcome1 is no-effect refusal,
// outcome2 created/readback, outcome3 uncertain after the ONE add attempt.
// Caller reserves its exclusive receipt BEFORE entering; uncertainty never
// causes search, overwrite, retry, automatic delete or old-item inspection.
// Every failing step records its stage id and Security OSStatus (first failure
// wins, root_acl_darwin.h); the notes never change outcome or the return value.
static int KVQCreateRun(unsigned char **reference, size_t *referenceLength,
    unsigned char **before, size_t *beforeLength, unsigned char **after, size_t *afterLength, int *outcome) {
    KVQSymbols symbols = {0};
    if (!KVQResolve(&symbols) || KVQSelf(1) != errSecSuccess) return 1;
    SecKeychainRef keychain = NULL;
    if (KVQLogin(&keychain) != errSecSuccess) return 1;
    SecAccessRef intended = NULL, actual = NULL;
    SecKeychainItemRef item = NULL;
    CFDataRef beforeFrame = NULL, afterFrame = NULL;
    CFTypeRef added = NULL;
    CFMutableDictionaryRef query = NULL;
    OSStatus status = KVQIntendedAccess(symbols, KVQDescriptor, KVQApplicationLabel, &intended);
    if (status == errSecSuccess) {
        status = KVQProject(intended, symbols, &beforeFrame);
        if (status != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_BEFORE_OWNER_ACL);
    }
    if (status == errSecSuccess && !KVQCopyPublicData(beforeFrame, before, beforeLength, 1048576)) {
        status = errSecAllocate;
        KVQDiagNote(KVQ_STAGE_BEFORE_COPY, status);
    }
    if (status == errSecSuccess) {
        query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!query) {
            status = errSecAllocate;
            KVQDiagNote(KVQ_STAGE_ADD_PREPARE, status);
        }
    }
    CFDataRef marker = NULL;
    if (status == errSecSuccess) {
        const char *value = "keyvault-root-acl-qualification/1";
        marker = CFDataCreate(NULL, (const unsigned char *)value, (CFIndex)strlen(value));
        if (!marker) {
            status = errSecAllocate;
            KVQDiagNote(KVQ_STAGE_ADD_PREPARE, status);
        }
    }
    if (status == errSecSuccess) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, CFSTR("works.relux.mac-keyvault.root-acl-qualification.v1"));
        CFDictionarySetValue(query, kSecAttrAccount, CFSTR("public-marker@1"));
        CFDictionarySetValue(query, kSecAttrLabel, CFSTR("Root ACL public qualification"));
        CFDictionarySetValue(query, kSecUseKeychain, keychain);
        CFDictionarySetValue(query, kSecAttrAccess, intended);
        CFDictionarySetValue(query, kSecValueData, marker);
        CFDictionarySetValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
        *outcome = 3;
        status = SecItemAdd(query, &added); // Sole native mutation; no update.
        KVQDiagNote(KVQ_STAGE_ADD, status);
        if (status == errSecDuplicateItem) *outcome = 1;
        if (status == errSecSuccess && !KVQCopyPublicData(added, reference, referenceLength, 16384)) {
            status = errSecDecode;
            KVQDiagNote(KVQ_STAGE_READBACK_REFERENCE, status);
        }
        if (status == errSecSuccess) {
            status = KVQFind(keychain, *reference, *referenceLength, &item);
            KVQDiagNote(KVQ_STAGE_READBACK_FIND, status);
        }
        if (status == errSecSuccess) {
            status = KVQOwnMarker(item);
            KVQDiagNote(KVQ_STAGE_READBACK_MARKER, status);
        }
        if (status == errSecSuccess) {
            status = SecKeychainItemCopyAccess(item, &actual);
            KVQDiagNote(KVQ_STAGE_READBACK_ACCESS, status);
        }
        if (status == errSecSuccess && !actual) {
            status = errSecDecode;
            KVQDiagNote(KVQ_STAGE_READBACK_ACCESS, status);
        }
        if (status == errSecSuccess) {
            status = KVQProject(actual, symbols, &afterFrame);
            if (status != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_AFTER_OWNER_ACL);
        }
        if (status == errSecSuccess && !KVQCopyPublicData(afterFrame, after, afterLength, 1048576)) {
            status = errSecAllocate;
            KVQDiagNote(KVQ_STAGE_READBACK_COPY, status);
        }
        if (status == errSecSuccess) *outcome = 2;
    }
    if (added) CFRelease(added);
    if (marker) CFRelease(marker);
    if (query) CFRelease(query);
    if (afterFrame) CFRelease(afterFrame);
    if (beforeFrame) CFRelease(beforeFrame);
    if (actual) CFRelease(actual);
    if (intended) CFRelease(intended);
    if (item) CFRelease(item);
    CFRelease(keychain);
    return status == errSecSuccess ? 0 : 1;
}

int MacKeyVaultRootQualificationCreate(unsigned char **reference, size_t *referenceLength,
    unsigned char **before, size_t *beforeLength, unsigned char **after, size_t *afterLength, int *outcome,
    int *stage, int *osStatus) {
    if (!reference || !referenceLength || !before || !beforeLength || !after || !afterLength || !outcome || !stage || !osStatus) return 1;
    *reference = *before = *after = NULL;
    *referenceLength = *beforeLength = *afterLength = 0; *outcome = 1;
    *stage = 0; *osStatus = 0;
    KVQDiagReset();
    int result = KVQCreateRun(reference, referenceLength, before, beforeLength, after, afterLength, outcome);
    int recordedStage = 0;
    OSStatus recorded = errSecSuccess;
    if (KVQDiagTake(&recordedStage, &recorded)) {
        *stage = recordedStage;
        *osStatus = (int)recorded;
    }
    return result;
}

// Separate attended cleanup, exact same public item and full unchanged
// projection. No broad search, alternate ref, automatic cleanup or retry.
int MacKeyVaultRootQualificationDelete(const unsigned char *reference, size_t referenceLength,
    const unsigned char *expectedProjectionSHA256, size_t digestLength, int *outcome) {
    if (!outcome) return 1;
    *outcome = 1;
    if (!reference || referenceLength < 1 || referenceLength > 16384 || !expectedProjectionSHA256 || digestLength != 32) return 1;
    KVQSymbols symbols = {0};
    if (!KVQResolve(&symbols) || KVQSelf(1) != errSecSuccess) return 1;
    SecKeychainRef keychain = NULL;
    if (KVQLogin(&keychain) != errSecSuccess) return 1;
    SecKeychainItemRef item = NULL;
    SecAccessRef access = NULL;
    CFDataRef frame = NULL;
    OSStatus status = KVQFind(keychain, reference, referenceLength, &item);
    if (status == errSecSuccess) status = KVQOwnMarker(item);
    if (status == errSecSuccess) status = SecKeychainItemCopyAccess(item, &access);
    if (status == errSecSuccess && !access) status = errSecDecode;
    if (status == errSecSuccess) status = KVQProject(access, symbols, &frame);
    if (status == errSecSuccess && (!frame || CFDataGetLength(frame) <= 0 || CFDataGetLength(frame) > 1048576)) status = errSecDecode;
    if (status == errSecSuccess) {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(CFDataGetBytePtr(frame), (CC_LONG)CFDataGetLength(frame), digest);
        if (memcmp(digest, expectedProjectionSHA256, sizeof(digest)) != 0) status = errSecAuthFailed;
    }
    if (status == errSecSuccess) {
        *outcome = 3;
        status = SecKeychainItemDelete(item); // Exactly one attempt, fixed item.
        if (status == errSecSuccess) *outcome = 2;
    }
    if (frame) CFRelease(frame);
    if (access) CFRelease(access);
    if (item) CFRelease(item);
    CFRelease(keychain);
    return status == errSecSuccess ? 0 : 1;
}
