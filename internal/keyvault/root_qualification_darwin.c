#include "security_darwin.h"
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

// Signatures are from the source-pinned Security SecTrustedApplicationPriv.h.
// Both symbols must exist BEFORE any Keychain query, even for a read control.
typedef OSStatus (*KVQCreateRequirement)(const char *, SecRequirementRef, SecTrustedApplicationRef *);
typedef OSStatus (*KVQCopyRequirement)(SecTrustedApplicationRef, SecRequirementRef *);
typedef struct { KVQCreateRequirement create; KVQCopyRequirement copy; } KVQSymbols;

static int KVQResolve(KVQSymbols *out) {
    out->create = (KVQCreateRequirement)dlsym(RTLD_DEFAULT, "SecTrustedApplicationCreateFromRequirement");
    out->copy = (KVQCopyRequirement)dlsym(RTLD_DEFAULT, "SecTrustedApplicationCopyRequirement");
    return out->create != NULL && out->copy != NULL;
}

static int KVQHashEquals(const unsigned char *bytes, size_t length, const char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        if (hex[2*i] != digits[bytes[i] >> 4] || hex[2*i+1] != digits[bytes[i] & 15]) return 0;
    }
    return hex[2*length] == 0;
}

static const char *KVQRole(int role) {
    switch (role) {
    case 1: return "works.relux.keyvault";
    case 2: return "works.relux.keyvault.enclave";
    case 4: return "works.relux.keyvault.qualification-foreign";
    default: return NULL; // Seed and every unknown role are excluded.
    }
}

// Check the ACTUAL running code, its complete leaf and fixed binary DR. No
// path-only identity, ad-hoc flags, implicit team DR or caller requirement.
static OSStatus KVQCode(int role, int pid, const unsigned char *expectedHash, size_t hashLength) {
    const char *identifier = KVQRole(role);
    if (!identifier || getuid() != geteuid() || pid < 0 ||
        (hashLength != 0 && (!expectedHash || (hashLength != 20 && hashLength != 32)))) return errSecAuthFailed;
    CFStringRef id = CFStringCreateWithCString(NULL, identifier, kCFStringEncodingUTF8);
    CFStringRef text = id ? CFStringCreateWithFormat(NULL, NULL,
        CFSTR("identifier \"%@\" and anchor apple generic and certificate leaf = H\"d71190abe54185f908169ee9ca538d4066942c0f\" and certificate 1[field.1.2.840.113635.100.6.2.1]"), id) : NULL;
    SecCodeRef code = NULL;
    SecStaticCodeRef staticCode = NULL;
    SecRequirementRef expected = NULL, actual = NULL;
    CFDataRef expectedData = NULL, actualData = NULL, leaf = NULL;
    CFDictionaryRef info = NULL;
    OSStatus status = text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &expected) : errSecAllocate;
    if (status == errSecSuccess && !expected) status = errSecAuthFailed;
    if (status == errSecSuccess && pid == 0) status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (status == errSecSuccess && pid > 0) {
        CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
        if (!attributes || !number) status = errSecAllocate;
        else {
            CFDictionarySetValue(attributes, kSecGuestAttributePid, number);
            status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
        }
        if (number) CFRelease(number);
        if (attributes) CFRelease(attributes);
    }
    if (status == errSecSuccess && !code) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSStrictValidate, expected);
    if (status == errSecSuccess) status = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &staticCode);
    if (status == errSecSuccess && !staticCode) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(staticCode,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, expected);
    if (status == errSecSuccess) status = SecCodeCopyDesignatedRequirement(staticCode, kSecCSDefaultFlags, &actual);
    if (status == errSecSuccess && !actual) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(expected, kSecCSDefaultFlags, &expectedData);
    if (status == errSecSuccess) status = SecRequirementCopyData(actual, kSecCSDefaultFlags, &actualData);
    if (status == errSecSuccess && (!expectedData || !actualData || !CFEqual(expectedData, actualData))) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecCodeCopySigningInformation((SecStaticCodeRef)code,
        kSecCSSigningInformation | kSecCSDynamicInformation, &info);
    if (status == errSecSuccess && (!info || CFGetTypeID(info) != CFDictionaryGetTypeID())) status = errSecAuthFailed;
    if (status == errSecSuccess) {
        CFTypeRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        CFTypeRef dynamic = CFDictionaryGetValue(info, kSecCodeInfoStatus);
        CFTypeRef actualID = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
        CFTypeRef team = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
        CFTypeRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
        CFTypeRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        uint32_t f = 0, d = 0;
        if (!flags || CFGetTypeID(flags) != CFNumberGetTypeID() || !CFNumberGetValue(flags, kCFNumberSInt32Type, &f) || f != 0x10000 ||
            !dynamic || CFGetTypeID(dynamic) != CFNumberGetTypeID() || !CFNumberGetValue(dynamic, kCFNumberSInt32Type, &d) ||
            !(d & 1) || !(d & 0x10000) || (d & 0x10000000) ||
            !actualID || CFGetTypeID(actualID) != CFStringGetTypeID() || !CFEqual(actualID, id) ||
            !team || CFGetTypeID(team) != CFStringGetTypeID() || !CFEqual(team, CFSTR("262RZ595FP")) ||
            !hash || CFGetTypeID(hash) != CFDataGetTypeID() || (CFDataGetLength(hash) != 20 && CFDataGetLength(hash) != 32) ||
            (entitlements && (CFGetTypeID(entitlements) != CFDictionaryGetTypeID() || CFDictionaryGetCount(entitlements) != 0))) status = errSecAuthFailed;
        if (status == errSecSuccess && hashLength != 0 &&
            ((size_t)CFDataGetLength(hash) != hashLength || memcmp(CFDataGetBytePtr(hash), expectedHash, hashLength) != 0)) status = errSecAuthFailed;
    }
    if (status == errSecSuccess) {
        CFTypeRef certificates = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
        if (!certificates || CFGetTypeID(certificates) != CFArrayGetTypeID() || CFArrayGetCount(certificates) < 1) status = errSecAuthFailed;
        else {
            CFTypeRef certificate = CFArrayGetValueAtIndex(certificates, 0);
            if (!certificate || CFGetTypeID(certificate) != SecCertificateGetTypeID()) status = errSecAuthFailed;
            else leaf = SecCertificateCopyData((SecCertificateRef)certificate);
        }
        if (status == errSecSuccess && (!leaf || CFDataGetLength(leaf) <= 0 || CFDataGetLength(leaf) > 32768)) status = errSecAuthFailed;
        if (status == errSecSuccess) {
            unsigned char sha1[CC_SHA1_DIGEST_LENGTH], sha256[CC_SHA256_DIGEST_LENGTH];
            CC_SHA1(CFDataGetBytePtr(leaf), (CC_LONG)CFDataGetLength(leaf), sha1);
            CC_SHA256(CFDataGetBytePtr(leaf), (CC_LONG)CFDataGetLength(leaf), sha256);
            if (!KVQHashEquals(sha1, sizeof(sha1), "d71190abe54185f908169ee9ca538d4066942c0f") ||
                !KVQHashEquals(sha256, sizeof(sha256), "b315ed0ac55f58d4dbcfc3ce4f7937f6ed058277feba7e4aa3e64bd10b17d3a1")) status = errSecAuthFailed;
        }
    }
    if (leaf) CFRelease(leaf);
    if (info) CFRelease(info);
    if (actualData) CFRelease(actualData);
    if (expectedData) CFRelease(expectedData);
    if (actual) CFRelease(actual);
    if (expected) CFRelease(expected);
    if (staticCode) CFRelease(staticCode);
    if (code) CFRelease(code);
    if (text) CFRelease(text);
    if (id) CFRelease(id);
    return status;
}

static OSStatus KVQSelf(int role) { return KVQCode(role, 0, NULL, 0); }

// Parent verifies its actual runtime against the observed vault artifact, or
// one live child against the observed helper/foreign artifact BEFORE sending
// the public request. Roles and certificate policy are fixed, never DR input.
int MacKeyVaultRootQualificationCode(int role, int pid, const unsigned char *hash, size_t length) {
    if (!hash || (length != 20 && length != 32) ||
        !((pid == 0 && role == 1) || (pid > 0 && (role == 2 || role == 4)))) return 1;
    return KVQCode(role, pid, hash, length) == errSecSuccess ? 0 : 1;
}

static OSStatus KVQLogin(SecKeychainRef *out) {
    *out = NULL;
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    struct passwd user, *found = NULL;
    char buffer[16384], path[PATH_MAX], actual[PATH_MAX];
    if (getpwuid_r(getuid(), &user, buffer, sizeof(buffer), &found) != 0 || !found || !user.pw_dir || user.pw_uid != getuid() || user.pw_dir[0] != '/') return errSecNotAvailable;
    int length = snprintf(path, sizeof(path), "%s/Library/Keychains/login.keychain-db", user.pw_dir);
    if (length <= 0 || (size_t)length >= sizeof(path)) return errSecParam;
    status = SecKeychainOpen(path, out);
    if (status == errSecSuccess && !*out) status = errSecNotAvailable;
    UInt32 capacity = sizeof(actual);
    if (status == errSecSuccess) status = SecKeychainGetPath(*out, &capacity, actual);
    if (status == errSecSuccess && (capacity != (UInt32)length || capacity >= sizeof(actual) || memcmp(actual, path, (size_t)length) != 0)) status = errSecAuthFailed;
    SecKeychainStatus state = 0;
    if (status == errSecSuccess) status = SecKeychainGetStatus(*out, &state);
    if (status == errSecSuccess && !(state & kSecUnlockStateStatus)) status = errSecInteractionNotAllowed;
    if (status != errSecSuccess && *out) { CFRelease(*out); *out = NULL; }
    return status;
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

// Bounded PUBLIC projection frame, decoded by rootqualification's KVQP1
// decoder. This records unknowns; it is never an admission/learning policy.
static int KVQPut(CFMutableDataRef out, const void *bytes, size_t length) {
    if (!out || length > 1048576 || CFDataGetLength(out) < 0 ||
        (size_t)CFDataGetLength(out) > 1048576 - length) return 0;
    if (length) CFDataAppendBytes(out, bytes, (CFIndex)length);
    return 1;
}
static int KVQU32(CFMutableDataRef out, uint32_t n) {
    unsigned char bytes[4] = { (unsigned char)(n >> 24), (unsigned char)(n >> 16), (unsigned char)(n >> 8), (unsigned char)n };
    return KVQPut(out, bytes, sizeof(bytes));
}
static int KVQField(CFMutableDataRef out, const void *bytes, size_t length, size_t max) {
    return length <= max && length <= UINT32_MAX && (!length || bytes) && KVQU32(out, (uint32_t)length) && KVQPut(out, bytes, length);
}
static int KVQText(CFMutableDataRef out, CFStringRef value, size_t max) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
    CFIndex needed = 0, characters = CFStringGetLength(value);
    CFIndex converted = CFStringGetBytes(value, CFRangeMake(0, characters), kCFStringEncodingUTF8, 0, false, NULL, 0, &needed);
    if (converted != characters || needed < 0 || (size_t)needed > max) return 0;
    unsigned char *bytes = malloc(needed ? (size_t)needed : 1);
    if (!bytes) return 0;
    CFIndex written = 0;
    converted = CFStringGetBytes(value, CFRangeMake(0, characters), kCFStringEncodingUTF8, 0, false, bytes, needed, &written);
    int ok = converted == characters && written == needed && KVQField(out, bytes, (size_t)needed, max);
    free(bytes);
    return ok;
}
static int KVQEmpty(CFMutableDataRef out) { return KVQU32(out, 0); }

static int KVQApplication(CFMutableDataRef out, CFTypeRef application, KVQSymbols symbols) {
    uint32_t state = 3; // An unexpected CF type stays explicit, never trusted.
    SecRequirementRef requirement = NULL;
    CFDataRef data = NULL;
    CFStringRef text = NULL;
    if (application && CFGetTypeID(application) == SecTrustedApplicationGetTypeID()) {
        OSStatus status = symbols.copy((SecTrustedApplicationRef)application, &requirement);
        state = status == errSecSuccess ? (requirement ? 0 : 1) : 2;
        if (state == 0) {
            if (CFGetTypeID(requirement) != SecRequirementGetTypeID() ||
                SecRequirementCopyData(requirement, kSecCSDefaultFlags, &data) != errSecSuccess || !data ||
                CFDataGetLength(data) <= 0 || CFDataGetLength(data) > 65536 ||
                SecRequirementCopyString(requirement, kSecCSDefaultFlags, &text) != errSecSuccess || !text || CFStringGetLength(text) == 0) state = 2;
        }
    }
    int ok = KVQU32(out, state);
    if (ok && state == 0) ok = KVQField(out, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data), 65536) && KVQText(out, text, 65536);
    else if (ok) ok = KVQEmpty(out) && KVQEmpty(out);
    if (text) CFRelease(text);
    if (data) CFRelease(data);
    if (requirement) CFRelease(requirement);
    return ok;
}

static OSStatus KVQProject(SecAccessRef access, KVQSymbols symbols, CFDataRef *out) {
    *out = NULL;
    uid_t uid = 0; gid_t gid = 0; SecAccessOwnerType owner = 0;
    CFArrayRef list = NULL;
    OSStatus status = SecAccessCopyOwnerAndACL(access, &uid, &gid, &owner, &list);
    CFMutableDataRef frame = CFDataCreateMutable(NULL, 0);
    if (status == errSecSuccess && (!frame || !list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64 ||
        !KVQPut(frame, "KVQP1", 5) || !KVQU32(frame, uid) || !KVQU32(frame, gid) || !KVQU32(frame, owner) || !KVQU32(frame, (uint32_t)CFArrayGetCount(list)))) status = errSecDecode;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef candidate = CFArrayGetValueAtIndex(list, i);
        if (!candidate || CFGetTypeID(candidate) != SecACLGetTypeID()) { status = errSecDecode; break; }
        SecACLRef acl = (SecACLRef)candidate;
        // Preserve the complete numeric set even when symbolic names are
        // unavailable/unknown. No authorization tag is classified as harmless.
        CSSM_ACL_AUTHORIZATION_TAG numbers[64]; uint32 numberCount = 64;
        status = SecACLGetAuthorizations(acl, numbers, &numberCount);
        if (status != errSecSuccess || numberCount > 64) { status = errSecDecode; break; }
        CFArrayRef names = SecACLCopyAuthorizations(acl);
        int namesReadable = names && CFGetTypeID(names) == CFArrayGetTypeID() && CFArrayGetCount(names) <= 64;
        if (namesReadable) for (CFIndex j = 0; j < CFArrayGetCount(names); j++) {
            CFTypeRef name = CFArrayGetValueAtIndex(names, j);
            if (!name || CFGetTypeID(name) != CFStringGetTypeID()) namesReadable = 0;
        }
        int ok = KVQU32(frame, namesReadable ? 0 : 1) && KVQU32(frame, namesReadable ? (uint32_t)CFArrayGetCount(names) : 0);
        if (namesReadable) for (CFIndex j = 0; ok && j < CFArrayGetCount(names); j++) ok = KVQText(frame, CFArrayGetValueAtIndex(names, j), 1024);
        if (names) CFRelease(names);
        ok = ok && KVQU32(frame, numberCount);
        for (uint32 j = 0; ok && j < numberCount; j++) ok = KVQU32(frame, (uint32_t)numbers[j]);
        CFArrayRef apps = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        OSStatus contents = SecACLCopyContents(acl, &apps, &description, &prompt);
        int readable = contents == errSecSuccess && (!apps || CFGetTypeID(apps) == CFArrayGetTypeID()) &&
            (!description || CFGetTypeID(description) == CFStringGetTypeID());
        if (readable && apps && CFArrayGetCount(apps) > 64) ok = 0;
        ok = ok && KVQU32(frame, readable ? 0 : 1) && KVQU32(frame, readable ? (description ? 1 : 0) : 2);
        ok = ok && (readable && description ? KVQText(frame, description, 32768) : KVQEmpty(frame)) && KVQU32(frame, readable ? (uint32_t)prompt : 0);
        // CopyContents exposes a 16-bit selector. Also retain the complete
        // underlying CSSM version/32-bit flags; unknown high bits are not lost.
        CFArrayRef rawApps = NULL; CFStringRef rawDescription = NULL;
        CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR rawPrompt = {0, 0};
        OSStatus rawStatus = SecACLCopySimpleContents(acl, &rawApps, &rawDescription, &rawPrompt);
        ok = ok && KVQU32(frame, rawStatus == errSecSuccess ? 0 : 1) &&
            KVQU32(frame, rawStatus == errSecSuccess ? rawPrompt.version : 0) && KVQU32(frame, rawStatus == errSecSuccess ? rawPrompt.flags : 0);
        if (rawApps) CFRelease(rawApps);
        if (rawDescription) CFRelease(rawDescription);
        ok = ok && KVQU32(frame, readable ? (apps ? 1 : 0) : 2) && KVQU32(frame, readable && apps ? (uint32_t)CFArrayGetCount(apps) : 0);
        if (readable && apps) for (CFIndex j = 0; ok && j < CFArrayGetCount(apps); j++) ok = KVQApplication(frame, CFArrayGetValueAtIndex(apps, j), symbols);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (!ok) status = errSecDecode;
    }
    if (list) CFRelease(list);
    if (status == errSecSuccess) *out = frame;
    else if (frame) CFRelease(frame);
    return status;
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

static OSStatus KVQPartitionDescription(CFStringRef *out) {
    *out = NULL;
    const void *partition = CFSTR("teamid:262RZ595FP");
    CFArrayRef values = CFArrayCreate(NULL, &partition, 1, &kCFTypeArrayCallBacks);
    const void *key = CFSTR("Partitions");
    CFDictionaryRef object = values ? CFDictionaryCreate(NULL, &key, (const void **)&values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
    CFDataRef xml = object ? CFPropertyListCreateData(NULL, object, kCFPropertyListXMLFormat_v1_0, 0, NULL) : NULL;
    OSStatus status = xml && CFDataGetLength(xml) > 0 && CFDataGetLength(xml) <= 16384 ? errSecSuccess : errSecDecode;
    if (status == errSecSuccess) {
        size_t n = (size_t)CFDataGetLength(xml);
        unsigned char *hex = malloc(n * 2);
        if (!hex) status = errSecAllocate;
        else {
            static const unsigned char digits[] = "0123456789abcdef";
            const unsigned char *bytes = CFDataGetBytePtr(xml);
            for (size_t i = 0; i < n; i++) { hex[i*2] = digits[bytes[i] >> 4]; hex[i*2+1] = digits[bytes[i] & 15]; }
            *out = CFStringCreateWithBytes(NULL, hex, (CFIndex)(n*2), kCFStringEncodingASCII, false);
            if (!*out) status = errSecAllocate;
            free(hex);
        }
    }
    if (xml) CFRelease(xml);
    if (object) CFRelease(object);
    if (values) CFRelease(values);
    return status;
}

static int KVQPlaintextTag(CSSM_ACL_AUTHORIZATION_TAG tag) {
    return tag == CSSM_ACL_AUTHORIZATION_ANY || tag == CSSM_ACL_AUTHORIZATION_DECRYPT ||
        tag == CSSM_ACL_AUTHORIZATION_EXPORT_CLEAR || tag == CSSM_ACL_AUTHORIZATION_EXPORT_WRAPPED;
}

static int KVQExactApplication(CFTypeRef application, CFDataRef expected, KVQSymbols symbols) {
    if (!application || CFGetTypeID(application) != SecTrustedApplicationGetTypeID() || !expected) return 0;
    SecRequirementRef requirement = NULL; CFDataRef data = NULL;
    OSStatus status = symbols.copy((SecTrustedApplicationRef)application, &requirement);
    if (status == errSecSuccess && !requirement) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(requirement, kSecCSDefaultFlags, &data);
    int ok = status == errSecSuccess && data && CFEqual(data, expected);
    if (data) CFRelease(data);
    if (requirement) CFRelease(requirement);
    return ok;
}

// Only the already-agreed release/partition predicates are enforced here.
// No unknown owner/writer/native subject becomes an accepted root policy.
static OSStatus KVQIntendedBindings(SecAccessRef access, CFDataRef required, CFStringRef partitionDescription, KVQSymbols symbols) {
    CFArrayRef list = NULL;
    OSStatus status = SecAccessCopyACLList(access, &list);
    if (status == errSecSuccess && (!list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64)) status = errSecDecode;
    unsigned int releases = 0, partitions = 0;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef candidate = CFArrayGetValueAtIndex(list, i);
        if (!candidate || CFGetTypeID(candidate) != SecACLGetTypeID()) { status = errSecDecode; break; }
        SecACLRef acl = (SecACLRef)candidate;
        CSSM_ACL_AUTHORIZATION_TAG tags[64]; uint32 count = 64;
        status = SecACLGetAuthorizations(acl, tags, &count);
        if (status != errSecSuccess || count > 64) { status = errSecDecode; break; }
        int release = 0;
        for (uint32 j = 0; j < count; j++) if (KVQPlaintextTag(tags[j])) release = 1;
        CFArrayRef names = SecACLCopyAuthorizations(acl), apps = NULL;
        CFStringRef description = NULL; SecKeychainPromptSelector prompt = 0;
        if (!names || CFGetTypeID(names) != CFArrayGetTypeID() || CFArrayGetCount(names) > 64) status = errSecDecode;
        int partition = status == errSecSuccess && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), kSecACLAuthorizationPartitionID);
        if (status == errSecSuccess && (release || partition)) status = SecACLCopyContents(acl, &apps, &description, &prompt);
        if (status == errSecSuccess && release) {
            releases++;
            if (!apps || CFGetTypeID(apps) != CFArrayGetTypeID() || CFArrayGetCount(apps) != 1 ||
                !KVQExactApplication(CFArrayGetValueAtIndex(apps, 0), required, symbols)) status = errSecAuthFailed;
        }
        if (status == errSecSuccess && partition) {
            partitions++;
            if (partitions > 1 || release || CFArrayGetCount(names) != 1 || !description || !CFEqual(description, partitionDescription)) status = errSecAuthFailed;
        }
        if (description) CFRelease(description);
        if (apps) CFRelease(apps);
        if (names) CFRelease(names);
    }
    if (status == errSecSuccess && (releases == 0 || partitions != 1)) status = errSecAuthFailed;
    if (list) CFRelease(list);
    return status;
}

// The application's trust is compiled from the fixed certificate requirement,
// never derived from a path. Defaults/owner/writer representations are fully
// observed afterward and are NOT admitted as a root-storage policy here.
static OSStatus KVQIntendedAccess(KVQSymbols symbols, SecAccessRef *out) {
    *out = NULL;
    SecRequirementRef requirement = NULL;
    CFDataRef requirementData = NULL;
    SecTrustedApplicationRef application = NULL;
    CFArrayRef trusted = NULL, list = NULL;
    CFStringRef partitionDescription = NULL;
    SecACLRef partitionACL = NULL;
    OSStatus status = SecRequirementCreateWithString(CFSTR("identifier \"works.relux.keyvault\" and anchor apple generic and certificate leaf = H\"d71190abe54185f908169ee9ca538d4066942c0f\" and certificate 1[field.1.2.840.113635.100.6.2.1]"), kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess && !requirement) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);
    if (status == errSecSuccess && !requirementData) status = errSecAuthFailed;
    if (status == errSecSuccess) status = symbols.create("keyvault-root-acl-qualification:/vault", requirement, &application);
    if (status == errSecSuccess && !KVQExactApplication(application, requirementData, symbols)) status = errSecAuthFailed;
    if (status == errSecSuccess) {
        trusted = CFArrayCreate(NULL, (const void **)&application, 1, &kCFTypeArrayCallBacks);
        status = trusted ? SecAccessCreate(CFSTR("Root ACL public qualification"), trusted, out) : errSecAllocate;
    }
    if (status == errSecSuccess && !*out) status = errSecDecode;
    if (status == errSecSuccess) status = SecAccessCopyACLList(*out, &list);
    if (status == errSecSuccess && (!list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64)) status = errSecDecode;
    if (status == errSecSuccess) status = KVQPartitionDescription(&partitionDescription);
    unsigned int releases = 0, partitions = 0;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef entry = CFArrayGetValueAtIndex(list, i);
        if (!entry || CFGetTypeID(entry) != SecACLGetTypeID()) { status = errSecDecode; break; }
        SecACLRef acl = (SecACLRef)entry;
        CSSM_ACL_AUTHORIZATION_TAG tags[64]; uint32 count = 64;
        status = SecACLGetAuthorizations(acl, tags, &count);
        if (status != errSecSuccess || count > 64) { status = errSecDecode; break; }
        int release = 0;
        for (uint32 j = 0; j < count; j++) if (KVQPlaintextTag(tags[j])) release = 1;
        CFArrayRef names = SecACLCopyAuthorizations(acl);
        if (!names || CFGetTypeID(names) != CFArrayGetTypeID() || CFArrayGetCount(names) > 64) status = errSecDecode;
        int partition = status == errSecSuccess && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), kSecACLAuthorizationPartitionID);
        if (status == errSecSuccess && partition) {
            partitions++;
            if (partitions > 1 || CFArrayGetCount(names) != 1 || release) status = errSecDecode;
            else status = SecACLSetContents(acl, NULL, partitionDescription, 0);
        } else if (status == errSecSuccess && release) {
            releases++;
            CFArrayRef previous = NULL; CFStringRef description = NULL; SecKeychainPromptSelector prompt = 0;
            status = SecACLCopyContents(acl, &previous, &description, &prompt);
            if (status == errSecSuccess) status = SecACLSetContents(acl, trusted, description ? description : CFSTR("Root ACL public qualification"), prompt);
            if (previous) CFRelease(previous);
            if (description) CFRelease(description);
        }
        if (names) CFRelease(names);
    }
    if (status == errSecSuccess && releases == 0) status = errSecDecode;
    if (status == errSecSuccess && partitions == 0) {
        status = SecACLCreateWithSimpleContents(*out, NULL, partitionDescription, 0, &partitionACL);
        const void *tag = kSecACLAuthorizationPartitionID;
        CFArrayRef tags = CFArrayCreate(NULL, &tag, 1, &kCFTypeArrayCallBacks);
        if (status == errSecSuccess && (!partitionACL || !tags)) status = errSecAllocate;
        if (status == errSecSuccess) status = SecACLUpdateAuthorizations(partitionACL, tags);
        if (tags) CFRelease(tags);
    }
    if (status == errSecSuccess) status = KVQIntendedBindings(*out, requirementData, partitionDescription, symbols);
    if (partitionACL) CFRelease(partitionACL);
    if (partitionDescription) CFRelease(partitionDescription);
    if (list) CFRelease(list);
    if (trusted) CFRelease(trusted);
    if (application) CFRelease(application);
    if (requirementData) CFRelease(requirementData);
    if (requirement) CFRelease(requirement);
    if (status != errSecSuccess && *out) { CFRelease(*out); *out = NULL; }
    return status;
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
int MacKeyVaultRootQualificationCreate(unsigned char **reference, size_t *referenceLength,
    unsigned char **before, size_t *beforeLength, unsigned char **after, size_t *afterLength, int *outcome) {
    if (!reference || !referenceLength || !before || !beforeLength || !after || !afterLength || !outcome) return 1;
    *reference = *before = *after = NULL;
    *referenceLength = *beforeLength = *afterLength = 0; *outcome = 1;
    KVQSymbols symbols = {0};
    if (!KVQResolve(&symbols) || KVQSelf(1) != errSecSuccess) return 1;
    SecKeychainRef keychain = NULL;
    if (KVQLogin(&keychain) != errSecSuccess) return 1;
    SecAccessRef intended = NULL, actual = NULL;
    SecKeychainItemRef item = NULL;
    CFDataRef beforeFrame = NULL, afterFrame = NULL;
    CFTypeRef added = NULL;
    CFMutableDictionaryRef query = NULL;
    OSStatus status = KVQIntendedAccess(symbols, &intended);
    if (status == errSecSuccess) status = KVQProject(intended, symbols, &beforeFrame);
    if (status == errSecSuccess && !KVQCopyPublicData(beforeFrame, before, beforeLength, 1048576)) status = errSecAllocate;
    if (status == errSecSuccess) {
        query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!query) status = errSecAllocate;
    }
    CFDataRef marker = NULL;
    if (status == errSecSuccess) {
        const char *value = "keyvault-root-acl-qualification/1";
        marker = CFDataCreate(NULL, (const unsigned char *)value, (CFIndex)strlen(value));
        if (!marker) status = errSecAllocate;
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
        if (status == errSecDuplicateItem) *outcome = 1;
        if (status == errSecSuccess && !KVQCopyPublicData(added, reference, referenceLength, 16384)) status = errSecDecode;
        if (status == errSecSuccess) status = KVQFind(keychain, *reference, *referenceLength, &item);
        if (status == errSecSuccess) status = KVQOwnMarker(item);
        if (status == errSecSuccess) status = SecKeychainItemCopyAccess(item, &actual);
        if (status == errSecSuccess && !actual) status = errSecDecode;
        if (status == errSecSuccess) status = KVQProject(actual, symbols, &afterFrame);
        if (status == errSecSuccess && !KVQCopyPublicData(afterFrame, after, afterLength, 1048576)) status = errSecAllocate;
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
