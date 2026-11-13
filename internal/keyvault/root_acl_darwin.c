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

// Shared root-item ACL unit. The public-marker qualification lane and the
// production root-grants adapter build their access object, check the running
// code and project the actual ACL through THIS code, so the qualified
// observation and the production item cannot silently diverge. This unit has
// no item namespace, no Keychain add/read/delete and no private-value access.

// Failure diagnostics. The FIRST failure recorded on the calling thread wins and
// later statuses never overwrite it. The qualification create call resets the
// record on entry and takes it before returning, inside one cgo call (one OS
// thread). The record is a stage id (security_darwin.h) and a Security OSStatus:
// no item data, no path, no string.
static _Thread_local int kvqDiagStage;
static _Thread_local OSStatus kvqDiagStatus;

void KVQDiagReset(void) {
    kvqDiagStage = KVQ_STAGE_NONE;
    kvqDiagStatus = errSecSuccess;
}

void KVQDiagNote(int stage, OSStatus status) {
    if (kvqDiagStage == KVQ_STAGE_NONE && stage != KVQ_STAGE_NONE && status != errSecSuccess) {
        kvqDiagStage = stage;
        kvqDiagStatus = status;
    }
}

int KVQDiagTake(int *stage, OSStatus *status) {
    *stage = kvqDiagStage;
    *status = kvqDiagStatus;
    return kvqDiagStage != KVQ_STAGE_NONE;
}

void KVQDiagRetagProjection(int base) {
    if (kvqDiagStage >= KVQ_STAGE_PROJECT_OWNER_ACL && kvqDiagStage <= KVQ_STAGE_PROJECT_APPLICATIONS) {
        kvqDiagStage = base + (kvqDiagStage - KVQ_STAGE_PROJECT_OWNER_ACL);
    }
}

// Test-only fault injection. These definitions exist ONLY when the package is built
// with the kvqfault tag (which defines KVQ_FAULT_INJECTION); a normal build has no
// injection state, no hook and no entry point.
#ifdef KVQ_FAULT_INJECTION
static _Thread_local int kvqFaultStage;
static _Thread_local OSStatus kvqFaultStatus;
// A test may ignore the natural verdict of the release-requirement check so that
// the stages after it stay reachable on a system where that check itself fails.
static _Thread_local int kvqMaskRequirement;
// A test may likewise ignore the natural verdict of the projection groups, so that
// the BEFORE and AFTER ids can be armed on a system where a group fails naturally.
static _Thread_local int kvqMaskProjection;
// A test may make the projection see a string where it expects an ACL object, the
// shape SecAccessCopyOwnerAndACL returns, to prove that such an element is refused.
static _Thread_local int kvqFaultNonACL;
#define KVQ_NATURAL_MASKED() (kvqMaskProjection)
#define KVQ_FAULT(stage, var) do { if (kvqFaultStage == (stage)) (var) = kvqFaultStatus; } while (0)
#else
#define KVQ_FAULT(stage, var) do { } while (0)
#define KVQ_NATURAL_MASKED() 0
#endif

// Runs one step while nothing has failed and records its failure at stage. An armed
// test fault replaces the step's own status.
#define KVQ_STEP(stage, var, expr) do { \
    if ((var) == errSecSuccess) { \
        (var) = (expr); \
        KVQ_FAULT((stage), (var)); \
        if ((var) != errSecSuccess) KVQDiagNote((stage), (var)); \
    } } while (0)

// Fails the current step with err when cond holds (cond is evaluated only while
// nothing has failed), or with the armed test fault.
#define KVQ_FAIL_IF(stage, var, cond, err) do { \
    if ((var) == errSecSuccess) { \
        OSStatus kvqForced = errSecSuccess; \
        if (cond) kvqForced = (err); \
        KVQ_FAULT((stage), kvqForced); \
        if (kvqForced != errSecSuccess) { (var) = kvqForced; KVQDiagNote((stage), (var)); } \
    } } while (0)

// Closes one group of projection writes: the first group whose writes failed, or
// that has an armed test fault, names the failure.
#define KVQ_GROUP_END(stage) do { \
    OSStatus kvqForced = errSecSuccess; \
    KVQ_FAULT((stage), kvqForced); \
    if (kvqForced != errSecSuccess && !failGroup) { failGroup = (stage); failStatus = kvqForced; ok = 0; } \
    else if (!ok && !failGroup) { if (KVQ_NATURAL_MASKED()) ok = 1; else { failGroup = (stage); failStatus = errSecDecode; } } } while (0)


int KVQResolve(KVQSymbols *out) {
    out->create = (KVQCreateRequirement)dlsym(RTLD_DEFAULT, "SecTrustedApplicationCreateFromRequirement");
    out->copy = (KVQCopyRequirement)dlsym(RTLD_DEFAULT, "SecTrustedApplicationCopyRequirement");
    OSStatus status = out->create != NULL && out->copy != NULL ? errSecSuccess : errSecUnimplemented;
    KVQ_FAULT(KVQ_STAGE_RESOLVE, status);
    if (status != errSecSuccess) {
        KVQDiagNote(KVQ_STAGE_RESOLVE, status);
        return 0;
    }
    return 1;
}

static int KVQHashEquals(const unsigned char *bytes, size_t length, const char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        if (hex[2*i] != digits[bytes[i] >> 4] || hex[2*i+1] != digits[bytes[i] & 15]) return 0;
    }
    return hex[2*length] == 0;
}

const char *KVQRole(int role) {
    switch (role) {
    case 1: return "works.relux.keyvault";
    case 2: return "works.relux.keyvault.enclave";
    case 4: return "works.relux.keyvault.qualification-foreign";
    default: return NULL; // Seed and every unknown role are excluded.
    }
}

// Check the ACTUAL running code, its complete leaf and fixed binary DR. No
// path-only identity, ad-hoc flags, implicit team DR or caller requirement.
OSStatus KVQCode(int role, int pid, const unsigned char *expectedHash, size_t hashLength) {
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

OSStatus KVQSelf(int role) {
    OSStatus status = KVQCode(role, 0, NULL, 0);
    KVQ_FAULT(KVQ_STAGE_SELF_CODE, status);
    if (status != errSecSuccess) KVQDiagNote(KVQ_STAGE_SELF_CODE, status);
    return status;
}

OSStatus KVQLogin(SecKeychainRef *out) {
    *out = NULL;
    OSStatus status = errSecSuccess;
    KVQ_STEP(KVQ_STAGE_LOGIN_INTERACTION, status, SecKeychainSetUserInteractionAllowed(false));
    if (status != errSecSuccess) return status;
    struct passwd user, *found = NULL;
    char buffer[16384], path[PATH_MAX], actual[PATH_MAX];
    int length = 0;
    KVQ_FAIL_IF(KVQ_STAGE_LOGIN_ACCOUNT_PATH, status,
        getpwuid_r(getuid(), &user, buffer, sizeof(buffer), &found) != 0 || !found || !user.pw_dir || user.pw_uid != getuid() || user.pw_dir[0] != '/',
        errSecNotAvailable);
    if (status != errSecSuccess) return status;
    length = snprintf(path, sizeof(path), "%s/Library/Keychains/login.keychain-db", user.pw_dir);
    KVQ_FAIL_IF(KVQ_STAGE_LOGIN_ACCOUNT_PATH, status, length <= 0 || (size_t)length >= sizeof(path), errSecParam);
    if (status != errSecSuccess) return status;
    KVQ_STEP(KVQ_STAGE_LOGIN_OPEN, status, SecKeychainOpen(path, out));
    KVQ_FAIL_IF(KVQ_STAGE_LOGIN_OPEN, status, !*out, errSecNotAvailable);
    UInt32 capacity = sizeof(actual);
    KVQ_STEP(KVQ_STAGE_LOGIN_PATH_CHECK, status, SecKeychainGetPath(*out, &capacity, actual));
    KVQ_FAIL_IF(KVQ_STAGE_LOGIN_PATH_CHECK, status,
        capacity != (UInt32)length || capacity >= sizeof(actual) || memcmp(actual, path, (size_t)length) != 0, errSecAuthFailed);
    SecKeychainStatus state = 0;
    KVQ_STEP(KVQ_STAGE_LOGIN_STATUS, status, SecKeychainGetStatus(*out, &state));
    KVQ_FAIL_IF(KVQ_STAGE_LOGIN_LOCKED, status, !(state & kSecUnlockStateStatus), errSecInteractionNotAllowed);
    if (status != errSecSuccess && *out) { CFRelease(*out); *out = NULL; }
    return status;
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

OSStatus KVQProject(SecAccessRef access, KVQSymbols symbols, CFDataRef *out) {
    *out = NULL;
    uid_t uid = 0; gid_t gid = 0; SecAccessOwnerType owner = 0;
    // SecAccessCopyOwnerAndACL is read for the owner only: its list holds strings, not
    // ACL objects, on current macOS. The ACL objects come from SecAccessCopyACLList, the
    // call the access constructor and its bindings already read.
    CFArrayRef ownerList = NULL, list = NULL;
    OSStatus status = errSecSuccess;
    KVQ_STEP(KVQ_STAGE_PROJECT_OWNER_ACL, status, SecAccessCopyOwnerAndACL(access, &uid, &gid, &owner, &ownerList));
    if (ownerList) CFRelease(ownerList);
    KVQ_STEP(KVQ_STAGE_PROJECT_OWNER_ACL, status, SecAccessCopyACLList(access, &list));
    CFMutableDataRef frame = CFDataCreateMutable(NULL, 0);
    KVQ_FAIL_IF(KVQ_STAGE_PROJECT_OWNER_ACL, status,
        !frame || !list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64 ||
        !KVQPut(frame, "KVQP1", 5) || !KVQU32(frame, uid) || !KVQU32(frame, gid) || !KVQU32(frame, owner) || !KVQU32(frame, (uint32_t)CFArrayGetCount(list)),
        errSecDecode);
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef candidate = CFArrayGetValueAtIndex(list, i);
#ifdef KVQ_FAULT_INJECTION
        if (kvqFaultNonACL) candidate = CFSTR("not an ACL");
#endif
        KVQ_FAIL_IF(KVQ_STAGE_PROJECT_AUTHORIZATIONS, status, !candidate || CFGetTypeID(candidate) != SecACLGetTypeID(), errSecDecode);
        if (status != errSecSuccess) break;
        SecACLRef acl = (SecACLRef)candidate;
        // Preserve the complete numeric set even when symbolic names are
        // unavailable/unknown. No authorization tag is classified as harmless.
        CSSM_ACL_AUTHORIZATION_TAG numbers[64]; uint32 numberCount = 64;
        KVQ_STEP(KVQ_STAGE_PROJECT_AUTHORIZATIONS, status, SecACLGetAuthorizations(acl, numbers, &numberCount));
        KVQ_FAIL_IF(KVQ_STAGE_PROJECT_AUTHORIZATIONS, status, numberCount > 64, errSecDecode);
        if (status != errSecSuccess) break;
        int failGroup = 0;
        OSStatus failStatus = errSecSuccess;
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
        KVQ_GROUP_END(KVQ_STAGE_PROJECT_AUTHORIZATIONS);
        CFArrayRef apps = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        OSStatus contents = SecACLCopyContents(acl, &apps, &description, &prompt);
        int readable = contents == errSecSuccess && (!apps || CFGetTypeID(apps) == CFArrayGetTypeID()) &&
            (!description || CFGetTypeID(description) == CFStringGetTypeID());
        if (readable && apps && CFArrayGetCount(apps) > 64) ok = 0;
        ok = ok && KVQU32(frame, readable ? 0 : 1) && KVQU32(frame, readable ? (description ? 1 : 0) : 2);
        ok = ok && (readable && description ? KVQText(frame, description, 32768) : KVQEmpty(frame)) && KVQU32(frame, readable ? (uint32_t)prompt : 0);
        KVQ_GROUP_END(KVQ_STAGE_PROJECT_CONTENTS);
        // CopyContents exposes a 16-bit selector. Also retain the complete
        // underlying CSSM version/32-bit flags; unknown high bits are not lost.
        CFArrayRef rawApps = NULL; CFStringRef rawDescription = NULL;
        CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR rawPrompt = {0, 0};
        OSStatus rawStatus = SecACLCopySimpleContents(acl, &rawApps, &rawDescription, &rawPrompt);
        ok = ok && KVQU32(frame, rawStatus == errSecSuccess ? 0 : 1) &&
            KVQU32(frame, rawStatus == errSecSuccess ? rawPrompt.version : 0) && KVQU32(frame, rawStatus == errSecSuccess ? rawPrompt.flags : 0);
        if (rawApps) CFRelease(rawApps);
        if (rawDescription) CFRelease(rawDescription);
        KVQ_GROUP_END(KVQ_STAGE_PROJECT_RAW_CONTENTS);
        ok = ok && KVQU32(frame, readable ? (apps ? 1 : 0) : 2) && KVQU32(frame, readable && apps ? (uint32_t)CFArrayGetCount(apps) : 0);
        if (readable && apps) for (CFIndex j = 0; ok && j < CFArrayGetCount(apps); j++) ok = KVQApplication(frame, CFArrayGetValueAtIndex(apps, j), symbols);
        KVQ_GROUP_END(KVQ_STAGE_PROJECT_APPLICATIONS);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (!ok) {
            status = failStatus != errSecSuccess ? failStatus : errSecDecode;
            KVQDiagNote(failGroup ? failGroup : KVQ_STAGE_PROJECT_APPLICATIONS, status);
        }
    }
    if (list) CFRelease(list);
    if (status == errSecSuccess) *out = frame;
    else if (frame) CFRelease(frame);
    return status;
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

// Returns errSecSuccess only for exactly the expected requirement. *differs is set
// to 1 when the requirement was readable but not byte-equal to expected, and 0 for
// every other failure (wrong type, SPI failure, NULL requirement, unreadable data).
static OSStatus KVQExactApplicationStatus(CFTypeRef application, CFDataRef expected, KVQSymbols symbols, int *differs) {
    if (differs) *differs = 0;
    if (!application || CFGetTypeID(application) != SecTrustedApplicationGetTypeID() || !expected) return errSecDecode;
    SecRequirementRef requirement = NULL; CFDataRef data = NULL;
    OSStatus status = symbols.copy((SecTrustedApplicationRef)application, &requirement);
    if (status == errSecSuccess && !requirement) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(requirement, kSecCSDefaultFlags, &data);
    if (status == errSecSuccess && !data) status = errSecAuthFailed;
    if (status == errSecSuccess && !CFEqual(data, expected)) {
        status = errSecAuthFailed;
        if (differs) *differs = 1;
    }
    if (data) CFRelease(data);
    if (requirement) CFRelease(requirement);
    return status;
}

static int KVQExactApplication(CFTypeRef application, CFDataRef expected, KVQSymbols symbols) {
    return KVQExactApplicationStatus(application, expected, symbols, NULL) == errSecSuccess;
}

// Only the already-agreed release/partition predicates are enforced here.
// No unknown owner/writer/native subject becomes an accepted root policy.
static OSStatus KVQIntendedBindings(SecAccessRef access, CFDataRef required, CFStringRef partitionDescription, KVQSymbols symbols) {
    CFArrayRef list = NULL;
    OSStatus status = errSecSuccess;
    KVQ_STEP(KVQ_STAGE_BIND_ACL_LIST, status, SecAccessCopyACLList(access, &list));
    KVQ_FAIL_IF(KVQ_STAGE_BIND_ACL_LIST, status, !list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64, errSecDecode);
    unsigned int releases = 0, partitions = 0;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef candidate = CFArrayGetValueAtIndex(list, i);
        KVQ_FAIL_IF(KVQ_STAGE_BIND_ACL_READ, status, !candidate || CFGetTypeID(candidate) != SecACLGetTypeID(), errSecDecode);
        if (status != errSecSuccess) break;
        SecACLRef acl = (SecACLRef)candidate;
        CSSM_ACL_AUTHORIZATION_TAG tags[64]; uint32 count = 64;
        KVQ_STEP(KVQ_STAGE_BIND_ACL_READ, status, SecACLGetAuthorizations(acl, tags, &count));
        KVQ_FAIL_IF(KVQ_STAGE_BIND_ACL_READ, status, count > 64, errSecDecode);
        if (status != errSecSuccess) break;
        int release = 0;
        for (uint32 j = 0; j < count; j++) if (KVQPlaintextTag(tags[j])) release = 1;
        CFArrayRef names = SecACLCopyAuthorizations(acl), apps = NULL;
        CFStringRef description = NULL; SecKeychainPromptSelector prompt = 0;
        KVQ_FAIL_IF(KVQ_STAGE_BIND_ACL_READ, status, !names || CFGetTypeID(names) != CFArrayGetTypeID() || CFArrayGetCount(names) > 64, errSecDecode);
        int partition = status == errSecSuccess && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), kSecACLAuthorizationPartitionID);
        if (release || partition) KVQ_STEP(KVQ_STAGE_BIND_ACL_READ, status, SecACLCopyContents(acl, &apps, &description, &prompt));
        if (status == errSecSuccess && release) {
            releases++;
            KVQ_FAIL_IF(KVQ_STAGE_BIND_RELEASE_COUNT, status, !apps || CFGetTypeID(apps) != CFArrayGetTypeID() || CFArrayGetCount(apps) != 1, errSecAuthFailed);
            if (status == errSecSuccess) {
                int differs = 0;
                OSStatus exact = KVQExactApplicationStatus(CFArrayGetValueAtIndex(apps, 0), required, symbols, &differs);
#ifdef KVQ_FAULT_INJECTION
                if (kvqMaskRequirement) exact = errSecSuccess;
                if (kvqFaultStage == KVQ_STAGE_BIND_RELEASE_REQUIREMENT_DIFFERS) { exact = kvqFaultStatus; differs = 1; }
                else if (kvqFaultStage == KVQ_STAGE_BIND_RELEASE_REQUIREMENT_READ) { exact = kvqFaultStatus; differs = 0; }
#endif
                if (exact != errSecSuccess) {
                    status = exact;
                    KVQDiagNote(differs ? KVQ_STAGE_BIND_RELEASE_REQUIREMENT_DIFFERS : KVQ_STAGE_BIND_RELEASE_REQUIREMENT_READ, status);
                }
            }
        }
        if (status == errSecSuccess && partition) {
            partitions++;
            KVQ_FAIL_IF(KVQ_STAGE_BIND_PARTITION, status,
                partitions > 1 || release || CFArrayGetCount(names) != 1 || !description || !CFEqual(description, partitionDescription), errSecAuthFailed);
        }
        if (description) CFRelease(description);
        if (apps) CFRelease(apps);
        if (names) CFRelease(names);
    }
    KVQ_FAIL_IF(KVQ_STAGE_BIND_COUNTS, status, releases == 0 || partitions != 1, errSecAuthFailed);
    if (list) CFRelease(list);
    return status;
}

// The application's trust is compiled from the fixed certificate requirement,
// never derived from a path. Defaults/owner/writer representations are fully
// observed afterward and are NOT admitted as a root-storage policy here.
// descriptor names the access in system dialogs and becomes the description of
// the projected ACLs; applicationLabel only labels the trusted application. Each
// caller passes its own fixed strings, never caller input.
OSStatus KVQIntendedAccess(KVQSymbols symbols, const char *descriptor, const char *applicationLabel, SecAccessRef *out) {
    *out = NULL;
    if (!descriptor || !descriptor[0] || !applicationLabel || !applicationLabel[0]) return errSecParam;
    CFStringRef descriptorText = CFStringCreateWithCString(NULL, descriptor, kCFStringEncodingUTF8);
    if (!descriptorText) return errSecAllocate;
    SecRequirementRef requirement = NULL;
    CFDataRef requirementData = NULL;
    SecTrustedApplicationRef application = NULL;
    CFArrayRef trusted = NULL, list = NULL;
    CFStringRef partitionDescription = NULL;
    SecACLRef partitionACL = NULL;
    OSStatus status = errSecSuccess;
    KVQ_STEP(KVQ_STAGE_ACCESS_REQUIREMENT, status, SecRequirementCreateWithString(CFSTR("identifier \"works.relux.keyvault\" and anchor apple generic and certificate leaf = H\"d71190abe54185f908169ee9ca538d4066942c0f\" and certificate 1[field.1.2.840.113635.100.6.2.1]"), kSecCSDefaultFlags, &requirement));
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_REQUIREMENT, status, !requirement, errSecAuthFailed);
    KVQ_STEP(KVQ_STAGE_ACCESS_REQUIREMENT, status, SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData));
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_REQUIREMENT, status, !requirementData, errSecAuthFailed);
    KVQ_STEP(KVQ_STAGE_ACCESS_APPLICATION, status, symbols.create(applicationLabel, requirement, &application));
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_APPLICATION_EXACT, status, !KVQExactApplication(application, requirementData, symbols), errSecAuthFailed);
    if (status == errSecSuccess) trusted = CFArrayCreate(NULL, (const void **)&application, 1, &kCFTypeArrayCallBacks);
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_CREATE, status, !trusted, errSecAllocate);
    KVQ_STEP(KVQ_STAGE_ACCESS_CREATE, status, SecAccessCreate(descriptorText, trusted, out));
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_CREATE, status, !*out, errSecDecode);
    KVQ_STEP(KVQ_STAGE_ACCESS_ACL_LIST, status, SecAccessCopyACLList(*out, &list));
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_LIST, status, !list || CFGetTypeID(list) != CFArrayGetTypeID() || CFArrayGetCount(list) > 64, errSecDecode);
    KVQ_STEP(KVQ_STAGE_ACCESS_PARTITION_DESCRIPTION, status, KVQPartitionDescription(&partitionDescription));
    unsigned int releases = 0, partitions = 0;
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(list); i++) {
        CFTypeRef entry = CFArrayGetValueAtIndex(list, i);
        KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_WALK, status, !entry || CFGetTypeID(entry) != SecACLGetTypeID(), errSecDecode);
        if (status != errSecSuccess) break;
        SecACLRef acl = (SecACLRef)entry;
        CSSM_ACL_AUTHORIZATION_TAG tags[64]; uint32 count = 64;
        KVQ_STEP(KVQ_STAGE_ACCESS_ACL_WALK, status, SecACLGetAuthorizations(acl, tags, &count));
        KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_WALK, status, count > 64, errSecDecode);
        if (status != errSecSuccess) break;
        int release = 0;
        for (uint32 j = 0; j < count; j++) if (KVQPlaintextTag(tags[j])) release = 1;
        CFArrayRef names = SecACLCopyAuthorizations(acl);
        KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_WALK, status, !names || CFGetTypeID(names) != CFArrayGetTypeID() || CFArrayGetCount(names) > 64, errSecDecode);
        int partition = status == errSecSuccess && CFArrayContainsValue(names, CFRangeMake(0, CFArrayGetCount(names)), kSecACLAuthorizationPartitionID);
        if (status == errSecSuccess && partition) {
            partitions++;
            KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_WALK, status, partitions > 1 || CFArrayGetCount(names) != 1 || release, errSecDecode);
            KVQ_STEP(KVQ_STAGE_ACCESS_ACL_WALK, status, SecACLSetContents(acl, NULL, partitionDescription, 0));
        } else if (status == errSecSuccess && release) {
            releases++;
            CFArrayRef previous = NULL; CFStringRef description = NULL; SecKeychainPromptSelector prompt = 0;
            KVQ_STEP(KVQ_STAGE_ACCESS_ACL_WALK, status, SecACLCopyContents(acl, &previous, &description, &prompt));
            KVQ_STEP(KVQ_STAGE_ACCESS_ACL_WALK, status, SecACLSetContents(acl, trusted, description ? description : descriptorText, prompt));
            if (previous) CFRelease(previous);
            if (description) CFRelease(description);
        }
        if (names) CFRelease(names);
    }
    KVQ_FAIL_IF(KVQ_STAGE_ACCESS_ACL_WALK, status, releases == 0, errSecDecode);
    if (status == errSecSuccess && partitions == 0) {
        KVQ_STEP(KVQ_STAGE_ACCESS_PARTITION_ACL, status, SecACLCreateWithSimpleContents(*out, NULL, partitionDescription, 0, &partitionACL));
        const void *tag = kSecACLAuthorizationPartitionID;
        CFArrayRef tags = CFArrayCreate(NULL, &tag, 1, &kCFTypeArrayCallBacks);
        KVQ_FAIL_IF(KVQ_STAGE_ACCESS_PARTITION_ACL, status, !partitionACL || !tags, errSecAllocate);
        KVQ_STEP(KVQ_STAGE_ACCESS_PARTITION_ACL, status, SecACLUpdateAuthorizations(partitionACL, tags));
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
    CFRelease(descriptorText);
    if (status != errSecSuccess && *out) { CFRelease(*out); *out = NULL; }
    return status;
}

#ifdef KVQ_FAULT_INJECTION
// Test entry points, present only in a kvqfault build. They take and return plain
// ints so the Go test file needs no Security types, and they arm, run and disarm a
// fault inside one cgo call (one OS thread).

// Runs symbol resolution and the intended access object (with its bindings) with one
// stage armed (0 = a natural run). With maskRequirement the natural verdict of the
// release-requirement check is ignored, so the stages after it can be reached.
int KVQFaultRunIntended(int armStage, int armStatus, int maskRequirement, int *stage, int *status, int *completed) {
    KVQDiagReset();
    kvqFaultStage = armStage;
    kvqFaultStatus = (OSStatus)armStatus;
    kvqMaskRequirement = maskRequirement;
    *stage = 0; *status = 0; *completed = 0;
    KVQSymbols symbols = {0};
    OSStatus result = KVQResolve(&symbols) ? errSecSuccess : errSecUnimplemented;
    SecAccessRef access = NULL;
    if (result == errSecSuccess) result = KVQIntendedAccess(symbols, "Root ACL fault test", "keyvault-root-acl-fault-test:/vault", &access);
    if (access) CFRelease(access);
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    kvqMaskRequirement = 0;
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    *completed = result == errSecSuccess;
    return (int)result;
}

// Projects a plain in-memory access object twice, as BEFORE and then as AFTER, with
// one projection stage armed (a KVQ_STAGE_PROJECT_* id; with armAfter only for the
// second projection). The recorded failure is retagged exactly as the create call
// does. No code check, no Keychain, no intended access.
int KVQFaultRunProject(int armStage, int armStatus, int armAfter, int maskNatural, int *stage, int *status, int *completed) {
    KVQDiagReset();
    kvqMaskProjection = maskNatural;
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    *stage = 0; *status = 0; *completed = 0;
    KVQSymbols symbols = {0};
    OSStatus result = KVQResolve(&symbols) ? errSecSuccess : errSecUnimplemented;
    SecAccessRef access = NULL;
    CFDataRef frame = NULL;
    if (result == errSecSuccess) result = SecAccessCreate(CFSTR("Root ACL fault test"), NULL, &access);
    if (result == errSecSuccess && !access) result = errSecDecode;
    if (armStage != 0 && !armAfter) { kvqFaultStage = armStage; kvqFaultStatus = (OSStatus)armStatus; }
    if (result == errSecSuccess) {
        result = KVQProject(access, symbols, &frame);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_BEFORE_OWNER_ACL);
    }
    if (frame) { CFRelease(frame); frame = NULL; }
    kvqFaultStage = 0;
    if (result == errSecSuccess && armStage != 0 && armAfter) { kvqFaultStage = armStage; kvqFaultStatus = (OSStatus)armStatus; }
    if (result == errSecSuccess) {
        result = KVQProject(access, symbols, &frame);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_AFTER_OWNER_ACL);
    }
    if (frame) CFRelease(frame);
    if (access) CFRelease(access);
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    kvqMaskProjection = 0;
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    *completed = result == errSecSuccess;
    return (int)result;
}

// Runs the first half of the create call exactly as it runs there: symbol resolution,
// the intended access object, and its BEFORE projection, all natural (nothing armed).
// This reproduces the point where the create call refused on a real system.
int KVQFaultRunBefore(int *stage, int *status, int *completed) {
    KVQDiagReset();
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    *stage = 0; *status = 0; *completed = 0;
    KVQSymbols symbols = {0};
    OSStatus result = KVQResolve(&symbols) ? errSecSuccess : errSecUnimplemented;
    SecAccessRef access = NULL;
    CFDataRef frame = NULL;
    if (result == errSecSuccess) result = KVQIntendedAccess(symbols, "Root ACL fault test", "keyvault-root-acl-fault-test:/vault", &access);
    if (result == errSecSuccess) {
        result = KVQProject(access, symbols, &frame);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_BEFORE_OWNER_ACL);
    }
    if (frame) CFRelease(frame);
    if (access) CFRelease(access);
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    *completed = result == errSecSuccess;
    return (int)result;
}

// Describes the inputs of the authorizations group of the projection on a plain
// in-memory access object: for every ACL, whether its names are readable, how each
// name converts to UTF-8, and whether the projection's own text writer accepts it.
// out: [0] ACL count, [1] ACLs with unreadable names, [2] names examined, [3] names the
// UTF-8 conversion count check rejects, [4] names the projection's text writer
// rejects, [5] ACLs whose authorization numbers cannot be read, [6] length of the
// first rejected name in characters, [7] characters CFStringGetBytes reported for it.
// failName receives the first rejected name (authorization names are public constants).
int KVQFaultProbeAuthorizations(int *out, char *failName, int failNameSize) {
    for (int i = 0; i < 8; i++) out[i] = 0;
    if (failNameSize > 0) failName[0] = 0;
    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreate(CFSTR("Root ACL fault test"), NULL, &access);
    if (status != errSecSuccess || !access) return status != errSecSuccess ? (int)status : (int)errSecDecode;
    CFArrayRef list = NULL;
    status = SecAccessCopyACLList(access, &list);
    CFMutableDataRef scratch = CFDataCreateMutable(NULL, 0);
    if (status == errSecSuccess && list && scratch) {
        out[0] = (int)CFArrayGetCount(list);
        for (CFIndex i = 0; i < CFArrayGetCount(list); i++) {
            SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(list, i);
            CSSM_ACL_AUTHORIZATION_TAG numbers[64]; uint32 numberCount = 64;
            if (SecACLGetAuthorizations(acl, numbers, &numberCount) != errSecSuccess || numberCount > 64) out[5]++;
            CFArrayRef names = SecACLCopyAuthorizations(acl);
            if (!names || CFGetTypeID(names) != CFArrayGetTypeID() || CFArrayGetCount(names) > 64) { out[1]++; if (names) CFRelease(names); continue; }
            for (CFIndex j = 0; j < CFArrayGetCount(names); j++) {
                CFTypeRef name = CFArrayGetValueAtIndex(names, j);
                if (!name || CFGetTypeID(name) != CFStringGetTypeID()) { out[1]++; continue; }
                out[2]++;
                CFIndex characters = CFStringGetLength((CFStringRef)name), needed = 0;
                CFIndex converted = CFStringGetBytes((CFStringRef)name, CFRangeMake(0, characters), kCFStringEncodingUTF8, 0, false, NULL, 0, &needed);
                int countRejected = converted != characters;
                int textRejected = !KVQText(scratch, (CFStringRef)name, 1024);
                if (countRejected) out[3]++;
                if (textRejected) out[4]++;
                if ((countRejected || textRejected) && out[6] == 0) {
                    out[6] = (int)characters;
                    out[7] = (int)converted;
                    if (failNameSize > 0) (void)CFStringGetCString((CFStringRef)name, failName, failNameSize, kCFStringEncodingUTF8);
                }
            }
            CFRelease(names);
        }
    }
    if (scratch) CFRelease(scratch);
    if (list) CFRelease(list);
    CFRelease(access);
    return (int)status;
}

// Describes what SecAccessCopyOwnerAndACL, the call the projection reads its ACL list
// from, returns for a plain in-memory access object, next to what SecAccessCopyACLList
// (the call the access constructor and its bindings read) returns. out: [0] status of
// OwnerAndACL, [1] list present, [2] list is an array, [3] element count, [4] elements
// that are SecACL objects, [5] dictionaries, [6] data, [7] strings, [8] CFTypeID of the
// first element, [9] SecACLGetTypeID(), [10] status of SecACLGetAuthorizations on the
// first SecACL element (-1 if none), [11] its number count, [12] status of
// SecAccessCopyACLList, [13] its element count, [14] its elements that are SecACL objects.
int KVQFaultProbeOwnerACL(int *out) {
    for (int i = 0; i < 16; i++) out[i] = 0;
    out[10] = -1;
    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreate(CFSTR("Root ACL fault test"), NULL, &access);
    if (status != errSecSuccess || !access) return status != errSecSuccess ? (int)status : (int)errSecDecode;
    uid_t uid = 0; gid_t gid = 0; SecAccessOwnerType owner = 0;
    CFArrayRef list = NULL;
    out[0] = (int)SecAccessCopyOwnerAndACL(access, &uid, &gid, &owner, &list);
    out[9] = (int)SecACLGetTypeID();
    if (list) {
        out[1] = 1;
        out[2] = CFGetTypeID(list) == CFArrayGetTypeID();
        if (out[2]) {
            out[3] = (int)CFArrayGetCount(list);
            for (CFIndex i = 0; i < CFArrayGetCount(list); i++) {
                CFTypeRef element = CFArrayGetValueAtIndex(list, i);
                CFTypeID type = element ? CFGetTypeID(element) : 0;
                if (i == 0) out[8] = (int)type;
                if (type == SecACLGetTypeID()) {
                    out[4]++;
                    if (out[10] == -1) {
                        CSSM_ACL_AUTHORIZATION_TAG tags[64]; uint32 count = 64;
                        out[10] = (int)SecACLGetAuthorizations((SecACLRef)element, tags, &count);
                        out[11] = (int)count;
                    }
                } else if (type == CFDictionaryGetTypeID()) out[5]++;
                else if (type == CFDataGetTypeID()) out[6]++;
                else if (type == CFStringGetTypeID()) out[7]++;
            }
        }
        CFRelease(list);
    }
    CFArrayRef plain = NULL;
    out[12] = (int)SecAccessCopyACLList(access, &plain);
    if (plain) {
        out[13] = (int)CFArrayGetCount(plain);
        for (CFIndex i = 0; i < CFArrayGetCount(plain); i++) {
            CFTypeRef element = CFArrayGetValueAtIndex(plain, i);
            if (element && CFGetTypeID(element) == SecACLGetTypeID()) out[14]++;
        }
        CFRelease(plain);
    }
    CFRelease(access);
    return 0;
}

// Projects a plain in-memory access object while the projection sees a string in place
// of every ACL object, and reports the recorded failure retagged as the create call
// does. The expected record is the BEFORE authorizations stage with errSecDecode.
int KVQFaultRunProjectNonACL(int *stage, int *status, int *completed) {
    KVQDiagReset();
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    kvqFaultNonACL = 1;
    *stage = 0; *status = 0; *completed = 0;
    KVQSymbols symbols = {0};
    OSStatus result = KVQResolve(&symbols) ? errSecSuccess : errSecUnimplemented;
    SecAccessRef access = NULL;
    CFDataRef frame = NULL;
    if (result == errSecSuccess) result = SecAccessCreate(CFSTR("Root ACL fault test"), NULL, &access);
    if (result == errSecSuccess && !access) result = errSecDecode;
    if (result == errSecSuccess) {
        result = KVQProject(access, symbols, &frame);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_BEFORE_OWNER_ACL);
    }
    if (frame) CFRelease(frame);
    if (access) CFRelease(access);
    kvqFaultNonACL = 0;
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    *completed = result == errSecSuccess;
    return (int)result;
}

// Builds the intended access object and projects it twice. With fresh the second
// projection is of a second, separately built access object; otherwise it is the same
// object again. Both frames are copied out so a test can compare their bytes and decode
// them with the Go decoder.
int KVQFaultProjectTwice(int fresh, unsigned char *a, unsigned char *b, int capacity, int *la, int *lb, int *stage, int *status) {
    KVQDiagReset();
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    *la = 0; *lb = 0; *stage = 0; *status = 0;
    KVQSymbols symbols = {0};
    OSStatus result = KVQResolve(&symbols) ? errSecSuccess : errSecUnimplemented;
    SecAccessRef x = NULL, y = NULL;
    CFDataRef frameA = NULL, frameB = NULL;
    if (result == errSecSuccess) result = KVQIntendedAccess(symbols, "Root ACL fault test", "keyvault-root-acl-fault-test:/vault", &x);
    if (result == errSecSuccess) {
        if (fresh) result = KVQIntendedAccess(symbols, "Root ACL fault test", "keyvault-root-acl-fault-test:/vault", &y);
        else y = (SecAccessRef)CFRetain(x);
    }
    if (result == errSecSuccess) {
        result = KVQProject(x, symbols, &frameA);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_BEFORE_OWNER_ACL);
    }
    if (result == errSecSuccess) {
        result = KVQProject(y, symbols, &frameB);
        if (result != errSecSuccess) KVQDiagRetagProjection(KVQ_STAGE_AFTER_OWNER_ACL);
    }
    if (result == errSecSuccess && (CFDataGetLength(frameA) > capacity || CFDataGetLength(frameB) > capacity)) result = errSecAllocate;
    if (result == errSecSuccess) {
        memcpy(a, CFDataGetBytePtr(frameA), (size_t)CFDataGetLength(frameA));
        memcpy(b, CFDataGetBytePtr(frameB), (size_t)CFDataGetLength(frameB));
        *la = (int)CFDataGetLength(frameA);
        *lb = (int)CFDataGetLength(frameB);
    }
    if (frameA) CFRelease(frameA);
    if (frameB) CFRelease(frameB);
    if (x) CFRelease(x);
    if (y) CFRelease(y);
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    return (int)result;
}

// Runs only the login-keychain step with one fault armed (0 = a natural run).
int KVQFaultRunLogin(int armStage, int armStatus, int *stage, int *status, int *completed) {
    KVQDiagReset();
    kvqFaultStage = armStage;
    kvqFaultStatus = (OSStatus)armStatus;
    *stage = 0; *status = 0; *completed = 0;
    SecKeychainRef keychain = NULL;
    OSStatus result = KVQLogin(&keychain);
    if (keychain) CFRelease(keychain);
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    *completed = result == errSecSuccess;
    return (int)result;
}

// Runs the code check of the running executable with one fault armed.
int KVQFaultRunSelf(int armStage, int armStatus, int *stage, int *status) {
    KVQDiagReset();
    kvqFaultStage = armStage;
    kvqFaultStatus = (OSStatus)armStatus;
    *stage = 0; *status = 0;
    OSStatus result = KVQSelf(1);
    kvqFaultStage = 0;
    kvqFaultStatus = errSecSuccess;
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
    return (int)result;
}

// First-failure-wins control: two notes in order, only the first may be kept.
void KVQFaultNoteTwice(int firstStage, int firstStatus, int secondStage, int secondStatus, int *stage, int *status) {
    KVQDiagReset();
    KVQDiagNote(firstStage, (OSStatus)firstStatus);
    KVQDiagNote(secondStage, (OSStatus)secondStatus);
    OSStatus recorded = errSecSuccess; int recordedStage = 0;
    *stage = 0; *status = 0;
    if (KVQDiagTake(&recordedStage, &recorded)) { *stage = recordedStage; *status = (int)recorded; }
}
#endif
