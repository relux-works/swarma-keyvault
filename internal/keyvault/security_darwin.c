// Security.framework bridge for mac-keyvault.
//
// An ad-hoc signed CLI cannot persist keys in the Secure
// Enclave or the Data Protection keychain (-34018 errSecMissingEntitlement).
// kSecAttrAccessControl routes the item to the Data Protection keychain and
// fails the same way, so the login (file-based) keychain with a legacy
// SecAccess trusted-application list is the ACL mechanism this bridge uses:
// the item lives in the current user's login keychain and its private-key
// operations are trusted only for the calling binary.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

#include "security_darwin.h"

// Keep the namespace literal in agreement with NostrNamespace in nostr.go.
static const CFStringRef MacKeyVaultNostrService = CFSTR("works.relux.mac-keyvault.nostr.v1");

static CFStringRef MacKeyVaultString(const char *value) {
    return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFDataRef MacKeyVaultData(const char *value) {
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)value, (CFIndex)strlen(value));
}

static CFMutableDictionaryRef MacKeyVaultDictionary(void) {
    return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
}

static int MacKeyVaultErrorCode(CFErrorRef error) {
    if (error == NULL) return MacKeyVaultUnknownError;
    CFIndex code = CFErrorGetCode(error);
    return code == 0 ? MacKeyVaultUnknownError : (int)code;
}

// Copies the uncompressed X9.63 point of the public half into a malloc'd buffer.
static int MacKeyVaultCopyPublicPoint(SecKeyRef privateKey, unsigned char **out, size_t *outLen) {
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (publicKey == NULL) return MacKeyVaultPublicKeyUnavailable;
    CFErrorRef error = NULL;
    CFDataRef point = SecKeyCopyExternalRepresentation(publicKey, &error);
    CFRelease(publicKey);
    if (point == NULL) {
        int code = MacKeyVaultErrorCode(error);
        if (error != NULL) CFRelease(error);
        return code;
    }
    size_t length = (size_t)CFDataGetLength(point);
    unsigned char *buffer = malloc(length);
    if (buffer == NULL) {
        CFRelease(point);
        return MacKeyVaultUnknownError;
    }
    memcpy(buffer, CFDataGetBytePtr(point), length);
    CFRelease(point);
    *out = buffer;
    *outLen = length;
    return 0;
}

// Builds the legacy SecAccess whose trusted-application list contains only the
// calling binary (SecTrustedApplicationCreateFromPath(NULL) = current process).
static OSStatus MacKeyVaultCreateAccess(SecAccessRef *out) {
    SecTrustedApplicationRef self = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &self);
    if (status != errSecSuccess) return status;
    CFArrayRef trusted = CFArrayCreate(kCFAllocatorDefault, (const void **)&self, 1, &kCFTypeArrayCallBacks);
    CFRelease(self);
    status = SecAccessCreate(CFSTR("mac-keyvault private key"), trusted, out);
    CFRelease(trusted);
    return status;
}

int MacKeyVaultCreate(const char *label, const char *tag, int enclave, int userPresence,
                      unsigned char **outPub, size_t *outPubLen) {
    CFStringRef labelString = MacKeyVaultString(label);
    CFDataRef tagData = MacKeyVaultData(tag);
    CFMutableDictionaryRef privateAttrs = MacKeyVaultDictionary();
    CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privateAttrs, kSecAttrLabel, labelString);
    CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, tagData);

    int result = 0;
    SecAccessRef access = NULL;
    SecAccessControlRef control = NULL;
    if (enclave || userPresence) {
        // Both shapes need the Data Protection keychain; an unprovisioned binary
        // gets -34018 here and the caller surfaces that verbatim.
        SecAccessControlCreateFlags flags = enclave ? kSecAccessControlPrivateKeyUsage : 0;
        if (userPresence) flags |= kSecAccessControlUserPresence;
        CFErrorRef error = NULL;
        control = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                  flags, &error);
        if (control == NULL) {
            result = MacKeyVaultErrorCode(error);
            if (error != NULL) CFRelease(error);
            goto cleanup;
        }
        CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, control);
    } else {
        OSStatus status = MacKeyVaultCreateAccess(&access);
        if (status != errSecSuccess) {
            result = (int)status;
            goto cleanup;
        }
    }

    CFMutableDictionaryRef attrs = MacKeyVaultDictionary();
    // The SecAccess, like kSecAttrIsExtractable, is honoured only at the top
    // level of the legacy generate path; inside kSecPrivateKeyAttrs it is
    // ignored and the keychain's default (creator-only) access is installed
    // instead, which hides a broadened list (observed with
    // a two-application list inside kSecPrivateKeyAttrs produced a one-entry
    // ACL). At the top level the list is installed verbatim and the ACL
    // attestation test reads it back.
    if (access != NULL) CFDictionarySetValue(attrs, kSecAttrAccess, access);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256;
    CFNumberRef bitsNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsNumber);
    CFRelease(bitsNumber);
    CFDictionarySetValue(attrs, kSecAttrLabel, labelString);
    // Non-extractability must be requested at the top level: the legacy
    // keychain path of SecKeyCreateRandomKey ignores kSecAttrIsExtractable
    // inside kSecPrivateKeyAttrs and generates CSSM_KEYATTR_EXTRACTABLE keys
    // (an observed earlier key variant exported with status 0).
    // Here it clears CSSM_KEYATTR_EXTRACTABLE on the private half, both
    // export paths answer errSecDataNotAvailable (-25316), and the public
    // half stays readable through SecKeyCopyPublicKey.
    CFDictionarySetValue(attrs, kSecAttrIsExtractable, kCFBooleanFalse);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privateAttrs);
    if (enclave) CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(attrs, &error);
    CFRelease(attrs);
    if (key == NULL) {
        result = MacKeyVaultErrorCode(error);
        if (error != NULL) CFRelease(error);
        goto cleanup;
    }
    result = MacKeyVaultCopyPublicPoint(key, outPub, outPubLen);
    CFRelease(key);

cleanup:
    if (access != NULL) CFRelease(access);
    if (control != NULL) CFRelease(control);
    CFRelease(privateAttrs);
    CFRelease(tagData);
    CFRelease(labelString);
    return result;
}

static void MacKeyVaultAppendField(CFMutableDataRef out, const void *bytes, CFIndex length, char terminator) {
    if (bytes != NULL && length > 0) CFDataAppendBytes(out, (const UInt8 *)bytes, length);
    CFDataAppendBytes(out, (const UInt8 *)&terminator, 1);
}

static void MacKeyVaultAppendString(CFMutableDataRef out, CFStringRef value, char terminator) {
    if (value == NULL) {
        MacKeyVaultAppendField(out, NULL, 0, terminator);
        return;
    }
    CFDataRef data = CFStringCreateExternalRepresentation(kCFAllocatorDefault, value, kCFStringEncodingUTF8, 0);
    MacKeyVaultAppendField(out, data ? CFDataGetBytePtr(data) : NULL, data ? CFDataGetLength(data) : 0, terminator);
    if (data != NULL) CFRelease(data);
}

// Only attributes are read for keys outside `prefix`; SecKeyCopyPublicKey and
// every other per-key operation run only for labels that carry the prefix.
int MacKeyVaultList(const char *prefix, char **out, size_t *outLen) {
    CFMutableDictionaryRef query = MacKeyVaultDictionary();
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFTypeRef matches = NULL;
    OSStatus status = SecItemCopyMatching(query, &matches);
    CFRelease(query);
    if (status == errSecItemNotFound) {
        *out = NULL;
        *outLen = 0;
        return 0;
    }
    if (status != errSecSuccess) return (int)status;
    if (matches == NULL || CFGetTypeID(matches) != CFArrayGetTypeID()) {
        if (matches != NULL) CFRelease(matches);
        return MacKeyVaultUnknownError;
    }

    CFMutableDataRef buffer = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CFIndex count = CFArrayGetCount(matches);
    size_t prefixLen = strlen(prefix);
    int result = 0;
    for (CFIndex i = 0; i < count && result == 0; i++) {
        CFDictionaryRef item = CFArrayGetValueAtIndex(matches, i);
        if (CFGetTypeID(item) != CFDictionaryGetTypeID()) continue;
        CFStringRef label = CFDictionaryGetValue(item, kSecAttrLabel);
        if (label == NULL || CFGetTypeID(label) != CFStringGetTypeID()) continue;
        char labelBuffer[1024];
        if (!CFStringGetCString(label, labelBuffer, sizeof(labelBuffer), kCFStringEncodingUTF8)) continue;
        if (strncmp(labelBuffer, prefix, prefixLen) != 0) continue;

        CFTypeRef tag = CFDictionaryGetValue(item, kSecAttrApplicationTag);
        CFTypeRef ref = CFDictionaryGetValue(item, kSecValueRef);
        if (ref == NULL || CFGetTypeID(ref) != SecKeyGetTypeID()) continue;
        unsigned char *point = NULL;
        size_t pointLen = 0;
        int pointResult = MacKeyVaultCopyPublicPoint((SecKeyRef)ref, &point, &pointLen);
        MacKeyVaultAppendString(buffer, label, MacKeyVaultFieldSeparator);
        if (tag != NULL && CFGetTypeID(tag) == CFDataGetTypeID()) {
            MacKeyVaultAppendField(buffer, CFDataGetBytePtr(tag), CFDataGetLength(tag), MacKeyVaultFieldSeparator);
        } else {
            MacKeyVaultAppendField(buffer, NULL, 0, MacKeyVaultFieldSeparator);
        }
        char statusText[16];
        snprintf(statusText, sizeof(statusText), "%d", pointResult);
        MacKeyVaultAppendField(buffer, statusText, (CFIndex)strlen(statusText), MacKeyVaultFieldSeparator);
        // Hex keeps the raw point bytes clear of the record framing.
        static const char hex[] = "0123456789abcdef";
        for (size_t b = 0; b < pointLen; b++) {
            char pair[2] = { hex[point[b] >> 4], hex[point[b] & 0x0f] };
            CFDataAppendBytes(buffer, (const UInt8 *)pair, 2);
        }
        MacKeyVaultAppendField(buffer, NULL, 0, MacKeyVaultRecordSeparator);
        free(point);
    }
    CFRelease(matches);

    size_t length = (size_t)CFDataGetLength(buffer);
    char *copy = malloc(length + 1);
    if (copy == NULL) {
        CFRelease(buffer);
        return MacKeyVaultUnknownError;
    }
    memcpy(copy, CFDataGetBytePtr(buffer), length);
    copy[length] = '\0';
    CFRelease(buffer);
    *out = copy;
    *outLen = length;
    return result;
}

int MacKeyVaultDelete(const char *label) {
    CFStringRef labelString = MacKeyVaultString(label);
    CFMutableDictionaryRef query = MacKeyVaultDictionary();
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrLabel, labelString);
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    CFRelease(labelString);
    return (int)status;
}

// Finds the private half under label; the caller releases *out.
static OSStatus MacKeyVaultCopyPrivateKey(const char *label, SecKeyRef *out) {
    CFStringRef labelString = MacKeyVaultString(label);
    CFMutableDictionaryRef query = MacKeyVaultDictionary();
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecAttrLabel, labelString);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef ref = NULL;
    OSStatus status = SecItemCopyMatching(query, &ref);
    CFRelease(query);
    CFRelease(labelString);
    if (status != errSecSuccess) return status;
    if (ref == NULL || CFGetTypeID(ref) != SecKeyGetTypeID()) {
        if (ref != NULL) CFRelease(ref);
        return errSecItemNotFound;
    }
    *out = (SecKeyRef)ref;
    return errSecSuccess;
}

// Replaces the application tag (the record) of the private half only.
// SecItemUpdate is deliberately not used: on a legacy keychain key it writes
// kSecAttrApplicationTag into the PrintName (label) attribute and leaves the
// tag untouched, which orphans the item. The
// legacy attribute API addresses kSecKeyApplicationTag directly.
int MacKeyVaultUpdateTag(const char *label, const char *tag) {
    SecKeyRef key = NULL;
    OSStatus status = MacKeyVaultCopyPrivateKey(label, &key);
    if (status != errSecSuccess) return (int)status;
    SecKeychainAttribute attr = { kSecKeyApplicationTag, (UInt32)strlen(tag), (void *)tag };
    SecKeychainAttributeList list = { 1, &attr };
    status = SecKeychainItemModifyAttributesAndData((SecKeychainItemRef)key, &list, 0, NULL);
    CFRelease(key);
    return (int)status;
}

// Signs a SHA-256 digest with the private half under label. The digest
// algorithm variant is used so Security.framework signs the given bytes as
// the digest instead of hashing them again; the output is X9.62 DER.
int MacKeyVaultSign(const char *label, const unsigned char *digest, size_t digestLen,
                    unsigned char **out, size_t *outLen) {
    SecKeyRef key = NULL;
    OSStatus status = MacKeyVaultCopyPrivateKey(label, &key);
    if (status != errSecSuccess) return (int)status;
    CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, digest, (CFIndex)digestLen);
    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, &error);
    CFRelease(digestData);
    CFRelease(key);
    if (signature == NULL) {
        int code = MacKeyVaultErrorCode(error);
        if (error != NULL) CFRelease(error);
        return code;
    }
    size_t length = (size_t)CFDataGetLength(signature);
    unsigned char *buffer = malloc(length);
    if (buffer == NULL) {
        CFRelease(signature);
        return MacKeyVaultUnknownError;
    }
    memcpy(buffer, CFDataGetBytePtr(signature), length);
    CFRelease(signature);
    *out = buffer;
    *outLen = length;
    return 0;
}

// ECIES unwrap with the private half under label
// (kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM). The
// plaintext is returned to the caller; the private key stays in
// Security.framework. A tampered or foreign envelope fails GCM and comes back
// as the framework's error code (errSecParam, -50).
int MacKeyVaultDecrypt(const char *label, const unsigned char *in, size_t inLen,
                       unsigned char **out, size_t *outLen) {
    SecKeyRef key = NULL;
    OSStatus status = MacKeyVaultCopyPrivateKey(label, &key);
    if (status != errSecSuccess) return (int)status;
    CFDataRef envelope = CFDataCreate(kCFAllocatorDefault, in, (CFIndex)inLen);
    CFErrorRef error = NULL;
    CFDataRef plain = SecKeyCreateDecryptedData(key, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, envelope, &error);
    CFRelease(envelope);
    CFRelease(key);
    if (plain == NULL) {
        int code = MacKeyVaultErrorCode(error);
        if (error != NULL) CFRelease(error);
        return code;
    }
    size_t length = (size_t)CFDataGetLength(plain);
    unsigned char *buffer = malloc(length == 0 ? 1 : length);
    if (buffer == NULL) {
        CFRelease(plain);
        return MacKeyVaultUnknownError;
    }
    memcpy(buffer, CFDataGetBytePtr(plain), length);
    CFRelease(plain);
    *out = buffer;
    *outLen = length;
    return 0;
}

// Keychain access of this process never raises a dialog: a call that would
// need one fails with errSecInteractionNotAllowed or errSecAuthFailed
// instead. Used by unattended callers (the KEK broker).
int MacKeyVaultDisableUI(void) {
    return (int)SecKeychainSetUserInteractionAllowed(false);
}

// Attestation probe: tries both private-material export paths on the item and
// reports their statuses verbatim. 0 from either would mean the private key
// left the keychain; the tests require the documented refusals instead.
int MacKeyVaultProbeExport(const char *label, int *repStatus, int *exportStatus, size_t *leaked) {
    SecKeyRef key = NULL;
    OSStatus status = MacKeyVaultCopyPrivateKey(label, &key);
    if (status != errSecSuccess) return (int)status;
    *leaked = 0;

    CFErrorRef error = NULL;
    CFDataRef rep = SecKeyCopyExternalRepresentation(key, &error);
    if (rep != NULL) {
        *repStatus = 0;
        *leaked += (size_t)CFDataGetLength(rep);
        CFRelease(rep);
    } else {
        *repStatus = MacKeyVaultErrorCode(error);
        if (error != NULL) CFRelease(error);
    }

    CFDataRef exported = NULL;
    SecItemImportExportKeyParameters params;
    memset(&params, 0, sizeof(params));
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.passphrase = CFSTR("mac-keyvault-probe");
    OSStatus exportResult = SecItemExport(key, kSecFormatWrappedPKCS8, 0, &params, &exported);
    *exportStatus = (int)exportResult;
    if (exported != NULL) {
        *leaked += (size_t)CFDataGetLength(exported);
        CFRelease(exported);
    }
    CFRelease(key);
    return 0;
}

// Attestation probe: serialises the installed ACL of the private half as
// "auth1,auth2|app1;app2" per entry (RS separated). "*" in the application
// column means any application, an empty column means no application.
int MacKeyVaultCopyACL(const char *label, char **out, size_t *outLen) {
    SecKeyRef key = NULL;
    OSStatus status = MacKeyVaultCopyPrivateKey(label, &key);
    if (status != errSecSuccess) return (int)status;
    SecAccessRef access = NULL;
    status = SecKeychainItemCopyAccess((SecKeychainItemRef)key, &access);
    CFRelease(key);
    if (status != errSecSuccess) return (int)status;
    CFArrayRef acls = NULL;
    status = SecAccessCopyACLList(access, &acls);
    CFRelease(access);
    if (status != errSecSuccess) return (int)status;

    CFMutableDataRef buffer = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CFIndex count = CFArrayGetCount(acls);
    for (CFIndex i = 0; i < count; i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        CFIndex authCount = auths ? CFArrayGetCount(auths) : 0;
        for (CFIndex a = 0; a < authCount; a++) {
            if (a > 0) MacKeyVaultAppendField(buffer, NULL, 0, ',');
            CFStringRef auth = CFArrayGetValueAtIndex(auths, a);
            if (CFGetTypeID(auth) == CFStringGetTypeID()) {
                CFDataRef data = CFStringCreateExternalRepresentation(kCFAllocatorDefault, auth, kCFStringEncodingUTF8, 0);
                if (data != NULL) {
                    CFDataAppendBytes(buffer, CFDataGetBytePtr(data), CFDataGetLength(data));
                    CFRelease(data);
                }
            }
        }
        if (auths != NULL) CFRelease(auths);
        MacKeyVaultAppendField(buffer, NULL, 0, '|');

        CFArrayRef apps = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector selector = 0;
        status = SecACLCopyContents(acl, &apps, &description, &selector);
        if (status != errSecSuccess) {
            CFRelease(acls);
            CFRelease(buffer);
            return (int)status;
        }
        if (apps == NULL) {
            MacKeyVaultAppendField(buffer, "*", 1, MacKeyVaultRecordSeparator);
        } else {
            CFIndex appCount = CFArrayGetCount(apps);
            for (CFIndex a = 0; a < appCount; a++) {
                if (a > 0) MacKeyVaultAppendField(buffer, NULL, 0, ';');
                SecTrustedApplicationRef app = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, a);
                CFDataRef path = NULL;
                if (SecTrustedApplicationCopyData(app, &path) == errSecSuccess && path != NULL) {
                    // The data is a NUL-terminated path.
                    CFIndex length = CFDataGetLength(path);
                    const UInt8 *bytes = CFDataGetBytePtr(path);
                    while (length > 0 && bytes[length - 1] == 0) length--;
                    CFDataAppendBytes(buffer, bytes, length);
                    CFRelease(path);
                }
            }
            CFRelease(apps);
            MacKeyVaultAppendField(buffer, NULL, 0, MacKeyVaultRecordSeparator);
        }
        if (description != NULL) CFRelease(description);
    }
    CFRelease(acls);

    size_t length = (size_t)CFDataGetLength(buffer);
    char *copy = malloc(length + 1);
    if (copy == NULL) {
        CFRelease(buffer);
        return MacKeyVaultUnknownError;
    }
    memcpy(copy, CFDataGetBytePtr(buffer), length);
    copy[length] = '\0';
    CFRelease(buffer);
    *out = copy;
    *outLen = length;
    return 0;
}

// Nostr uses a separate generic-password namespace. Every operation disables
// Keychain UI: a foreign/rebuilt binary, locked store or refused ACL fails
// rather than asking the user to expand trust. No Data Protection fallback.
static OSStatus MacKeyVaultNostrQuery(CFMutableDictionaryRef *out, SecKeychainRef *keychain, int writing) {
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    // Select the OS account's login keychain, never HOME or a changed default.
    struct passwd user;
    struct passwd *found = NULL;
    char userBuffer[16384];
    if (getpwuid_r(getuid(), &user, userBuffer, sizeof(userBuffer), &found) != 0 || found == NULL || user.pw_dir == NULL) return errSecNotAvailable;
    char path[PATH_MAX];
    int pathLen = snprintf(path, sizeof(path), "%s/Library/Keychains/login.keychain-db", user.pw_dir);
    if (pathLen < 0 || (size_t)pathLen >= sizeof(path)) return errSecParam;
    status = SecKeychainOpen(path, keychain);
    if (status != errSecSuccess) return status;
    SecKeychainStatus state = 0;
    status = SecKeychainGetStatus(*keychain, &state);
    if (status != errSecSuccess || !(state & kSecUnlockStateStatus)) {
        CFRelease(*keychain); *keychain = NULL;
        return status != errSecSuccess ? status : errSecInteractionNotAllowed;
    }
    *out = MacKeyVaultDictionary();
    CFDictionarySetValue(*out, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(*out, kSecAttrService, MacKeyVaultNostrService);
    if (writing) {
        CFDictionarySetValue(*out, kSecUseKeychain, *keychain);
    } else {
        CFArrayRef search = CFArrayCreate(NULL, (const void **)keychain, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(*out, kSecMatchSearchList, search);
        CFRelease(search);
    }
    return errSecSuccess;
}

static OSStatus MacKeyVaultNostrSignedSelf(void) {
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSStrictValidate, NULL);
        CFRelease(code);
    }
    return status;
}

// Admit exactly one trusted application on every decrypt ACL. The OS separately
// checks the executable's signing requirement when retrieving the secret; a
// matching path alone is never used as code-identity authorization.
static OSStatus MacKeyVaultNostrCheckAccess(SecKeychainItemRef item) {
    SecAccessRef access = NULL;
    OSStatus status = SecKeychainItemCopyAccess(item, &access);
    if (status != errSecSuccess) return status;
    CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    CFRelease(access);
    if (acls == NULL || CFArrayGetCount(acls) == 0) {
        if (acls) CFRelease(acls);
        return errSecAuthFailed;
    }
    SecTrustedApplicationRef self = NULL;
    CFDataRef selfData = NULL;
    status = SecTrustedApplicationCreateFromPath(NULL, &self);
    if (status == errSecSuccess) status = SecTrustedApplicationCopyData(self, &selfData);
    if (self) CFRelease(self);
    for (CFIndex i = 0; status == errSecSuccess && i < CFArrayGetCount(acls); i++) {
        CFArrayRef apps = NULL;
        CFStringRef description = NULL;
        SecKeychainPromptSelector selector = 0;
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(acls, i), &apps, &description, &selector);
        if (status == errSecSuccess && (apps == NULL || CFArrayGetCount(apps) != 1)) status = errSecAuthFailed;
        CFDataRef appData = NULL;
        if (status == errSecSuccess) {
            status = SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, 0), &appData);
            if (status == errSecSuccess && !CFEqual(appData, selfData)) status = errSecAuthFailed;
        }
        if (appData) CFRelease(appData);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
    }
    if (selfData) CFRelease(selfData);
    CFRelease(acls);
    return status;
}

int MacKeyVaultNostrCreate(const char *account, const char *metadata, const unsigned char *secret) {
    OSStatus status = MacKeyVaultNostrSignedSelf();
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = NULL;
    SecKeychainRef keychain = NULL;
    status = MacKeyVaultNostrQuery(&query, &keychain, 1);
    if (status != errSecSuccess) return (int)status;
    SecAccessRef access = NULL;
    status = MacKeyVaultCreateAccess(&access);
    if (status == errSecSuccess) {
        CFStringRef accountString = MacKeyVaultString(account);
        CFStringRef metadataString = MacKeyVaultString(metadata);
        // No-copy input: Go owns and clears this buffer after the synchronous call.
        CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, secret, 32, kCFAllocatorNull);
        CFDictionarySetValue(query, kSecAttrAccount, accountString);
        CFDictionarySetValue(query, kSecAttrLabel, accountString);
        CFDictionarySetValue(query, kSecAttrComment, metadataString);
        CFDictionarySetValue(query, kSecAttrAccess, access);
        CFDictionarySetValue(query, kSecValueData, data);
        // SecItemAdd is atomic and never updates an existing account.
        status = SecItemAdd(query, NULL);
        CFRelease(accountString); CFRelease(metadataString); CFRelease(data);
        CFRelease(access);
    }
    CFRelease(query); CFRelease(keychain);
    return (int)status;
}

int MacKeyVaultRecoveryCreate(const char *account, const char *metadata, const unsigned char *secret, size_t length, int *mutationAttempted) {
    if (mutationAttempted == NULL) return errSecParam;
    *mutationAttempted = 0;
    if (length == 0 || length > 65536 || strlen(metadata) > 32768) return errSecParam;
    OSStatus status = MacKeyVaultRecoveryCode(0, NULL, 0);
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = NULL;
    SecKeychainRef keychain = NULL;
    status = MacKeyVaultNostrQuery(&query, &keychain, 1);
    if (status != errSecSuccess) return (int)status;
    SecAccessRef access = NULL;
    status = MacKeyVaultCreateAccess(&access);
    if (status == errSecSuccess) {
        CFStringRef accountString = MacKeyVaultString(account);
        CFStringRef metadataString = MacKeyVaultString(metadata);
        // No-copy input: Go owns and clears this buffer after the synchronous call.
        CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, secret, (CFIndex)length, kCFAllocatorNull);
        CFDictionarySetValue(query, kSecAttrAccount, accountString);
        CFDictionarySetValue(query, kSecAttrLabel, accountString);
        CFDictionarySetValue(query, kSecAttrComment, metadataString);
        CFDictionarySetValue(query, kSecAttrAccess, access);
        CFDictionarySetValue(query, kSecValueData, data);
        // SecItemAdd is atomic and never updates an existing account.
        // All earlier failures are definite no-effect, including code admission.
        *mutationAttempted = 1;
        status = SecItemAdd(query, NULL);
        CFRelease(accountString); CFRelease(metadataString); CFRelease(data);
        CFRelease(access);
    }
    CFRelease(query); CFRelease(keychain);
    return (int)status;
}


int MacKeyVaultNostrList(char **out, size_t *outLen) {
    CFMutableDictionaryRef query = NULL;
    SecKeychainRef keychain = NULL;
    OSStatus status = MacKeyVaultNostrQuery(&query, &keychain, 0);
    if (status != errSecSuccess) return (int)status;
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFTypeRef found = NULL;
    status = SecItemCopyMatching(query, &found);
    CFRelease(query); CFRelease(keychain);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess) return (int)status;
    if (CFGetTypeID(found) != CFArrayGetTypeID()) { CFRelease(found); return errSecDecode; }
    CFMutableDataRef buffer = CFDataCreateMutable(NULL, 0);
    for (CFIndex i = 0; i < CFArrayGetCount((CFArrayRef)found); i++) {
        CFTypeRef row = CFArrayGetValueAtIndex((CFArrayRef)found, i);
        if (CFGetTypeID(row) != CFDictionaryGetTypeID()) { status = errSecDecode; break; }
        CFStringRef fields[] = { CFDictionaryGetValue(row, kSecAttrAccount), CFDictionaryGetValue(row, kSecAttrComment) };
        for (int f = 0; f < 2; f++) {
            if (fields[f] == NULL || CFGetTypeID(fields[f]) != CFStringGetTypeID() || CFStringGetLength(fields[f]) > 32768) { status = errSecDecode; break; }
            CFDataRef text = CFStringCreateExternalRepresentation(NULL, fields[f], kCFStringEncodingUTF8, 0);
            if (text == NULL) { status = errSecDecode; break; }
            CFDataAppendBytes(buffer, CFDataGetBytePtr(text), CFDataGetLength(text));
            CFRelease(text);
            MacKeyVaultAppendField(buffer, NULL, 0, f == 0 ? MacKeyVaultFieldSeparator : MacKeyVaultRecordSeparator);
        }
        if (status != errSecSuccess) break;
        if (CFDataGetLength(buffer) > 4*1024*1024) { status = errSecDecode; break; }
    }
    CFRelease(found);
    if (status == errSecSuccess) {
        size_t length = (size_t)CFDataGetLength(buffer);
        char *copy = malloc(length + 1);
        if (copy == NULL) status = errSecAllocate;
        else { memcpy(copy, CFDataGetBytePtr(buffer), length); copy[length] = 0; *out = copy; *outLen = length; }
    }
    CFRelease(buffer);
    return (int)status;
}

int MacKeyVaultNostrRead(const char *account, const char *metadata, unsigned char *secret) {
    OSStatus status = MacKeyVaultNostrSignedSelf();
    if (status != errSecSuccess) return (int)status;
    CFMutableDictionaryRef query = NULL;
    SecKeychainRef keychain = NULL;
    status = MacKeyVaultNostrQuery(&query, &keychain, 0);
    if (status != errSecSuccess) return (int)status;
    CFStringRef name = MacKeyVaultString(account);
    CFDictionarySetValue(query, kSecAttrAccount, name);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFTypeRef item = NULL;
    status = SecItemCopyMatching(query, &item);
    CFRelease(name); CFRelease(query); CFRelease(keychain);
    if (status != errSecSuccess) return (int)status;
    status = MacKeyVaultNostrCheckAccess((SecKeychainItemRef)item);
    UInt32 tag = kSecCommentItemAttr;
    UInt32 format = CSSM_DB_ATTRIBUTE_FORMAT_BLOB;
    SecKeychainAttributeInfo info = {1, &tag, &format};
    SecKeychainAttributeList *attributes = NULL;
    UInt32 length = 0;
    void *data = NULL;
    if (status == errSecSuccess) status = SecKeychainItemCopyAttributesAndData((SecKeychainItemRef)item, &info, NULL, &attributes, &length, &data);
    if (status == errSecSuccess) {
        size_t metadataLen = strlen(metadata);
        if (length != 32 || attributes == NULL || attributes->count != 1 ||
            attributes->attr[0].tag != kSecCommentItemAttr || attributes->attr[0].length != metadataLen ||
            memcmp(attributes->attr[0].data, metadata, metadataLen) != 0) status = errSecDecode;
        else memcpy(secret, data, 32);
    }
    // Wipe the Security.framework-owned plaintext before releasing it.
    if (data) memset_s(data, length, 0, length);
    if (attributes || data) SecKeychainItemFreeAttributesAndData(attributes, data);
    CFRelease(item);
    return (int)status;
}

// Recovery values are ciphertext only. As for legacy Nostr scalars, check the
// sole-app decrypt ACL before asking Security.framework for the value.
int MacKeyVaultRecoveryRead(const char *account, const char *metadata, unsigned char **out, size_t *outLength) {
    *out = NULL; *outLength = 0;
    OSStatus status = MacKeyVaultRecoveryCode(0, NULL, 0);
    if (status != errSecSuccess) return status;
    CFMutableDictionaryRef query = NULL; SecKeychainRef keychain = NULL;
    status = MacKeyVaultNostrQuery(&query, &keychain, 0);
    if (status != errSecSuccess) return status;
    CFStringRef name = MacKeyVaultString(account);
    CFDictionarySetValue(query, kSecAttrAccount, name);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFTypeRef item = NULL;
    status = SecItemCopyMatching(query, &item);
    CFRelease(name); CFRelease(query); CFRelease(keychain);
    if (status != errSecSuccess) return status;
    status = MacKeyVaultNostrCheckAccess((SecKeychainItemRef)item);
    UInt32 tag = kSecCommentItemAttr, format = CSSM_DB_ATTRIBUTE_FORMAT_BLOB;
    SecKeychainAttributeInfo info = {1, &tag, &format};
    SecKeychainAttributeList *attributes = NULL; UInt32 length = 0; void *data = NULL;
    if (status == errSecSuccess) status = SecKeychainItemCopyAttributesAndData((SecKeychainItemRef)item, &info, NULL, &attributes, &length, &data);
    if (status == errSecSuccess) {
        size_t metadataLen = strlen(metadata);
        if (length == 0 || length > 65536 || attributes == NULL || attributes->count != 1 ||
            attributes->attr[0].tag != kSecCommentItemAttr || attributes->attr[0].length != metadataLen ||
            memcmp(attributes->attr[0].data, metadata, metadataLen) != 0) status = errSecDecode;
        else {
            *out = malloc(length);
            if (*out == NULL) status = errSecAllocate;
            else { memcpy(*out, data, length); *outLength = length; }
        }
    }
    if (data) memset_s(data, length, 0, length);
    if (attributes || data) SecKeychainItemFreeAttributesAndData(attributes, data);
    CFRelease(item); return status;
}

// Exact public metadata pins removal. OS delete authorization is separate from
// decrypt authorization; removal never retrieves the old private value.
int MacKeyVaultNostrDelete(const char *account, const char *metadata, int *mutationAttempted) {
    if (mutationAttempted == NULL) return errSecParam;
    *mutationAttempted = 0;
    OSStatus status = MacKeyVaultNostrSignedSelf();
    if (status != errSecSuccess) return status;
    CFMutableDictionaryRef query = NULL; SecKeychainRef keychain = NULL;
    status = MacKeyVaultNostrQuery(&query, &keychain, 0);
    if (status != errSecSuccess) return status;
    CFStringRef name = MacKeyVaultString(account), comment = MacKeyVaultString(metadata);
    CFDictionarySetValue(query, kSecAttrAccount, name);
    CFDictionarySetValue(query, kSecAttrComment, comment);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFTypeRef item = NULL;
    status = SecItemCopyMatching(query, &item);
    CFRelease(name); CFRelease(comment); CFRelease(query); CFRelease(keychain);
    if (status != errSecSuccess) return status;
    *mutationAttempted = 1;
    status = SecKeychainItemDelete((SecKeychainItemRef)item);
    CFRelease(item); return status;
}

// Recovery's existing hardening seam recognizes only these two representations.
// This compatibility predicate alone is never the root-item certificate policy.
int MacKeyVaultRecoveryCodeFlags(unsigned int flags) {
    return flags == 0x10002 || flags == 0x10000;
}

// Verify the actual running process, not merely a path that could change after
// launch. Strict signature validity, runtime and no entitlement exceptions form
// the positive admission boundary for the recovery/helper custody seam.
int MacKeyVaultRecoveryCode(int pid, const unsigned char *expectedHash, size_t hashLength) {
    SecCodeRef code = NULL;
    OSStatus status;
    if (pid == 0) status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    else {
        CFMutableDictionaryRef attrs = MacKeyVaultDictionary();
        CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
        CFDictionarySetValue(attrs, kSecGuestAttributePid, number); CFRelease(number);
        status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
        CFRelease(attrs);
    }
    if (status != errSecSuccess) return status;
    status = SecCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    CFDictionaryRef info = NULL;
    if (status == errSecSuccess) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation, &info);
    if (status == errSecSuccess) {
        CFTypeRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        CFTypeRef dynamic = CFDictionaryGetValue(info, kSecCodeInfoStatus);
        CFTypeRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
        CFTypeRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        uint32_t f = 0, d = 0;
        if (flags == NULL || CFGetTypeID(flags) != CFNumberGetTypeID() || !CFNumberGetValue(flags, kCFNumberSInt32Type, &f) ||
            dynamic == NULL || CFGetTypeID(dynamic) != CFNumberGetTypeID() || !CFNumberGetValue(dynamic, kCFNumberSInt32Type, &d) ||
            !MacKeyVaultRecoveryCodeFlags(f) || !(d & 0x10000) || !(d & 1) || (d & 0x10000000) ||
            (entitlements != NULL && (CFGetTypeID(entitlements) != CFDictionaryGetTypeID() || CFDictionaryGetCount(entitlements) != 0))) status = errSecAuthFailed;
        if (status == errSecSuccess && hashLength != 0 && (hash == NULL || CFGetTypeID(hash) != CFDataGetTypeID() ||
            (size_t)CFDataGetLength(hash) != hashLength || memcmp(CFDataGetBytePtr(hash), expectedHash, hashLength) != 0)) status = errSecAuthFailed;
    }
    if (info) CFRelease(info); CFRelease(code); return status;
}

// Finite paired-item code adoption. This private bridge does not provide an
// owner-review route. The typed owner sitting must review the prepared public
// write set and hold exclusion through Close. No Keychain UI is enabled here.
// SecAccess/ACL edits below are local until the one SecKeychainItemSetAccess.
#include <sys/stat.h>
#include <stdint.h>

struct MacKeyVaultRecoveryAdoption {
    SecKeychainRef keychain;
    SecKeychainItemRef item;
    SecAccessRef replacement;
    CFDataRef persistent, metadata, sealed, oldHash, newHash;
    CFDataRef oldApp, newApp, attributes, beforeACL, afterACL, frame;
    char *account, *oldPath, *newPath;
    int consumed;
};

static int AdoptionU32(CFMutableDataRef out, uint32_t value) {
    if (out == NULL || CFDataGetLength(out) > 1048576 - 4) return 0;
    UInt8 b[4] = {(UInt8)(value >> 24), (UInt8)(value >> 16), (UInt8)(value >> 8), (UInt8)value};
    CFDataAppendBytes(out, b, 4); return 1;
}

static int AdoptionField(CFMutableDataRef out, const void *bytes, size_t length) {
    if (out == NULL || length > 1048576 || (length != 0 && bytes == NULL) ||
        (size_t)CFDataGetLength(out) + 4 + length > 1048576 || !AdoptionU32(out, (uint32_t)length)) return 0;
    if (length) CFDataAppendBytes(out, bytes, (CFIndex)length);
    return 1;
}

static int AdoptionDataField(CFMutableDataRef out, CFDataRef data) {
    return data != NULL && AdoptionField(out, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data));
}

static int AdoptionStringField(CFMutableDataRef out, CFStringRef string) {
    if (string == NULL || CFGetTypeID(string) != CFStringGetTypeID()) return 0;
    CFDataRef utf8 = CFStringCreateExternalRepresentation(NULL, string, kCFStringEncodingUTF8, 0);
    int result = utf8 != NULL && AdoptionDataField(out, utf8);
    if (utf8) CFRelease(utf8);
    return result;
}

static CFMutableDataRef AdoptionFrame(const char *magic) {
    CFMutableDataRef data = CFDataCreateMutable(NULL, 0);
    if (data) CFDataAppendBytes(data, (const UInt8 *)magic, 5);
    return data;
}

// The new vault release has one fixed certificate DR. This is a static
// adoption-code check, not authority to change any existing item or its ACL.
static OSStatus AdoptionCertificateRequirement(SecStaticCodeRef code, CFDictionaryRef info) {
    CFTypeRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    CFTypeRef team = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
    CFTypeRef certificates = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (!identifier || CFGetTypeID(identifier) != CFStringGetTypeID() || !CFEqual(identifier, CFSTR("works.relux.keyvault")) ||
        !team || CFGetTypeID(team) != CFStringGetTypeID() || !CFEqual(team, CFSTR("262RZ595FP")) ||
        !certificates || CFGetTypeID(certificates) != CFArrayGetTypeID() || CFArrayGetCount(certificates) < 1) return errSecAuthFailed;
    CFTypeRef certificate = CFArrayGetValueAtIndex(certificates, 0);
    if (!certificate || CFGetTypeID(certificate) != SecCertificateGetTypeID()) return errSecAuthFailed;
    CFDataRef der = SecCertificateCopyData((SecCertificateRef)certificate);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    static const unsigned char expectedLeaf[CC_SHA256_DIGEST_LENGTH] = {
        0xb3,0x15,0xed,0x0a,0xc5,0x5f,0x58,0xd4,0xdb,0xcf,0xc3,0xce,0x4f,0x79,0x37,0xf6,
        0xed,0x05,0x82,0x77,0xfe,0xba,0x7e,0x4a,0xa3,0xe6,0x4b,0xd1,0x0b,0x17,0xd3,0xa1
    };
    if (!der || CFDataGetLength(der) <= 0 || CFDataGetLength(der) > 32768) {
        if (der) CFRelease(der); return errSecAuthFailed;
    }
    CC_SHA256(CFDataGetBytePtr(der), (CC_LONG)CFDataGetLength(der), digest);
    CFRelease(der);
    if (memcmp(digest, expectedLeaf, sizeof(digest)) != 0) return errSecAuthFailed;
    SecRequirementRef expected = NULL, actual = NULL;
    CFDataRef expectedData = NULL, actualData = NULL;
    OSStatus status = SecRequirementCreateWithString(CFSTR("identifier \"works.relux.keyvault\" and anchor apple generic and certificate leaf = H\"d71190abe54185f908169ee9ca538d4066942c0f\" and certificate 1[field.1.2.840.113635.100.6.2.1]"), kSecCSDefaultFlags, &expected);
    if (status == errSecSuccess && !expected) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, expected);
    if (status == errSecSuccess) status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &actual);
    if (status == errSecSuccess && !actual) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(expected, kSecCSDefaultFlags, &expectedData);
    if (status == errSecSuccess) status = SecRequirementCopyData(actual, kSecCSDefaultFlags, &actualData);
    if (status == errSecSuccess && (!expectedData || !actualData || !CFEqual(expectedData, actualData))) status = errSecAuthFailed;
    if (actualData) CFRelease(actualData); if (expectedData) CFRelease(expectedData);
    if (actual) CFRelease(actual); if (expected) CFRelease(expected);
    return status;
}

// A valid pinned binary can still embed an overbroad designated requirement.
// Preserve Apple's exact legacy CDHash binary requirement representations,
// optionally conjoined with its actual safe identifier; the new certificate
// form is separately fixed to the full vault DR and leaf above. No arbitrary
// team/path/OR/true expression is admitted by validating a file alone.
static OSStatus AdoptionExactRequirement(SecStaticCodeRef code, CFDictionaryRef info, CFDataRef hash) {
    CFTypeRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
    uint32_t f = 0;
    if (!flags || CFGetTypeID(flags) != CFNumberGetTypeID() || !CFNumberGetValue(flags, kCFNumberSInt32Type, &f)) return errSecAuthFailed;
    if (f == 0x10000) return AdoptionCertificateRequirement(code, info);
    if (f != 0x10002) return errSecAuthFailed;
    SecRequirementRef actual = NULL;
    CFDataRef actualData = NULL;
    OSStatus status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &actual);
    if (status == errSecSuccess) status = SecRequirementCopyData(actual, kSecCSDefaultFlags, &actualData);
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    CFIndex length = CFDataGetLength(hash);
    for (CFIndex i = 0; i < length; i++) {
        unsigned char b = CFDataGetBytePtr(hash)[i]; hex[2*i] = digits[b >> 4]; hex[2*i+1] = digits[b & 15];
    }
    hex[2*length] = 0;
    CFStringRef hashText = CFStringCreateWithCString(NULL, hex, kCFStringEncodingASCII);
    CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    char id[256]; int safeID = identifier && CFGetTypeID(identifier) == CFStringGetTypeID() &&
        CFStringGetCString(identifier, id, sizeof(id), kCFStringEncodingASCII) && id[0] != 0;
    if (safeID) for (size_t i = 0; id[i]; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) safeID = 0;
    }
    int admitted = 0;
    for (int variant = 0; status == errSecSuccess && !admitted && variant < (safeID ? 3 : 1); variant++) {
        CFStringRef text = variant == 0 ? CFStringCreateWithFormat(NULL, NULL, CFSTR("cdhash H\"%@\""), hashText) :
            (variant == 1 ? CFStringCreateWithFormat(NULL, NULL, CFSTR("identifier \"%@\" and cdhash H\"%@\""), identifier, hashText) :
                CFStringCreateWithFormat(NULL, NULL, CFSTR("cdhash H\"%@\" and identifier \"%@\""), hashText, identifier));
        SecRequirementRef candidate = NULL;
        CFDataRef data = NULL;
        OSStatus result = text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &candidate) : errSecAllocate;
        if (result == errSecSuccess) result = SecRequirementCopyData(candidate, kSecCSDefaultFlags, &data);
        if (result == errSecSuccess && CFEqual(data, actualData)) admitted = 1;
        if (data) CFRelease(data); if (candidate) CFRelease(candidate); if (text) CFRelease(text);
    }
    if (hashText) CFRelease(hashText); if (actualData) CFRelease(actualData); if (actual) CFRelease(actual);
    return status == errSecSuccess && admitted ? errSecSuccess : errSecAuthFailed;
}

// Actual static validation precedes deriving the trusted application. Recreate
// and recheck it at apply; immutable artifact custody is additionally required.
static OSStatus AdoptionCode(const char *path, CFDataRef hash, CFDataRef *appData, SecTrustedApplicationRef *app) {
    struct stat before, after;
    char physical[PATH_MAX];
    if (path == NULL || hash == NULL || (CFDataGetLength(hash) != 20 && CFDataGetLength(hash) != 32) ||
        realpath(path, physical) == NULL || strcmp(path, physical) != 0 || lstat(path, &before) != 0 ||
        !S_ISREG(before.st_mode) || (before.st_uid != getuid() && before.st_uid != 0) || (before.st_mode & 022) != 0) return errSecAuthFailed;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    SecStaticCodeRef code = NULL;
    OSStatus status = url ? SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) : errSecAllocate;
    if (url) CFRelease(url);
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, NULL);
    CFDictionaryRef info = NULL;
    if (status == errSecSuccess) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    if (status == errSecSuccess) {
        CFTypeRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
        CFTypeRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
        CFTypeRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
        CFTypeRef rawEntitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlements);
        uint32_t f = 0;
        if (!flags || CFGetTypeID(flags) != CFNumberGetTypeID() || !CFNumberGetValue(flags, kCFNumberSInt32Type, &f) || !MacKeyVaultRecoveryCodeFlags(f) ||
            !unique || CFGetTypeID(unique) != CFDataGetTypeID() || !CFEqual(unique, hash) ||
            (entitlements && (CFGetTypeID(entitlements) != CFDictionaryGetTypeID() || CFDictionaryGetCount(entitlements) != 0)) ||
            (rawEntitlements && !entitlements)) status = errSecAuthFailed;
    }
    if (status == errSecSuccess) status = AdoptionExactRequirement(code, info, hash);
    if (status == errSecSuccess) status = SecTrustedApplicationCreateFromPath(path, app);
    if (status == errSecSuccess) status = SecTrustedApplicationCopyData(*app, appData);
    if (status == errSecSuccess && (lstat(path, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
        before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec || before.st_mode != after.st_mode)) status = errSecAuthFailed;
    // Revalidate the held static object after the path-based trusted-app call.
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, NULL);
    if (info) CFRelease(info);
    if (code) CFRelease(code);
    if (status != errSecSuccess) {
        if (*appData) { CFRelease(*appData); *appData = NULL; }
        if (*app) { CFRelease(*app); *app = NULL; }
    }
    return status;
}

// Capture raw CSSM owner and entry state that the simple ACL projection omits:
// delegation, validity, entry tags/handles and every unrelated typed subject.
// Only the decrypt subject is projected through its complete simple contents;
// its sole application is the one permitted change. Complex simple-API failures
// refuse rather than reconstructing a subject or losing native state.
static int AdoptionList(CFMutableDataRef out, const CSSM_LIST *list, unsigned depth) {
    if (!list || depth > 16 || list->ListType > CSSM_LIST_TYPE_SEXPR || !AdoptionU32(out, list->ListType)) return 0;
    const CSSM_LIST_ELEMENT *p = list->Head, *last = NULL;
    unsigned count = 0;
    for (; p != NULL && count < 256; p = p->NextElement, count++) {
        if (!AdoptionU32(out, 1) || !AdoptionU32(out, p->WordID) || !AdoptionU32(out, p->ElementType)) return 0;
        switch (p->ElementType) {
        case CSSM_LIST_ELEMENT_DATUM:
            if (!AdoptionField(out, p->Element.Word.Data, p->Element.Word.Length)) return 0;
            break;
        case CSSM_LIST_ELEMENT_SUBLIST:
            if (!AdoptionList(out, &p->Element.Sublist, depth + 1)) return 0;
            break;
        case CSSM_LIST_ELEMENT_WORDID:
            break;
        default:
            return 0;
        }
        last = p;
    }
    return p == NULL && last == list->Tail && AdoptionU32(out, 0);
}

static OSStatus AdoptionRawAccess(SecAccessRef access, CFDataRef *out) {
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL;
    uint32 count = 0;
    OSStatus status = SecAccessGetOwnerAndACL(access, &owner, &count, &entries);
    CFMutableDataRef frame = AdoptionFrame("KVAR1");
    if (status == errSecSuccess && (!owner || !entries || count == 0 || count > 64 ||
        !AdoptionU32(frame, owner->Delegate) || !AdoptionList(frame, &owner->TypedSubject, 0) || !AdoptionU32(frame, count))) status = errSecDecode;
    for (uint32 i = 0; status == errSecSuccess && i < count; i++) {
        CSSM_ACL_ENTRY_PROTOTYPE *entry = &entries[i].EntryPublicInfo;
        uint64_t handle = (uint64_t)entries[i].EntryHandle;
        if (!AdoptionU32(frame, (uint32_t)(handle >> 32)) || !AdoptionU32(frame, (uint32_t)handle) ||
            !AdoptionU32(frame, entry->Delegate) || entry->Authorization.NumberOfAuthTags == 0 ||
            entry->Authorization.NumberOfAuthTags > 32 || !entry->Authorization.AuthTags ||
            !AdoptionU32(frame, entry->Authorization.NumberOfAuthTags)) { status = errSecDecode; break; }
        int decrypt = 0;
        for (uint32 j = 0; status == errSecSuccess && j < entry->Authorization.NumberOfAuthTags; j++) {
            CSSM_ACL_AUTHORIZATION_TAG tag = entry->Authorization.AuthTags[j];
            if (tag == CSSM_ACL_AUTHORIZATION_ANY || !AdoptionU32(frame, (uint32_t)tag)) status = errSecAuthFailed;
            if (tag == CSSM_ACL_AUTHORIZATION_DECRYPT) decrypt = 1;
        }
        size_t tagLength = strnlen(entry->EntryTag, sizeof(entry->EntryTag));
        if (status == errSecSuccess && ((decrypt && entry->Authorization.NumberOfAuthTags != 1) ||
            !AdoptionField(frame, entry->TimeRange.StartDate.Data, entry->TimeRange.StartDate.Length) ||
            !AdoptionField(frame, entry->TimeRange.EndDate.Data, entry->TimeRange.EndDate.Length) ||
            tagLength == sizeof(entry->EntryTag) || !AdoptionField(frame, entry->EntryTag, tagLength) ||
            !AdoptionU32(frame, decrypt) || (!decrypt && !AdoptionList(frame, &entry->TypedSubject, 0)))) status = errSecDecode;
    }
    // GetOwnerAndACL's pointers are only traversed while this SecAccess lives;
    // no CSSM pointer escapes or is retained in the public/native snapshot.
    if (status == errSecSuccess) *out = frame;
    else if (frame) CFRelease(frame);
    return status;
}

// Preserve each entry, including null versus empty application lists, complete
// authorizations, description and CSSM prompt version AND flags. Mixed decrypt
// entries cannot be changed without also changing other authorization policy.
// No splitting, wildcard-any admission, owner replacement or ACL recreation.
static OSStatus AdoptionAccess(SecAccessRef access, CFDataRef requiredApp, SecTrustedApplicationRef replaceWith, CFDataRef *out) {
    uid_t user = 0; gid_t group = 0; SecAccessOwnerType owner = 0;
    CFArrayRef list = NULL;
    OSStatus status = SecAccessCopyOwnerAndACL(access, &user, &group, &owner, &list);
    CFMutableDataRef frame = AdoptionFrame("KVAC1");
    CFIndex count = list ? CFArrayGetCount(list) : 0;
    if (status == errSecSuccess && (count == 0 || count > 64 || !AdoptionU32(frame, (uint32_t)user) ||
        !AdoptionU32(frame, (uint32_t)group) || !AdoptionU32(frame, (uint32_t)owner) || !AdoptionU32(frame, (uint32_t)count))) status = errSecDecode;
    CFDataRef raw = NULL;
    if (status == errSecSuccess) status = AdoptionRawAccess(access, &raw);
    int decrypts = 0;
    for (CFIndex i = 0; status == errSecSuccess && i < count; i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(list, i);
        CFArrayRef auth = NULL, apps = NULL;
        CFStringRef description = NULL;
        CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR prompt = {0, 0};
        CFMutableDataRef preserved = CFDataCreateMutable(NULL, 0), applications = CFDataCreateMutable(NULL, 0);
        if (CFGetTypeID(acl) != SecACLGetTypeID()) status = errSecDecode;
        if (status == errSecSuccess) auth = SecACLCopyAuthorizations(acl);
        CFIndex n = auth ? CFArrayGetCount(auth) : 0;
        int decrypt = 0;
        if (status == errSecSuccess && (n == 0 || n > 32 || !AdoptionU32(preserved, (uint32_t)n))) status = errSecDecode;
        for (CFIndex j = 0; status == errSecSuccess && j < n; j++) {
            CFStringRef tag = CFArrayGetValueAtIndex(auth, j);
            if (!AdoptionStringField(preserved, tag) || CFEqual(tag, kSecACLAuthorizationAny)) status = errSecAuthFailed;
            else if (CFEqual(tag, kSecACLAuthorizationDecrypt)) decrypt = 1;
        }
        if (status == errSecSuccess && decrypt && n != 1) status = errSecAuthFailed;
        if (status == errSecSuccess) status = SecACLCopySimpleContents(acl, &apps, &description, &prompt);
        if (status == errSecSuccess && (!AdoptionU32(preserved, description != NULL) ||
            !(description ? AdoptionStringField(preserved, description) : AdoptionField(preserved, NULL, 0)) ||
            !AdoptionU32(preserved, prompt.version) || !AdoptionU32(preserved, prompt.flags))) status = errSecAllocate;
        CFIndex appCount = apps ? CFArrayGetCount(apps) : 0;
        if (status == errSecSuccess && (appCount > 64 || (decrypt && (apps == NULL || appCount != 1)) ||
            !AdoptionU32(applications, apps != NULL) || !AdoptionU32(applications, (uint32_t)appCount))) status = errSecAuthFailed;
        for (CFIndex j = 0; status == errSecSuccess && j < appCount; j++) {
            SecTrustedApplicationRef application = (SecTrustedApplicationRef)CFArrayGetValueAtIndex(apps, j);
            CFDataRef data = NULL;
            if (CFGetTypeID(application) != SecTrustedApplicationGetTypeID()) status = errSecDecode;
            if (status == errSecSuccess) status = SecTrustedApplicationCopyData(application, &data);
            if (status == errSecSuccess && (data == NULL || CFDataGetLength(data) == 0 ||
                (decrypt && !CFEqual(data, requiredApp)) || !AdoptionDataField(applications, data))) status = errSecAuthFailed;
            if (data) CFRelease(data);
        }
        if (status == errSecSuccess && (!AdoptionU32(frame, decrypt) || !AdoptionDataField(frame, preserved) || !AdoptionDataField(frame, applications))) status = errSecAllocate;
        if (status == errSecSuccess && decrypt) {
            decrypts++;
            if (replaceWith) {
                CFArrayRef sole = CFArrayCreate(NULL, (const void **)&replaceWith, 1, &kCFTypeArrayCallBacks);
                status = sole ? SecACLSetSimpleContents(acl, sole, description, &prompt) : errSecAllocate;
                if (sole) CFRelease(sole);
            }
        }
        if (auth) CFRelease(auth);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (preserved) CFRelease(preserved);
        if (applications) CFRelease(applications);
    }
    if (status == errSecSuccess && (decrypts == 0 || !AdoptionDataField(frame, raw))) status = errSecAuthFailed;
    if (raw) CFRelease(raw);
    if (list) CFRelease(list);
    if (status == errSecSuccess) *out = frame;
    else if (frame) CFRelease(frame);
    return status;
}

static int AdoptionAttributeMatches(SecKeychainAttributeList *attributes, UInt32 tag, const void *bytes, size_t length) {
    int count = 0;
    for (UInt32 i = 0; i < attributes->count; i++) {
        SecKeychainAttribute *a = &attributes->attr[i];
        if (a->tag == tag) {
            if (a->length != length || (length && (!a->data || memcmp(a->data, bytes, length) != 0))) return 0;
            count++;
        }
    }
    return count == 1;
}

// All possible attributes for the generic-password class are captured, not a
// hand-picked metadata subset. Missing/ambiguous schemas refuse. Value is only
// compared in C, wiped and freed; no account unseal or value export is offered.
static OSStatus AdoptionItem(MacKeyVaultRecoveryAdoption *p, CFDataRef *out) {
    SecKeychainRef actual = NULL;
    CFDataRef persistent = NULL;
    SecKeychainAttributeInfo *info = NULL;
    SecKeychainAttributeList *attributes = NULL;
    UInt32 length = 0; void *data = NULL; SecItemClass itemClass = 0;
    OSStatus status = SecKeychainItemCopyKeychain(p->item, &actual);
    if (status == errSecSuccess && !CFEqual(actual, p->keychain)) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecKeychainItemCreatePersistentReference(p->item, &persistent);
    if (status == errSecSuccess && !CFEqual(persistent, p->persistent)) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecKeychainAttributeInfoForItemID(p->keychain, CSSM_DL_DB_RECORD_GENERIC_PASSWORD, &info);
    if (status == errSecSuccess && (!info || info->count == 0 || info->count > 128)) status = errSecDecode;
    if (status == errSecSuccess) status = SecKeychainItemCopyAttributesAndData(p->item, info, &itemClass, &attributes, &length, &data);
    if (status == errSecSuccess && (itemClass != kSecGenericPasswordItemClass || !attributes || attributes->count != info->count ||
        !AdoptionAttributeMatches(attributes, kSecServiceItemAttr, "works.relux.mac-keyvault.nostr.v1", strlen("works.relux.mac-keyvault.nostr.v1")) ||
        !AdoptionAttributeMatches(attributes, kSecAccountItemAttr, p->account, strlen(p->account)) ||
        !AdoptionAttributeMatches(attributes, kSecLabelItemAttr, p->account, strlen(p->account)) ||
        !AdoptionAttributeMatches(attributes, kSecCommentItemAttr, CFDataGetBytePtr(p->metadata), (size_t)CFDataGetLength(p->metadata)) ||
        length != (UInt32)CFDataGetLength(p->sealed) || !data || timingsafe_bcmp(data, CFDataGetBytePtr(p->sealed), length) != 0)) status = errSecDecode;
    CFMutableDataRef frame = AdoptionFrame("KVAT1");
    if (status == errSecSuccess && !AdoptionU32(frame, attributes->count)) status = errSecAllocate;
    // Canonical increasing tags, independent of the API's returned order.
    UInt32 last = 0;
    for (UInt32 n = 0; status == errSecSuccess && n < attributes->count; n++) {
        SecKeychainAttribute *next = NULL;
        for (UInt32 i = 0; i < attributes->count; i++) {
            SecKeychainAttribute *a = &attributes->attr[i];
            if ((n == 0 || a->tag > last) && (!next || a->tag < next->tag)) next = a;
        }
        UInt32 format = 0, formats = 0;
        if (next) for (UInt32 i = 0; i < info->count; i++) if (info->tag[i] == next->tag) { format = info->format[i]; formats++; }
        if (!next || formats != 1 || !AdoptionU32(frame, next->tag) || !AdoptionU32(frame, format) || !AdoptionField(frame, next->data, next->length)) status = errSecDecode;
        if (next) last = next->tag;
    }
    if (data) { if (memset_s(data, length, 0, length) != 0) abort(); }
    if (attributes || data) SecKeychainItemFreeAttributesAndData(attributes, data);
    if (info) SecKeychainFreeAttributeInfo(info);
    if (actual) CFRelease(actual);
    if (persistent) CFRelease(persistent);
    if (status == errSecSuccess) *out = frame;
    else if (frame) CFRelease(frame);
    return status;
}

void MacKeyVaultRecoveryAdoptionClose(MacKeyVaultRecoveryAdoption *p) {
    if (!p) return;
    // CFData has one owned mutable backing for these sealed/public inputs.
    CFDataRef *owned[] = {&p->metadata, &p->sealed};
    for (size_t i = 0; i < sizeof(owned)/sizeof(owned[0]); i++) if (*owned[i]) {
        CFIndex n = CFDataGetLength(*owned[i]);
        if (n && memset_s(CFDataGetMutableBytePtr((CFMutableDataRef)*owned[i]), (size_t)n, 0, (size_t)n) != 0) abort();
    }
    CFTypeRef values[] = {p->keychain, p->item, p->replacement, p->persistent, p->metadata, p->sealed, p->oldHash, p->newHash,
        p->oldApp, p->newApp, p->attributes, p->beforeACL, p->afterACL, p->frame};
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++) if (values[i]) CFRelease(values[i]);
    free(p->account); free(p->oldPath); free(p->newPath);
    if (memset_s(p, sizeof(*p), 0, sizeof(*p)) != 0) abort();
    free(p);
}

static CFDataRef AdoptionOwned(const unsigned char *bytes, size_t length) {
    CFMutableDataRef result = CFDataCreateMutable(NULL, (CFIndex)length);
    if (result) CFDataAppendBytes(result, bytes, (CFIndex)length);
    return result;
}

// Defense in depth for this fixed pair namespace. Full canonical metadata and
// both envelope validators run in the private Go constructor before this call;
// this C bridge is not an independent JSON or general Keychain admin interface.
static int AdoptionPair(const char *account, const unsigned char *metadata, size_t metadataLength, const unsigned char *sealed, size_t sealedLength) {
    if (!account || !metadata || !sealed) return 0;
    const char *slash = strchr(account, '/');
    size_t serviceLength = slash ? (size_t)(slash - account) : 0;
    if (serviceLength == 0 || serviceLength > 40 || strncmp(slash, "/recovery@", 10) != 0) return 0;
    for (size_t i = 0; i < serviceLength; i++) {
        char c = account[i]; if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    const char *number = slash + 10;
    if (*number < '1' || *number > '9') return 0;
    uint64_t generation = 0;
    for (const char *c = number; *c; c++) {
        if (*c < '0' || *c > '9') return 0;
        generation = generation * 10 + (unsigned)(*c - '0');
        if (generation > 2147483647) return 0;
    }
    const char *m1 = "{\"schema\":\"keyvault-recovery/1\",", *m2 = "{\"schema\":\"keyvault-recovery/2\",";
    const char *s1 = "{\"schema\":\"keyvault-recovery-ciphertext/1\",", *s2 = "{\"schema\":\"keyvault-recovery-ciphertext/2\",";
    return (metadataLength >= strlen(m1) && sealedLength >= strlen(s1) && memcmp(metadata, m1, strlen(m1)) == 0 && memcmp(sealed, s1, strlen(s1)) == 0) ||
        (metadataLength >= strlen(m2) && sealedLength >= strlen(s2) && memcmp(metadata, m2, strlen(m2)) == 0 && memcmp(sealed, s2, strlen(s2)) == 0);
}

int MacKeyVaultRecoveryAdoptionInspect(const char *account, const unsigned char *metadata, size_t metadataLength,
    const unsigned char *sealed, size_t sealedLength, const unsigned char *persistent, size_t persistentLength,
    const char *oldPath, const unsigned char *oldHash, size_t oldHashLength, const char *newPath, const unsigned char *newHash, size_t newHashLength,
    MacKeyVaultRecoveryAdoption **out, unsigned char **frameOut, size_t *frameLength) {
    if (!out || !frameOut || !frameLength) return 1;
    *out = NULL; *frameOut = NULL; *frameLength = 0;
    if (!account || !oldPath || !newPath || !metadata || !sealed || !persistent || !oldHash || !newHash ||
        strlen(account) == 0 || strlen(account) > 128 || strlen(oldPath) > 4095 || strlen(newPath) > 4095 ||
        !metadataLength || metadataLength > 32768 || !sealedLength || sealedLength > 65536 || !persistentLength || persistentLength > 4096 ||
        (oldHashLength != 20 && oldHashLength != 32) || (newHashLength != 20 && newHashLength != 32) ||
        strcmp(oldPath, newPath) == 0 || (oldHashLength == newHashLength && memcmp(oldHash, newHash, oldHashLength) == 0) ||
        !AdoptionPair(account, metadata, metadataLength, sealed, sealedLength)) return 1;
    MacKeyVaultRecoveryAdoption *p = calloc(1, sizeof(*p));
    if (!p) return 1;
    p->account = strdup(account); p->oldPath = strdup(oldPath); p->newPath = strdup(newPath);
    p->metadata = AdoptionOwned(metadata, metadataLength); p->sealed = AdoptionOwned(sealed, sealedLength);
    p->persistent = CFDataCreate(NULL, persistent, (CFIndex)persistentLength);
    p->oldHash = CFDataCreate(NULL, oldHash, (CFIndex)oldHashLength); p->newHash = CFDataCreate(NULL, newHash, (CFIndex)newHashLength);
    OSStatus status = p->account && p->oldPath && p->newPath && p->metadata && p->sealed && p->persistent && p->oldHash && p->newHash ? errSecSuccess : errSecAllocate;
    if (status == errSecSuccess) {
        // Both principals qualify as code; the actual caller must be one of
        // them. The OS independently decides data and change-ACL authority.
        status = MacKeyVaultRecoveryCode(0, oldHash, oldHashLength);
        if (status != errSecSuccess) status = MacKeyVaultRecoveryCode(0, newHash, newHashLength);
    }
    SecTrustedApplicationRef old = NULL, next = NULL;
    if (status == errSecSuccess) status = AdoptionCode(oldPath, p->oldHash, &p->oldApp, &old);
    if (status == errSecSuccess) status = AdoptionCode(newPath, p->newHash, &p->newApp, &next);
    if (status == errSecSuccess && CFEqual(p->oldApp, p->newApp)) status = errSecAuthFailed;
    CFMutableDictionaryRef query = NULL;
    if (status == errSecSuccess) status = MacKeyVaultNostrQuery(&query, &p->keychain, 0);
    if (status == errSecSuccess) {
        CFStringRef name = MacKeyVaultString(account);
        CFDictionarySetValue(query, kSecAttrAccount, name);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
        CFTypeRef matches = NULL;
        status = SecItemCopyMatching(query, &matches);
        if (status == errSecSuccess && (!matches || CFGetTypeID(matches) != CFArrayGetTypeID() || CFArrayGetCount(matches) != 1 ||
            CFGetTypeID(CFArrayGetValueAtIndex((CFArrayRef)matches, 0)) != SecKeychainItemGetTypeID())) status = errSecDecode;
        if (status == errSecSuccess) p->item = (SecKeychainItemRef)CFRetain(CFArrayGetValueAtIndex((CFArrayRef)matches, 0));
        if (matches) CFRelease(matches);
        CFRelease(name);
    }
    if (status == errSecSuccess) status = SecKeychainItemCopyAccess(p->item, &p->replacement);
    if (status == errSecSuccess) status = AdoptionAccess(p->replacement, p->oldApp, NULL, &p->beforeACL);
    if (status == errSecSuccess) status = AdoptionItem(p, &p->attributes);
    CFDataRef original = NULL, rawBefore = NULL, rawAfter = NULL;
    if (status == errSecSuccess) status = AdoptionRawAccess(p->replacement, &rawBefore);
    if (status == errSecSuccess) status = AdoptionAccess(p->replacement, p->oldApp, next, &original);
    if (status == errSecSuccess && !CFEqual(original, p->beforeACL)) status = errSecDecode;
    if (status == errSecSuccess) status = AdoptionAccess(p->replacement, p->newApp, NULL, &p->afterACL);
    if (status == errSecSuccess) status = AdoptionRawAccess(p->replacement, &rawAfter);
    if (status == errSecSuccess && !CFEqual(rawBefore, rawAfter)) status = errSecDecode;
    CFMutableDataRef frame = AdoptionFrame("KVAD1");
    if (status == errSecSuccess && (!AdoptionDataField(frame, p->oldApp) || !AdoptionDataField(frame, p->newApp) ||
        !AdoptionDataField(frame, p->attributes) || !AdoptionDataField(frame, p->beforeACL) || !AdoptionDataField(frame, p->afterACL))) status = errSecAllocate;
    if (status == errSecSuccess) {
        *frameLength = (size_t)CFDataGetLength(frame); *frameOut = malloc(*frameLength);
        if (!*frameOut) { *frameLength = 0; status = errSecAllocate; }
        else { memcpy(*frameOut, CFDataGetBytePtr(frame), *frameLength); p->frame = CFRetain(frame); *out = p; }
    }
    if (old) CFRelease(old); if (next) CFRelease(next);
    if (rawBefore) CFRelease(rawBefore); if (rawAfter) CFRelease(rawAfter);
    if (original) CFRelease(original); if (frame) CFRelease(frame); if (query) CFRelease(query);
    if (status != errSecSuccess) MacKeyVaultRecoveryAdoptionClose(p);
    return status == errSecSuccess ? 0 : 1;
}

int MacKeyVaultRecoveryAdoptionApply(MacKeyVaultRecoveryAdoption *p, const unsigned char *reviewedFrame, size_t reviewedLength, int *attempted) {
    if (!attempted) return 1;
    *attempted = 0;
    if (!p || p->consumed) return 1;
    p->consumed = 1; // Every admitted apply call is one-shot, even on refusal.
    if (!reviewedFrame || reviewedLength != (size_t)CFDataGetLength(p->frame) ||
        memcmp(reviewedFrame, CFDataGetBytePtr(p->frame), reviewedLength) != 0 || SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return 1;
    OSStatus status = MacKeyVaultRecoveryCode(0, CFDataGetBytePtr(p->oldHash), (size_t)CFDataGetLength(p->oldHash));
    if (status != errSecSuccess) status = MacKeyVaultRecoveryCode(0, CFDataGetBytePtr(p->newHash), (size_t)CFDataGetLength(p->newHash));
    SecTrustedApplicationRef old = NULL, next = NULL;
    CFDataRef oldData = NULL, newData = NULL, attributes = NULL, acl = NULL;
    SecAccessRef current = NULL;
    if (status == errSecSuccess) status = AdoptionCode(p->oldPath, p->oldHash, &oldData, &old);
    if (status == errSecSuccess) status = AdoptionCode(p->newPath, p->newHash, &newData, &next);
    if (status == errSecSuccess && (!CFEqual(oldData, p->oldApp) || !CFEqual(newData, p->newApp))) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecKeychainItemCopyAccess(p->item, &current);
    if (status == errSecSuccess) status = AdoptionAccess(current, p->oldApp, NULL, &acl);
    if (status == errSecSuccess && !CFEqual(acl, p->beforeACL)) status = errSecDecode;
    if (status == errSecSuccess) status = AdoptionItem(p, &attributes);
    if (status == errSecSuccess && !CFEqual(attributes, p->attributes)) status = errSecDecode;
    if (current) { CFRelease(current); current = NULL; }
    if (acl) { CFRelease(acl); acl = NULL; }
    if (attributes) { CFRelease(attributes); attributes = NULL; }
    if (status == errSecSuccess) {
        *attempted = 1;
        status = SecKeychainItemSetAccess(p->item, p->replacement); // Sole persistent mutation.
        if (status == errSecSuccess) status = SecKeychainItemCopyAccess(p->item, &current);
        if (status == errSecSuccess) status = AdoptionAccess(current, p->newApp, NULL, &acl);
        if (status == errSecSuccess && !CFEqual(acl, p->afterACL)) status = errSecDecode;
        if (status == errSecSuccess) status = AdoptionItem(p, &attributes);
        if (status == errSecSuccess && !CFEqual(attributes, p->attributes)) status = errSecDecode;
    }
    if (old) CFRelease(old); if (next) CFRelease(next);
    if (oldData) CFRelease(oldData); if (newData) CFRelease(newData);
    if (current) CFRelease(current); if (acl) CFRelease(acl); if (attributes) CFRelease(attributes);
    // Raw OSStatus never crosses this finite boundary. Any post-write failure
    // is UNKNOWN, including denied data readback; there is no retry/rollback.
    return status == errSecSuccess ? 0 : (*attempted ? 2 : 1);
}
