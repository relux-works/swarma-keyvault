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
            f != 0x10002 || !(d & 0x10000) || !(d & 1) || (d & 0x10000000) ||
            (entitlements != NULL && (CFGetTypeID(entitlements) != CFDictionaryGetTypeID() || CFDictionaryGetCount(entitlements) != 0))) status = errSecAuthFailed;
        if (status == errSecSuccess && hashLength != 0 && (hash == NULL || CFGetTypeID(hash) != CFDataGetTypeID() ||
            (size_t)CFDataGetLength(hash) != hashLength || memcmp(CFDataGetBytePtr(hash), expectedHash, hashLength) != 0)) status = errSecAuthFailed;
    }
    if (info) CFRelease(info); CFRelease(code); return status;
}
