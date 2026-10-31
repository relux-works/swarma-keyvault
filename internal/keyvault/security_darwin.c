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

#include "security_darwin.h"

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
