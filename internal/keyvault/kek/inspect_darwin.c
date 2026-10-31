// Code identity for the KEK broker: the running peer of a Unix socket, by
// its audit token, and a file on disk. Security.framework only; nothing here
// touches the Keychain.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "inspect_darwin.h"

// Reads facts only after the caller validated this code with network access
// disabled. Ad-hoc code has no certificate; no ambient signing identity is used.
static int KekDescribe(SecStaticCodeRef code, KekCode *out) {
    CFDictionaryRef info = NULL;
    OSStatus status = SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSRequirementInformation, &info);
    if (status != errSecSuccess) return (int)status;
    CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (unique != NULL && CFGetTypeID(unique) == CFDataGetTypeID() && CFDataGetLength(unique) == 20) {
        const UInt8 *bytes = CFDataGetBytePtr(unique);
        for (int i = 0; i < 20; i++) snprintf(out->cdhash + 2 * i, 3, "%02x", bytes[i]);
    }
    CFTypeRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    if (identifier != NULL && CFGetTypeID(identifier) == CFStringGetTypeID()) {
        // CFStringGetCString refuses truncation. Leave no partial identifier.
        if (!CFStringGetCString(identifier, out->identifier, sizeof(out->identifier), kCFStringEncodingASCII) ||
            strlen(out->identifier) != (size_t)CFStringGetLength(identifier))
            memset(out->identifier, 0, sizeof(out->identifier));
    }
    CFTypeRef certificates = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (certificates != NULL && CFGetTypeID(certificates) == CFArrayGetTypeID() && CFArrayGetCount(certificates) > 0) {
        CFTypeRef leaf = CFArrayGetValueAtIndex(certificates, 0);
        if (leaf != NULL && CFGetTypeID(leaf) == SecCertificateGetTypeID()) {
            CFDataRef der = SecCertificateCopyData((SecCertificateRef)leaf);
            if (der != NULL) {
                CFIndex length = CFDataGetLength(der);
                if (length > 0 && length <= UINT32_MAX) {
                    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
                    // Apple's requirement language pins SHA-1 of certificate
                    // DER. This is identification, not a SHA-1 data signature.
                    CC_SHA1(CFDataGetBytePtr(der), (CC_LONG)length, digest);
                    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
                        snprintf(out->certificateSHA1 + 2 * i, 3, "%02x", digest[i]);
                }
                CFRelease(der);
            }
        }
    }
    CFNumberRef flags = CFDictionaryGetValue(info, kSecCodeInfoFlags);
    if (flags != NULL && CFGetTypeID(flags) == CFNumberGetTypeID()) {
        uint32_t value = 0;
        CFNumberGetValue(flags, kCFNumberSInt32Type, &value);
        out->flags = value;
    }
    CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    if (entitlements != NULL && CFGetTypeID(entitlements) == CFDictionaryGetTypeID()) {
        CFTypeRef allow = CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.get-task-allow"));
        out->getTaskAllow = allow != NULL && allow != kCFBooleanFalse;
    }
    CFRelease(info);
    return 0;
}

int KekInspectPeer(int fd, KekCode *out) {
    memset(out, 0, sizeof(*out));
    audit_token_t token;
    socklen_t len = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0 || len != sizeof(token)) return -1;
    CFDataRef tokenData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&token, sizeof(token));
    const void *keys[] = {kSecGuestAttributeAudit};
    const void *values[] = {tokenData};
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(tokenData);
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    if (status != errSecSuccess) return (int)status;
    out->status = (int)SecCodeCheckValidity(code, kSecCSNoNetworkAccess, NULL);
    out->valid = out->status == errSecSuccess;
    int result = out->valid ? KekDescribe((SecStaticCodeRef)code, out) : out->status;
    CFRelease(code);
    return result;
}

int KekInspectFile(const char *path, KekCode *out) {
    memset(out, 0, sizeof(*out));
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (url == NULL) return -1;
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess) return (int)status;
    out->status = (int)SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, NULL);
    out->valid = out->status == errSecSuccess;
    int result = out->valid ? KekDescribe(code, out) : out->status;
    CFRelease(code);
    return result;
}
