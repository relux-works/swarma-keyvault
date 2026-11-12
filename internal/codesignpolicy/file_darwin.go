//go:build darwin && cgo

package codesignpolicy

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// This inspects a static artifact, never its Keychain or running process.
static int certificateFile(const char *path, const char *expression,
                           unsigned char *out, size_t capacity, size_t *length) {
    *length = 0;
    SecStaticCodeRef code = NULL;
    SecRequirementRef expected = NULL, actual = NULL;
    CFDataRef expectedData = NULL, actualData = NULL, leaf = NULL;
    CFDictionaryRef info = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CFStringRef text = CFStringCreateWithCString(NULL, expression, kCFStringEncodingUTF8);
    OSStatus status = url && text ? SecRequirementCreateWithString(text, kSecCSDefaultFlags, &expected) : errSecAllocate;
    if (status == errSecSuccess && !expected) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess && !code) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSNoNetworkAccess, expected);
    if (status == errSecSuccess) status = SecCodeCopyDesignatedRequirement(code, kSecCSDefaultFlags, &actual);
    if (status == errSecSuccess && !actual) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecRequirementCopyData(expected, kSecCSDefaultFlags, &expectedData);
    if (status == errSecSuccess) status = SecRequirementCopyData(actual, kSecCSDefaultFlags, &actualData);
    if (status == errSecSuccess && (!expectedData || !actualData || !CFEqual(expectedData, actualData))) status = errSecAuthFailed;
    if (status == errSecSuccess) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    if (status == errSecSuccess) {
        CFTypeRef certificates = info ? CFDictionaryGetValue(info, kSecCodeInfoCertificates) : NULL;
        if (!certificates || CFGetTypeID(certificates) != CFArrayGetTypeID() || CFArrayGetCount(certificates) < 1) status = errSecAuthFailed;
        else {
            CFTypeRef first = CFArrayGetValueAtIndex(certificates, 0);
            if (!first || CFGetTypeID(first) != SecCertificateGetTypeID()) status = errSecAuthFailed;
            else leaf = SecCertificateCopyData((SecCertificateRef)first);
            if (!leaf || CFDataGetLength(leaf) <= 0 || (size_t)CFDataGetLength(leaf) > capacity) status = errSecAuthFailed;
            if (status == errSecSuccess) {
                *length = (size_t)CFDataGetLength(leaf);
                memcpy(out, CFDataGetBytePtr(leaf), *length);
            }
        }
    }
    if (leaf) CFRelease(leaf);
    if (info) CFRelease(info);
    if (actualData) CFRelease(actualData);
    if (expectedData) CFRelease(expectedData);
    if (actual) CFRelease(actual);
    if (expected) CFRelease(expected);
    if (code) CFRelease(code);
    if (text) CFRelease(text);
    if (url) CFRelease(url);
    return status == errSecSuccess ? 0 : 1;
}
*/
import "C"

import (
	"path/filepath"
	"strings"
	"unsafe"
)

// CertificateFile verifies the fixed role requirement against the actual static
// signature, compares binary DRs, then checks both complete leaf DER hashes.
// Native certificate/chain behavior requires attended qualification; fixture
// parser tests do not establish it. No Keychain lookup or artifact mutation.
func CertificateFile(path string, role Role) error {
	dr, err := Requirement(role)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return ErrPolicy
	}
	name, expression := C.CString(path), C.CString(strings.TrimPrefix(dr, "designated => "))
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(expression))
	raw := make([]byte, 32768)
	var n C.size_t
	if C.certificateFile(name, expression, (*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)), &n) != 0 || n == 0 || n > C.size_t(len(raw)) {
		return ErrPolicy
	}
	return Leaf(raw[:int(n)])
}
