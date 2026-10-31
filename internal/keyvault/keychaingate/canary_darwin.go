//go:build darwin && cgo

package keychaingate

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// This probe only queries; it never creates or changes an item.
static int canary_find_nonexistent(const char *service) {
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnAttributes, kSecMatchLimit };
    const void *values[] = { kSecClassGenericPassword, name, CFSTR("nonexistent-canary"), kCFBooleanTrue, kSecMatchLimitOne };
    CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5,
                                               &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef match = NULL;
    OSStatus status = SecItemCopyMatching(query, &match);
    if (match != NULL) CFRelease(match);
    CFRelease(query);
    CFRelease(name);
    return (int)status;
}
*/
import "C"

import "unsafe"

func canaryFindNonexistent(service string) int {
	name := C.CString(service)
	defer C.free(unsafe.Pointer(name))
	return int(C.canary_find_nonexistent(name))
}
