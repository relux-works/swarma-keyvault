//go:build darwin && cgo

// Package recoveryfixture supplies an in-memory Apple API binding for public
// synthetic conformance tests. The vault does not import this package.
package recoveryfixture

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// No Keychain query, persistent attribute, token or authentication context.
// The only operation is the platform ECIES primitive on supplied test bytes.
static CFDataRef fixtureOpen(const unsigned char *representation, size_t keyLength,
                             const unsigned char *wire, size_t wireLength, int *status) {
    *status = 0;
    const void *keys[] = { kSecAttrKeyType, kSecAttrKeyClass };
    const void *values[] = { kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPrivate };
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef bytes = CFDataCreate(NULL, representation, (CFIndex)keyLength);
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateWithData(bytes, attrs, &error);
    CFRelease(bytes); CFRelease(attrs);
    if (key == NULL) {
        *status = error == NULL ? -1 : (int)CFErrorGetCode(error);
        if (error != NULL) CFRelease(error);
        return NULL;
    }
    CFDataRef ciphertext = CFDataCreate(NULL, wire, (CFIndex)wireLength);
    CFDataRef plaintext = SecKeyCreateDecryptedData(key,
        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        ciphertext, &error);
    CFRelease(ciphertext); CFRelease(key);
    if (plaintext == NULL) *status = error == NULL ? -1 : (int)CFErrorGetCode(error);
    if (error != NULL) CFRelease(error);
    return plaintext;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Open accepts only public test-fixture key representations and recovery-sized
// ciphertext. All cryptographic expectations/assertions remain in Go tests;
// this shim delegates directly to Apple's existing implementation.
func Open(representation, wire []byte) ([]byte, error) {
	if len(representation) != 97 || (len(wire) != 149 && len(wire) != 181) {
		return nil, fmt.Errorf("fixture input size")
	}
	var code C.int
	plain := C.fixtureOpen((*C.uchar)(unsafe.Pointer(&representation[0])), C.size_t(len(representation)), (*C.uchar)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)), &code)
	if plain == 0 {
		return nil, fmt.Errorf("Apple ECIES refusal: %d", int(code))
	}
	defer C.CFRelease(C.CFTypeRef(plain))
	length := C.CFDataGetLength(plain)
	if length != 68 && length != 100 {
		return nil, fmt.Errorf("fixture plaintext size")
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(plain)), C.int(length)), nil
}
