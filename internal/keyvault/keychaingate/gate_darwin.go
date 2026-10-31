//go:build darwin && cgo

package keychaingate

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <sandbox.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"
)

func init() {
	if !testing.Testing() || os.Getenv(SkipEnv) == "" {
		return
	}
	if err := confine(); err != nil {
		service := fmt.Sprintf("works.relux.mac-keyvault.sandbox-canary.nonexistent.%d.%d", os.Getpid(), time.Now().UnixNano())
		status := canaryFindNonexistent(service)
		if status == -50 {
			confined = true
			return
		}
		fmt.Fprintf(os.Stderr, "keychaingate: %v; read-only canary OSStatus %d; refusing to run unsandboxed\n", err, status)
		os.Exit(1)
	}
	applied = true
}

func confine() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve HOME: %w", err)
	}
	if !filepath.IsAbs(home) {
		return fmt.Errorf("HOME must be absolute")
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		return fmt.Errorf("resolve HOME symlinks: %w", err)
	}
	profile := C.CString(profileForHome(home))
	defer C.free(unsafe.Pointer(profile))
	var message *C.char
	if C.sandbox_init(profile, 0, &message) != 0 {
		detail := "no diagnostic"
		if message != nil {
			detail = C.GoString(message)
			C.sandbox_free_error(message)
		}
		return fmt.Errorf("sandbox_init: %s", detail)
	}
	return nil
}

func profileForHome(home string) string {
	// trustd handles certificate trust evaluation used by fake TLS tests. It is
	// deliberately available; Keychain writes use the denied services below.
	return `(version 1)
(allow default)
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.security.keychaind")
  (global-name "com.apple.secd")
  (global-name "com.apple.ctkd.token-client")
  (global-name "com.apple.ctkahp")
  (global-name "com.apple.security.agent")
  (global-name "com.apple.security.authhost"))
(deny file-write* (subpath ` + strconv.Quote(filepath.Join(home, "Library", "Keychains")) + `))`
}
