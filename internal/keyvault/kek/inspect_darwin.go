//go:build darwin && cgo

package kek

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <stdlib.h>
#include "inspect_darwin.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

// Signature flags of interest (Security/CSCommon.h).
const (
	flagLibraryValidation = 0x2000
	flagRuntime           = 0x10000
)

// CodeInspector identifies code through Security.framework.
type CodeInspector struct{}

func identity(c C.KekCode) CodeIdentity {
	return CodeIdentity{
		Valid:             c.valid != 0,
		CDHash:            C.GoString(&c.cdhash[0]),
		Identifier:        C.GoString(&c.identifier[0]),
		CertificateSHA1:   C.GoString(&c.certificateSHA1[0]),
		Runtime:           c.flags&flagRuntime != 0,
		LibraryValidation: c.flags&flagLibraryValidation != 0,
		GetTaskAllow:      c.getTaskAllow != 0,
	}
}

// Peer identifies the process at the other end of conn by its audit token,
// which the kernel records at connect time; a later fd hand-off does not
// change it.
func (CodeInspector) Peer(conn *net.UnixConn) (CodeIdentity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return CodeIdentity{}, err
	}
	var c C.KekCode
	var status C.int
	if err := raw.Control(func(fd uintptr) { status = C.KekInspectPeer(C.int(fd), &c) }); err != nil {
		return CodeIdentity{}, err
	}
	if status != 0 {
		return CodeIdentity{}, fmt.Errorf("peer code identity: OSStatus %d", int(status))
	}
	return identity(c), nil
}

// File identifies the code at path. The path must be a regular file, not a
// symlink: a rebind binds what is installed, not what a link points at.
func (CodeInspector) File(path string) (CodeIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return CodeIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return CodeIdentity{}, fmt.Errorf("%s is not a regular file", path)
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var c C.KekCode
	if status := C.KekInspectFile(cpath, &c); status != 0 {
		return CodeIdentity{}, fmt.Errorf("code identity of %s: OSStatus %d", path, int(status))
	}
	return identity(c), nil
}
