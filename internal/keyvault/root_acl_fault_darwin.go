//go:build darwin && cgo && kvqfault

package keyvault

/*
#cgo CFLAGS: -DKVQ_FAULT_INJECTION
int KVQFaultRunIntended(int armStage, int armStatus, int maskRequirement, int *stage, int *status, int *completed);
int KVQFaultRunProject(int armStage, int armStatus, int armAfter, int maskNatural, int *stage, int *status, int *completed);
int KVQFaultRunBefore(int *stage, int *status, int *completed);
int KVQFaultProbeAuthorizations(int *out, char *failName, int failNameSize);
int KVQFaultProbeOwnerACL(int *out);
int KVQFaultRunProjectNonACL(int *stage, int *status, int *completed);
int KVQFaultProjectTwice(int fresh, unsigned char *a, unsigned char *b, int capacity, int *la, int *lb, int *stage, int *status);
int KVQFaultRunLogin(int armStage, int armStatus, int *stage, int *status, int *completed);
int KVQFaultRunSelf(int armStage, int armStatus, int *stage, int *status);
void KVQFaultNoteTwice(int firstStage, int firstStatus, int secondStage, int secondStatus, int *stage, int *status);
*/
import "C"

import "unsafe"

// This file exists only in a build with the kvqfault tag. It is the test-only way
// to arm one native failure stage; a normal build compiles none of it and the
// native unit then contains no injection state or entry point.

// faultRun is what one armed native run reported.
type faultRun struct {
	Result    int
	Stage     int
	OSStatus  int
	Completed bool
}

// runIntendedFault runs symbol resolution and the intended access object with one
// stage armed (0 is a natural run). With mask the natural verdict of the
// release-requirement check is ignored so the stages after it stay reachable.
func runIntendedFault(arm, status int, mask bool) faultRun {
	var stage, osStatus, completed C.int
	flag := C.int(0)
	if mask {
		flag = 1
	}
	result := C.KVQFaultRunIntended(C.int(arm), C.int(status), flag, &stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
}

// runProjectFault projects a plain in-memory access object as BEFORE and then as
// AFTER with one projection stage armed (a projection id; with after, only for the
// second projection). With mask the natural verdict of the projection groups is
// ignored, so every id stays reachable on a system where a group fails naturally.
func runProjectFault(arm, status int, after, mask bool) faultRun {
	var stage, osStatus, completed C.int
	afterFlag, maskFlag := C.int(0), C.int(0)
	if after {
		afterFlag = 1
	}
	if mask {
		maskFlag = 1
	}
	result := C.KVQFaultRunProject(C.int(arm), C.int(status), afterFlag, maskFlag, &stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
}

// runBeforeNatural runs the first half of the create call, unarmed: symbol
// resolution, the intended access object and its BEFORE projection.
func runBeforeNatural() faultRun {
	var stage, osStatus, completed C.int
	result := C.KVQFaultRunBefore(&stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
}

// authorizationsProbe describes the inputs of the projection's authorizations group.
// Counts: [0] ACLs, [1] ACLs or names that are unreadable, [2] names examined, [3] names
// the UTF-8 conversion count check rejects, [4] names the projection's own text writer
// rejects, [5] ACLs whose authorization numbers cannot be read, [6] characters of the
// first rejected name, [7] characters CFStringGetBytes reported for it. Name is that
// first rejected name (authorization names are public constants).
type authorizationsProbe struct {
	Counts [8]int
	Name   string
	Status int
}

func probeAuthorizations() authorizationsProbe {
	var out [8]C.int
	name := make([]C.char, 128)
	status := C.KVQFaultProbeAuthorizations(&out[0], &name[0], C.int(len(name)))
	var counts [8]int
	for i := range out {
		counts[i] = int(out[i])
	}
	return authorizationsProbe{Counts: counts, Name: C.GoString(&name[0]), Status: int(status)}
}

// runLoginFault runs only the login-keychain step with one stage armed.
func runLoginFault(arm, status int) faultRun {
	var stage, osStatus, completed C.int
	result := C.KVQFaultRunLogin(C.int(arm), C.int(status), &stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
}

// runSelfFault runs the running-code check with one stage armed.
func runSelfFault(arm, status int) faultRun {
	var stage, osStatus C.int
	result := C.KVQFaultRunSelf(C.int(arm), C.int(status), &stage, &osStatus)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus)}
}

// noteTwice records two failures in order and reports what the diagnostic kept.
func noteTwice(firstStage, firstStatus, secondStage, secondStatus int) faultRun {
	var stage, osStatus C.int
	C.KVQFaultNoteTwice(C.int(firstStage), C.int(firstStatus), C.int(secondStage), C.int(secondStatus), &stage, &osStatus)
	return faultRun{Stage: int(stage), OSStatus: int(osStatus)}
}

// probeOwnerACL describes what SecAccessCopyOwnerAndACL returns (the list the
// projection reads) next to SecAccessCopyACLList (the list the constructor reads).
// Indices: [0] OwnerAndACL status, [1] list present, [2] is an array, [3] elements,
// [4] SecACL elements, [5] dictionaries, [6] data, [7] strings, [8] first element's
// type id, [9] SecACL type id, [10] SecACLGetAuthorizations status on the first SecACL
// element (-1 none), [11] its count, [12] ACLList status, [13] its elements, [14] its
// SecACL elements.
func probeOwnerACL() ([16]int, int) {
	var out [16]C.int
	status := C.KVQFaultProbeOwnerACL(&out[0])
	var values [16]int
	for i := range out {
		values[i] = int(out[i])
	}
	return values, int(status)
}

// runProjectNonACL projects a plain access object while the projection sees a string
// where it expects an ACL object.
func runProjectNonACL() faultRun {
	var stage, osStatus, completed C.int
	result := C.KVQFaultRunProjectNonACL(&stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
}

// projectTwice builds the intended access object and returns two projections of it.
// With fresh the second one is of a second, separately built object.
func projectTwice(fresh bool) (first, second []byte, run faultRun) {
	const capacity = 65536
	a, b := make([]byte, capacity), make([]byte, capacity)
	var la, lb, stage, osStatus C.int
	flag := C.int(0)
	if fresh {
		flag = 1
	}
	result := C.KVQFaultProjectTwice(flag, (*C.uchar)(unsafe.Pointer(&a[0])), (*C.uchar)(unsafe.Pointer(&b[0])), C.int(capacity), &la, &lb, &stage, &osStatus)
	run = faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: result == 0}
	if la > 0 && int(la) <= capacity {
		first = a[:la]
	}
	if lb > 0 && int(lb) <= capacity {
		second = b[:lb]
	}
	return first, second, run
}
