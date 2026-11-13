//go:build darwin && cgo && kvqfault

package keyvault

/*
#cgo CFLAGS: -DKVQ_FAULT_INJECTION
int KVQFaultRunIntended(int armStage, int armStatus, int maskRequirement, int *stage, int *status, int *completed);
int KVQFaultRunProject(int armStage, int armStatus, int armAfter, int *stage, int *status, int *completed);
int KVQFaultRunLogin(int armStage, int armStatus, int *stage, int *status, int *completed);
int KVQFaultRunSelf(int armStage, int armStatus, int *stage, int *status);
void KVQFaultNoteTwice(int firstStage, int firstStatus, int secondStage, int secondStatus, int *stage, int *status);
*/
import "C"

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
// second projection).
func runProjectFault(arm, status int, after bool) faultRun {
	var stage, osStatus, completed C.int
	flag := C.int(0)
	if after {
		flag = 1
	}
	result := C.KVQFaultRunProject(C.int(arm), C.int(status), flag, &stage, &osStatus, &completed)
	return faultRun{Result: int(result), Stage: int(stage), OSStatus: int(osStatus), Completed: completed != 0}
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
