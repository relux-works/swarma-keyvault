package main

import (
	"io"
	"os"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

const rootQualificationChildLimit = 30 * time.Second

// This is one exact argv, not the ordinary flag parser or a namespace/ref
// selector. A linker mark alone never admits a different invocation.
func rootQualificationChildInvocation(args []string) bool {
	return len(args) == 5 && args[0] == "--json" && args[1] == "root-grants" &&
		args[2] == "qualify-storage" && args[3] == "--case" && args[4] == "child-read"
}

func rootQualificationChildAdmitted(mark string, args []string) bool {
	return mark == "1" && rootQualificationChildInvocation(args)
}

// FIFO type is required, not endpoint provenance. The parent creates the
// anonymous pipe; descriptor metadata alone cannot establish its origin.
func rootQualificationChildPipeMode(mode os.FileMode) bool {
	return mode.Type() == os.ModeNamedPipe
}

func rootQualificationChildDeadline(entered time.Time) time.Time {
	return entered.Add(rootQualificationChildLimit)
}

// Only actual main calls this process watchdog. In-process run/tests do not
// arm os.Exit against a caller/test runner. The monotonic entry sample is
// preserved through blocked stdin, native code and output; no phase renews it.
func rootQualificationChildProcess(entered time.Time) int {
	if !rootQualificationChildAdmitted(recoveryQualificationOnly, os.Args[1:]) {
		return exitUsage
	}
	deadline := rootQualificationChildDeadline(entered)
	if !time.Now().Before(deadline) {
		return exitFailure
	}
	// Keep this armed through main's actual process exit, including the gap
	// after run returns. Only this dedicated production process enters here.
	time.AfterFunc(time.Until(deadline), func() { os.Exit(exitFailure) })
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	// Even if normal completion races the watchdog callback, expiry cannot
	// return a successful protocol exit. Parent TERM remains the earlier cap.
	if !time.Now().Before(deadline) {
		return exitFailure
	}
	return code
}

// Exactly one public request over pipe/FIFO stdin and one actual fixed-role
// native marker read. No backend/provider/callback, filesystem/ref option,
// private session or owner/presence operation is reachable through this route.
func runRootQualificationChild(stdout io.Writer) int {
	if recoveryQualificationOnly != "1" {
		return exitUsage
	}
	info, err := os.Stdin.Stat()
	if err != nil || !rootQualificationChildPipeMode(info.Mode()) {
		return exitFailure
	}
	request, err := rootqualification.ReadRequest(os.Stdin)
	if err != nil {
		return exitFailure // protocol fatal: no OS/parser/reference diagnostics
	}
	defer request.Clear()
	result, err := keyvault.RootQualificationMarkerRead(codesignpolicy.Qualification, request)
	if err != nil {
		result = rootqualification.Unqualified
	}
	// Only the native bridge's actual intended marker-read denial can yield
	// AccessRefused. UnexpectedAccess is protocol-valid exit0 but FAILS the
	// parent's qualification. Startup/metadata/unknown is never a passing read.
	return rootQualificationChildResponse(stdout, result)
}

// Pure finite formatting does not determine whether a native control passed.
// A response write failure is fatal and never emits a diagnostic or envelope.
func rootQualificationChildResponse(stdout io.Writer, result rootqualification.Result) int {
	if rootqualification.WriteResponse(stdout, result) != nil {
		return exitFailure
	}
	return exitOK
}
