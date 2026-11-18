//go:build darwin && cgo

package keyvault

import (
	"io"
	"os"
	"testing"
)

// This proves the Darwin+cgo production host starts the test executable with
// its exact helper argv; it exercises no helper signing and cannot run on Linux.
func TestRootGrantsTrustContractCountersignDarwinExecHostUsesExactArgv(t *testing.T) {
	const want = "--root-grants-sign-trust-contract-countersign-v1"
	child, err := (rootGrantsTrustContractCountersignExecHost{path: os.Args[0]}).start()
	if err != nil {
		t.Fatalf("start production Darwin helper host: %v", err)
	}
	if child == nil || child.input == nil || child.output == nil || child.wait == nil || child.kill == nil {
		t.Fatal("production Darwin helper host returned an incomplete child")
	}
	_ = child.input.Close()
	output, readErr := io.ReadAll(child.output)
	waitErr := child.wait()
	_ = child.output.Close()
	if readErr != nil {
		t.Fatalf("read helper argv witness: %v", readErr)
	}
	if waitErr != nil {
		t.Fatalf("test executable exited after helper argv: %v", waitErr)
	}
	if got := string(output); got != want {
		t.Fatalf("production Darwin helper argv = %q, want exact %q", got, want)
	}
}
