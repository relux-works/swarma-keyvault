//go:build linux

package main

import "testing"

// Keep the legacy contract exercised on its supported platform, including
// cancellation, responsive framing and unchanged inherited descriptor flags.
func TestInheritedProtocolCancellation(t *testing.T) {
	testProtocolCancellation(t, []string{"write", "read", "responsive"})
}
