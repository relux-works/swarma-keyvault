//go:build !linux

package main

import (
	"strings"
	"testing"
)

func TestLegacyProtocolRequiresLinux(t *testing.T) {
	p, err := openProtocol()
	if p != nil || err == nil || !strings.Contains(err.Error(), "use --owned-protocol") {
		t.Fatalf("unsupported legacy protocol did not refuse explicitly: %v", err)
	}
}
