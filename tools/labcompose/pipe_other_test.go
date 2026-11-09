//go:build !linux

package main

import "testing"

func TestLegacyProtocolRequiresLinux(t *testing.T) {
	p, err := openProtocol()
	if p != nil || err == nil || err.Error() != "legacy protocol requires Linux; use --owned-protocol with dedicated pipes" {
		t.Fatalf("unsupported legacy protocol did not refuse explicitly: %v", err)
	}
}
