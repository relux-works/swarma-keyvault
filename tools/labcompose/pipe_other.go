//go:build !linux

package main

import "fmt"

// Shared inherited descriptions cannot portably be reopened with independent
// nonblocking flags. Callers on macOS must transfer dedicated pipe ownership.
func openProtocol() (*pipe, error) {
	return nil, fmt.Errorf("legacy protocol requires Linux; use --owned-protocol with dedicated pipes")
}
