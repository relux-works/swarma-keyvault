//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"context"
)

// No runtime executable/verifier/pin option. Use the same build-pinned paired
// helper and actual hardened-code check as recovery, without changing its old
// argument,120s budget or private behavior. This path returns PUBLIC/SEALED only.
func invokeRootGrantsHelper(ctx context.Context, raw []byte) (*rootGrantsHelperResult, error) {
	if _, err := rootGrantsHelperRequest(raw); err != nil {
		return nil, err
	}
	// Snapshot before authentication/start; this SAME owned request is sent
	// and later admitted, regardless of subsequent caller-buffer mutation.
	owned := bytes.Clone(raw)
	keep := false
	defer func() {
		if !keep {
			clear(owned)
		}
	}()
	pin, err := rootGrantsHelperPin()
	if err != nil {
		return nil, err
	}
	path, err := rootGrantsHelperPath()
	if err != nil {
		return nil, err
	}
	payload, pid, err := rootGrantsHelperExchange(ctx, owned, pin, rootGrantsExecHost{path: path})
	if err != nil {
		return nil, err
	}
	// This is the only production minting site. Validation alone never mints
	// this completion; it follows actual binding/live-PID/ACK/EOF/exit evidence.
	keep = true
	return &rootGrantsHelperResult{completion: &rootGrantsHelperCompletion{pid: pid, request: owned, sealed: payload}}, nil
}
