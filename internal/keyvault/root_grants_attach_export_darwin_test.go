//go:build darwin && cgo

package keyvault

import (
	"context"
	"errors"
	"testing"
)

// Claim: the two exported entries, bound to the real production vault and the
// real native seam, refuse in an executable that is not the signed vault BEFORE
// reading the pair, taking the guard or starting the helper: attach reports
// code_not_admitted (preflight, not_applied) and the public lookup refuses with the
// code refusal and returns no value. Limit: shows the ordering for the unsigned
// test executable only; the signed vault's admission is an attended native lane.
func TestRootGrantsExportedEntriesRefuseUnsignedExecutable(t *testing.T) {
	q := rootGrantsAttachRequestFor(t, "keyvault-recovery/2")
	result, err := AttachRootGrants(context.Background(), q)
	rootGrantsAttachFailure13(t, result, err, "code_not_admitted", "preflight", "not_applied")
	receipt, err := RootGrantsPublicLookup(context.Background(), "example-root", 1)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != "recovery_code_not_admitted" || receipt.IDValueUTF8 != "" {
		t.Fatalf("public lookup did not refuse before any read: %v", err)
	}
}
