package keyvault

import (
	"bytes"
	"context"
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// ReadRootGrantsForSigning returns one validated public/sealed snapshot. The
// pre-existing vault guard is held through inventory, exact-item selection,
// stored-ACL admission, pair binding, and the one-shot value read. It is released
// before this method returns; no private plaintext is handled here.
func (v *rootGrantsProductionVault) ReadRootGrantsForSigning(ctx context.Context, address RootGrantsAddress,
	expectedMetadataSHA256 string) (RootGrantsSigningSnapshot, error) {
	var empty RootGrantsSigningSnapshot
	if ctx == nil || !lowerHex(expectedMetadataSHA256, 32) {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "read", false)
	}
	account, err := address.Account()
	if err != nil {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}
	if v == nil || v.native == nil || v.policy == nil || v.lockSource == nil {
		return empty, rootGrantsGrantV3Failed("operation_unavailable", "read", false)
	}
	lock, err := v.lockSource()
	if err != nil {
		return empty, rootGrantsGrantV3Failed("lock_unavailable", "read", false)
	}
	guard, err := lockRootGrantsExisting(ctx, lock)
	if err != nil {
		if contextFailure := rootGrantsReadContextFailure(ctx); contextFailure != nil {
			return empty, contextFailure
		}
		return empty, rootGrantsGrantV3Failed("lock_unavailable", "read", false)
	}
	locked := &rootGrantsProductionLocked{vault: v, guard: guard}
	defer locked.Release()
	return locked.readRootGrantsForSigning(ctx, address, account, expectedMetadataSHA256)
}

func (l *rootGrantsProductionLocked) readRootGrantsForSigning(ctx context.Context, address RootGrantsAddress,
	account, expectedMetadataSHA256 string) (RootGrantsSigningSnapshot, error) {
	var empty RootGrantsSigningSnapshot
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.begin(); err != nil {
		return empty, rootGrantsGrantV3Failed("operation_unavailable", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}
	if err := l.vault.native.Startup(); err != nil {
		return empty, rootGrantsReadNativeFailure(ctx, err)
	}

	// Inventory first. The exact account and canonical metadata must already be
	// present before a native item reference is selected or its value is read.
	initialInventory, err := rootGrantsRootInventory(l.vault.native)
	if err != nil {
		return empty, rootGrantsReadInventoryFailure(ctx, err)
	}
	initialRow, ok := rootGrantsInventoryAccount(initialInventory, account)
	if !ok || initialRow.record.Service != address.Service || initialRow.record.Version != address.Version {
		return empty, rootGrantsGrantV3Failed("inventory_changed", "read", false)
	}
	if rootGrantsHashHex(initialRow.metadata) != expectedMetadataSHA256 {
		return empty, rootGrantsGrantV3Failed("public_pin_mismatch", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}

	// PrepareRead selects one exact account and retains its item reference, but
	// returns only metadata and the actual ACL. No value request is made yet.
	read, err := l.vault.native.PrepareRead(account)
	if err != nil {
		return empty, rootGrantsReadNativeFailure(ctx, err)
	}
	if read == nil {
		return empty, rootGrantsGrantV3Failed("operation_unavailable", "read", false)
	}
	defer read.Close()
	metadata := read.Metadata()
	aclFrame := read.ACLFrame()
	defer clear(metadata)
	defer clear(aclFrame)
	if len(metadata) == 0 || len(metadata) > 32768 || !bytes.Equal(metadata, initialRow.metadata) {
		return empty, rootGrantsGrantV3Failed("inventory_changed", "read", false)
	}
	record, err := ParseRootGrantsRecord(metadata)
	if err != nil || record.Service != address.Service || record.Version != address.Version {
		return empty, rootGrantsGrantV3Failed("inventory_changed", "read", false)
	}
	if rootGrantsHashHex(metadata) != expectedMetadataSHA256 {
		return empty, rootGrantsGrantV3Failed("public_pin_mismatch", "read", false)
	}
	projection, err := rootqualification.DecodeNativeProjection(aclFrame)
	if err != nil || l.vault.policy.AdmitStored(projection) != nil {
		return empty, rootGrantsGrantV3Failed("acl_refused", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}

	// Bind the root record to exactly one retained public pair before asking the
	// native plan for the sealed value.
	pairMetadata, err := rootGrantsPairMetadata(l.vault.native, record.Pair.Service, record.Pair.Version)
	if err != nil {
		return empty, rootGrantsReadPairFailure(ctx, err)
	}
	defer clear(pairMetadata)
	pairRecord, err := parseRecoveryRecord(pairMetadata)
	if err != nil {
		return empty, rootGrantsGrantV3Failed("retained_record_mismatch", "read", false)
	}
	if rootGrantsPairBinding(pairMetadata, pairRecord) != record.Pair {
		return empty, rootGrantsGrantV3Failed("binding_mismatch", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}

	envelope, err := read.ReadValue()
	if err != nil {
		return empty, rootGrantsReadNativeFailure(ctx, err)
	}
	defer clear(envelope)
	if _, err := ParseRootGrantsEnvelope(envelope, record); err != nil {
		return empty, rootGrantsGrantV3Failed("invalid_envelope", "read", false)
	}

	// Confirm the complete public inventory and retained pair still match the
	// exact selections used for this read while the same guard remains held.
	finalInventory, err := rootGrantsRootInventory(l.vault.native)
	if err != nil {
		return empty, rootGrantsReadInventoryFailure(ctx, err)
	}
	if !rootGrantsInventoriesEqual(initialInventory, finalInventory) {
		return empty, rootGrantsGrantV3Failed("inventory_changed", "read", false)
	}
	finalPair, err := rootGrantsPairMetadata(l.vault.native, record.Pair.Service, record.Pair.Version)
	if err != nil {
		return empty, rootGrantsReadPairFailure(ctx, err)
	}
	defer clear(finalPair)
	if !bytes.Equal(pairMetadata, finalPair) {
		return empty, rootGrantsGrantV3Failed("retained_record_mismatch", "read", false)
	}
	if err := rootGrantsReadContextFailure(ctx); err != nil {
		return empty, err
	}
	return RootGrantsSigningSnapshot{
		Metadata:     bytes.Clone(metadata),
		Envelope:     bytes.Clone(envelope),
		PairMetadata: bytes.Clone(pairMetadata),
	}, nil
}

func rootGrantsInventoryAccount(rows []rootGrantsRootRow, account string) (rootGrantsRootRow, bool) {
	for _, row := range rows {
		if row.account == account {
			return row, true
		}
	}
	return rootGrantsRootRow{}, false
}

func rootGrantsInventoriesEqual(a, b []rootGrantsRootRow) bool {
	if len(a) != len(b) {
		return false
	}
	byAccount := make(map[string][]byte, len(a))
	for _, row := range a {
		byAccount[row.account] = row.metadata
	}
	for _, row := range b {
		metadata, ok := byAccount[row.account]
		if !ok || !bytes.Equal(metadata, row.metadata) {
			return false
		}
	}
	return true
}

func rootGrantsReadContextFailure(ctx context.Context) error {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(ctx.Err()), "read", false)
}

func rootGrantsReadNativeFailure(ctx context.Context, err error) error {
	if contextFailure := rootGrantsReadContextFailure(ctx); contextFailure != nil {
		return contextFailure
	}
	code := "operation_unavailable"
	switch {
	case errors.Is(err, errRootGrantsNativeCode):
		code = "code_not_admitted"
	case errors.Is(err, errRootGrantsNativeItemMissing):
		code = "inventory_changed"
	case errors.Is(err, errRootGrantsNativeACL), errors.Is(err, rootqualification.ErrPolicyRefused):
		code = "acl_refused"
	default:
		var status *StatusError
		if errors.As(err, &status) {
			switch status.Status {
			case -25293: // errSecAuthFailed
				code = "acl_refused"
			case -25300: // errSecItemNotFound
				code = "inventory_changed"
			case -128: // errSecUserCanceled
				code = "canceled"
			case -25308: // errSecInteractionNotAllowed
				code = "operation_unavailable"
			default:
				code = "private_protocol_error"
			}
		} else {
			var refusal *Refusal
			if errors.As(err, &refusal) {
				switch refusal.Code {
				case "recovery_invalid_envelope":
					code = "invalid_envelope"
				case "recovery_operation_unavailable":
					code = "operation_unavailable"
				default:
					code = "private_protocol_error"
				}
			}
		}
	}
	return rootGrantsGrantV3Failed(code, "read", false)
}

func rootGrantsReadInventoryFailure(ctx context.Context, err error) error {
	if contextFailure := rootGrantsReadContextFailure(ctx); contextFailure != nil {
		return contextFailure
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return rootGrantsGrantV3Failed("inventory_changed", "read", false)
	}
	return rootGrantsReadNativeFailure(ctx, err)
}

func rootGrantsReadPairFailure(ctx context.Context, err error) error {
	if contextFailure := rootGrantsReadContextFailure(ctx); contextFailure != nil {
		return contextFailure
	}
	var refusal *Refusal
	if errors.As(err, &refusal) || errors.Is(err, ErrNotFound) {
		return rootGrantsGrantV3Failed("retained_record_mismatch", "read", false)
	}
	return rootGrantsReadNativeFailure(ctx, err)
}
