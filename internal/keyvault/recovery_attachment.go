package keyvault

// RootGrantsAttachmentInventory lets the recovery manager see whether a root-grants
// item references a retained pair. The production backend implements it; a backend
// that cannot (a test fake) simply has no attachment to protect.
type RootGrantsAttachmentInventory interface {
	RootGrantsAttached(RecoveryRecord) (bool, error)
}

var _ RootGrantsAttachmentInventory = (*NostrSecurityStore)(nil)

// RootGrantsAttached reports whether any stored root references this pair by its
// address or its group id. The whole root inventory must validate: an unparseable
// or ambiguous inventory refuses (error) instead of reading as "not attached".
func (*NostrSecurityStore) RootGrantsAttached(pair RecoveryRecord) (bool, error) {
	native := newRootGrantsNative()
	if native == nil {
		return false, recoveryRefuse("operation_unavailable")
	}
	return rootGrantsAttachedTo(native, pair)
}

func rootGrantsAttachedTo(native rootGrantsNative, pair RecoveryRecord) (bool, error) {
	rows, err := rootGrantsRootInventory(native)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		ref := row.record.Pair
		if (ref.Service == pair.Service && ref.Version == pair.Version) || ref.GroupID == pair.GroupID {
			return true, nil
		}
	}
	return false, nil
}
