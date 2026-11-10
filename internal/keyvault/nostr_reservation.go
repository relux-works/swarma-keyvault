package keyvault

type recoveryReservationProvider interface {
	RecoveryList() ([]RecoveryRecord, error)
}

// The shared vault lock must cover this admission and the following mutation.
// A paired item reserves its physical account and both logical purpose accounts.
func checkNostrReservation(backend NostrBackend, service, purpose string, version int) error {
	account, err := nostrAddress(service, purpose, version)
	if err != nil {
		return err
	}
	records, err := backend.List()
	if err != nil {
		return err
	}
	provider, paired := backend.(recoveryReservationProvider)
	seen := map[string]bool{}
	for _, r := range records {
		if validateNostrRecord(r) != nil || seen[r.Account()] {
			return nostrRefuse("invalid_record")
		}
		seen[r.Account()] = true
		if r.Account() == account {
			return nostrRefuse("duplicate")
		}
		if r.Storage == "enclave-wrapped-keychain" && !paired {
			return nostrRefuse("store_unavailable")
		}
	}
	if !paired {
		return nil
	}
	groups, err := provider.RecoveryList()
	if err != nil {
		return err
	}
	for _, g := range groups {
		if validateRecoveryRecord(g) != nil {
			return nostrRefuse("invalid_record")
		}
		n := g.PurposeAccount(g.Nostr)
		c := g.PurposeAccount(g.Namecoin)
		if account == g.Account() || account == n || account == c {
			return nostrRefuse("duplicate")
		}
	}
	return nil
}
