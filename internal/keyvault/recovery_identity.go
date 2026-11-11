package keyvault

// RecoveryPlan contains public names only. Advisory inventory is rechecked
// under the mutation lock after the user's exact identity confirmation.
type RecoveryPlan struct {
	Schema           string `json:"schema"`
	Advisory         bool   `json:"advisory"`
	NostrIdentity    string `json:"nostr_identity"`
	NamecoinIdentity string `json:"namecoin_identity"`
	Version          int    `json:"version"`
	NostrVersion     int    `json:"nostr_version"`
	NamecoinVersion  int    `json:"namecoin_version"`
	Group            string `json:"group"`
	NostrRecord      string `json:"nostr_record"`
	NamecoinRecord   string `json:"namecoin_record"`
}

func recoveryPlan(q RecoveryRequest) RecoveryPlan {
	g, _ := nostrAddress(q.NostrIdentity, "recovery", q.Version)
	n, _ := nostrAddress(q.NostrIdentity, "nostr", q.NostrVersion)
	c, _ := nostrAddress(q.NamecoinIdentity, "namecoin", q.NamecoinVersion)
	return RecoveryPlan{Schema: "keyvault-recovery-plan/1", Advisory: true, NostrIdentity: q.NostrIdentity, NamecoinIdentity: q.NamecoinIdentity, Version: q.Version, NostrVersion: q.NostrVersion, NamecoinVersion: q.NamecoinVersion, Group: g, NostrRecord: n, NamecoinRecord: c}
}

func recordRecoveryPlan(r RecoveryRecord) RecoveryPlan {
	return recoveryPlan(RecoveryRequest{NostrIdentity: r.purposeService(r.Nostr), NamecoinIdentity: r.purposeService(r.Namecoin), Version: r.Version, NostrVersion: r.Nostr.Version, NamecoinVersion: r.Namecoin.Version})
}

// RecoveryPlanner has only metadata inventory and a shared lock. It has no
// helper, randomness, terminal, private-data or mutation interface.
type RecoveryPlanner struct {
	inventory RecoveryInventory
	lock      interface{ LockReadOnly() (func(), error) }
}

func NewRecoveryPlanner(inventory RecoveryInventory, lock interface{ LockReadOnly() (func(), error) }) *RecoveryPlanner {
	return &RecoveryPlanner{inventory: inventory, lock: lock}
}

func (m *RecoveryManager) Plan(q RecoveryRequest) (RecoveryPlan, error) {
	lock, _ := m.lock.(interface{ LockReadOnly() (func(), error) })
	return NewRecoveryPlanner(m.backend, lock).Plan(q)
}

func (p *RecoveryPlanner) Plan(q RecoveryRequest) (RecoveryPlan, error) {
	var zero RecoveryPlan
	if q.Service != "" {
		return zero, recoveryRefuse("invalid_address")
	}
	q, err := normalizeRecoveryIdentities(q)
	if err != nil {
		return zero, err
	}
	if p == nil || p.inventory == nil {
		return zero, recoveryRefuse("unavailable")
	}
	if p.lock == nil {
		return zero, recoveryRefuse("lock_unavailable")
	}
	release, err := p.lock.LockReadOnly()
	if err != nil {
		return zero, recoveryRefuse("lock_unavailable")
	}
	defer release()
	groups, err := p.inventory.RecoveryList()
	if err != nil {
		return zero, err
	}
	keys, err := p.inventory.List()
	if err != nil {
		return zero, err
	}
	highest := map[string]int{}
	add := func(service, purpose string, version int) {
		k := service + "\x00" + purpose
		if version > highest[k] {
			highest[k] = version
		}
	}
	for _, r := range groups {
		if validateRecoveryRecord(r) != nil {
			return zero, recoveryRefuse("invalid_record")
		}
		add(r.Service, "recovery", r.Version)
		add(r.purposeService(r.Nostr), "nostr", r.Nostr.Version)
		add(r.purposeService(r.Namecoin), "namecoin", r.Namecoin.Version)
	}
	for _, r := range keys {
		if validateNostrRecord(r) != nil {
			return zero, recoveryRefuse("invalid_record")
		}
		add(r.Service, r.Purpose, r.Version)
	}
	for _, p := range []struct {
		service, purpose string
		value            *int
	}{{q.NostrIdentity, "recovery", &q.Version}, {q.NostrIdentity, "nostr", &q.NostrVersion}, {q.NamecoinIdentity, "namecoin", &q.NamecoinVersion}} {
		if *p.value < 0 || *p.value > 2147483647 {
			return zero, recoveryRefuse("invalid_address")
		}
		if *p.value == 0 {
			v := highest[p.service+"\x00"+p.purpose]
			if v == 2147483647 {
				return zero, recoveryRefuse("generation_exhausted")
			}
			*p.value = v + 1
		}
	}
	if err := validateRecoveryRequest(q); err != nil {
		return zero, err
	}
	if err := recoveryPreflight(p.inventory, q); err != nil {
		return zero, err
	}
	return recoveryPlan(q), nil
}

// Service is only an explicit legacy alias. The new form never infers a
// missing purpose identity, even when the other one was supplied.
func normalizeRecoveryIdentities(q RecoveryRequest) (RecoveryRequest, error) {
	if q.Service != "" {
		if q.NostrIdentity != "" || q.NamecoinIdentity != "" {
			return q, recoveryRefuse("invalid_address")
		}
		q.NostrIdentity, q.NamecoinIdentity = q.Service, q.Service
	} else {
		q.Service = q.NostrIdentity
	}
	if ValidateName("service", CodeInvalidService, q.NostrIdentity) != nil || ValidateName("service", CodeInvalidService, q.NamecoinIdentity) != nil {
		return q, recoveryRefuse("invalid_address")
	}
	return q, nil
}
