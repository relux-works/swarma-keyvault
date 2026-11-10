package keyvault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// RecoveryTerminal is the owner terminal inside the vault process. Neither a
// secret argv/file route nor a private export command is part of this contract.
type RecoveryTerminal interface {
	ConfirmIdentities(RecoveryPlan) error
	ConfirmMnemonic(words [][]byte) error
	ReadMnemonic() ([]byte, error)
}

// RecoveryBackend exposes public metadata and ciphertext only. Native custody
// creates hardware wrapping keys in the paired, verified helper. A mutation
// error is uncertain unless the backend returns RecoveryNotAppliedError, which
// guarantees no effect (including a definite atomic-add duplicate).
type RecoveryBackend interface {
	NostrBackend
	RecoveryList() ([]RecoveryRecord, error)
	RecoveryStore(RecoveryRecord, []byte) error
	RecoveryDelete(RecoveryRecord) error
	NostrDelete(NostrRecord) error
}

type recoveryWrap struct {
	Blob          []byte `json:"blob"`
	Point         []byte `json:"point"`
	Fingerprint   string `json:"fingerprint"`
	Policy        string `json:"policy"`
	SilentRefused bool   `json:"silent_refused"`
}

type recoveryHelper interface {
	CreateWrap(purpose string) (recoveryWrap, error)
	UnwrapNostr(recoveryEnvelope) ([]byte, error)
}

type RecoveryManager struct {
	backend RecoveryBackend
	helper  recoveryHelper
	lock    Locker
	now     func() time.Time
	random  io.Reader
}

func NewRecoveryManager(backend RecoveryBackend, lock Locker) *RecoveryManager {
	return &RecoveryManager{backend: backend, helper: newRecoveryHelper(), lock: lock, now: time.Now, random: rand.Reader}
}

type RecoveryRequest struct {
	NostrIdentity, NamecoinIdentity            string
	Service                                    string
	Version, NostrVersion, NamecoinVersion     int
	ExpectedNPub, ExpectedXPub, ExpectedOrigin string
}

func validateRecoveryRequest(r RecoveryRequest) error {
	for _, v := range []struct {
		service string
		purpose string
		version int
	}{{r.Service, "recovery", r.Version}, {r.NostrIdentity, "nostr", r.NostrVersion}, {r.NamecoinIdentity, "namecoin", r.NamecoinVersion}} {
		if _, err := nostrAddress(v.service, v.purpose, v.version); err != nil {
			return recoveryRefuse("invalid_address")
		}
	}
	return nil
}

func (m *RecoveryManager) preflight(q RecoveryRequest) error {
	group, _ := nostrAddress(q.Service, "recovery", q.Version)
	nostr, _ := nostrAddress(q.NostrIdentity, "nostr", q.NostrVersion)
	namecoin, _ := nostrAddress(q.NamecoinIdentity, "namecoin", q.NamecoinVersion)
	wanted := map[string]bool{group: true, nostr: true, namecoin: true}
	groups, err := m.backend.RecoveryList()
	if err != nil {
		return err
	}
	for _, g := range groups {
		if validateRecoveryRecord(g) != nil {
			return recoveryRefuse("invalid_record")
		}
		if wanted[g.Account()] || wanted[g.PurposeAccount(g.Nostr)] || wanted[g.PurposeAccount(g.Namecoin)] {
			return recoveryRefuse("duplicate")
		}
	}
	keys, err := m.backend.List()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if validateNostrRecord(key) != nil {
			return recoveryRefuse("invalid_record")
		}
		if wanted[key.Account()] {
			return recoveryRefuse("duplicate")
		}
	}
	return nil
}

func (m *RecoveryManager) Create(q RecoveryRequest, terminal RecoveryTerminal, restore bool) (RecoveryRecord, error) {
	var zero RecoveryRecord
	var err error
	q, err = normalizeRecoveryIdentities(q)
	if err != nil {
		return zero, err
	}
	if validateRecoveryRequest(q) != nil {
		return zero, recoveryRefuse("invalid_address")
	}
	if terminal == nil || m.backend == nil || m.helper == nil || m.lock == nil || m.random == nil {
		return zero, recoveryRefuse("unavailable")
	}
	if restore && (q.ExpectedNPub == "" || q.ExpectedXPub == "" || q.ExpectedOrigin == "") {
		return zero, recoveryRefuse("public_pins_required")
	}
	if !restore && (q.ExpectedNPub != "" || q.ExpectedXPub != "" || q.ExpectedOrigin != "") {
		return zero, recoveryRefuse("invalid_arguments")
	}
	// Creating the lock/prerequisites is an effect, so confirm first.
	if err := terminal.ConfirmIdentities(recoveryPlan(q)); err != nil {
		return zero, recoveryRefuse("identity_confirmation_failed")
	}
	release, err := m.lock.Lock()
	if err != nil {
		return zero, recoveryRefuse("lock_unavailable")
	}
	defer release()
	if err := m.preflight(q); err != nil {
		return zero, err
	}
	var phrase []byte
	if restore {
		phrase, err = terminal.ReadMnemonic()
	} else {
		var entropy [32]byte
		defer clear(entropy[:])
		if _, err = io.ReadFull(m.random, entropy[:]); err != nil {
			return zero, recoveryRefuse("random_unavailable")
		}
		indices, e := mnemonicIndices(entropy[:])
		if e != nil {
			return zero, e
		}
		defer clear(indices)
		phrase, err = mnemonicPhrase(indices)
		if err != nil {
			return zero, err
		}
		defer clear(phrase)
		words := make([][]byte, len(indices))
		defer func() {
			for _, word := range words {
				clear(word)
			}
		}()
		for i, index := range indices {
			words[i] = []byte(recoveryWords[index])
		}
		if err = terminal.ConfirmMnemonic(words); err != nil {
			return zero, recoveryRefuse("confirmation_refused")
		}
	}
	defer clear(phrase)
	if err != nil {
		return zero, recoveryRefuse("terminal_refused")
	}
	indices, err := parseMnemonic(phrase)
	if err != nil {
		return zero, err
	}
	defer clear(indices)
	if len(indices) != 24 {
		return zero, recoveryRefuse("requires_24_words")
	}
	material, err := deriveRecovery(phrase)
	if err != nil {
		return zero, err
	}
	defer material.clear()
	if restore && (q.ExpectedNPub != material.npub || q.ExpectedXPub != material.xpub || q.ExpectedOrigin != material.origin) {
		return zero, recoveryRefuse("public_pin_mismatch")
	}
	// No hardware key or item is created until the human and public pins pass.
	n, err := m.helper.CreateWrap("nostr")
	if err != nil {
		return zero, err
	}
	c, err := m.helper.CreateWrap("namecoin")
	if err != nil {
		return zero, err
	}
	if validateRecoveryWrap(n, "nostr") != nil || validateRecoveryWrap(c, "namecoin") != nil {
		return zero, recoveryRefuse("wrapping_policy_refused")
	}
	var id [16]byte
	if _, err := io.ReadFull(m.random, id[:]); err != nil {
		return zero, recoveryRefuse("random_unavailable")
	}
	r := RecoveryRecord{Schema: "keyvault-recovery/2", GroupID: hex.EncodeToString(id[:]), Service: q.Service, Version: q.Version, Created: m.now().UTC().Truncate(time.Second).Format(time.RFC3339), Nostr: RecoveryPurpose{Service: q.NostrIdentity, Purpose: "nostr", Version: q.NostrVersion, Path: "m/44'/1237'/0'/0/0", Algorithm: "secp256k1-bip340", Presence: "none", PublicKey: material.publicKey, NPub: material.npub, WrappingPoint: n.Point, WrappingFingerprint: n.Fingerprint}, Namecoin: RecoveryPurpose{Service: q.NamecoinIdentity, Purpose: "namecoin", Version: q.NamecoinVersion, Path: "m/84'/7'/0'", Algorithm: "bip32-secp256k1", Presence: "biometry-any", XPub: material.xpub, Origin: material.origin, WrappingPoint: c.Point, WrappingFingerprint: c.Fingerprint}}
	if err := validateRecoveryRecord(r); err != nil {
		return zero, err
	}
	ne, err := recoverySeal(r, r.Nostr, n.Blob, material.nostr[:])
	if err != nil {
		return zero, err
	}
	var node [64]byte
	defer clear(node[:])
	copy(node[:32], material.namecoin.key[:])
	copy(node[32:], material.namecoin.chain[:])
	ce, err := recoverySeal(r, r.Namecoin, c.Blob, node[:])
	if err != nil {
		return zero, err
	}
	ciphertext := recoveryCiphertext{Schema: r.ciphertextSchema(), Nostr: ne, Namecoin: ce}
	encoded, err := json.Marshal(ciphertext)
	if err != nil {
		return zero, recoveryRefuse("invalid_envelope")
	}
	if _, err := parseRecoveryCiphertext(encoded, r); err != nil {
		return zero, err
	}
	// Repeat admission immediately before the sole atomic write, under the same
	// vault lock. Store must use SecItemAdd and never update an existing record.
	if err := m.preflight(q); err != nil {
		return zero, err
	}
	if err := m.backend.RecoveryStore(r, encoded); err != nil {
		var noEffect *RecoveryNotAppliedError
		if errors.As(err, &noEffect) {
			return zero, err
		}
		operation := "generate"
		if restore {
			operation = "restore"
		}
		return r, recoveryMutationError(operation, r, err)
	}
	return r, nil
}

func validateRecoveryWrap(w recoveryWrap, purpose string) error {
	if len(w.Blob) == 0 || len(w.Blob) > 16384 || validateWrapping(w.Point, w.Fingerprint) != nil {
		return recoveryRefuse("wrapping_policy_refused")
	}
	if (purpose == "nostr" && (w.Policy != "none" || w.SilentRefused)) || (purpose == "namecoin" && (w.Policy != "biometry-any" || !w.SilentRefused)) || (purpose != "nostr" && purpose != "namecoin") {
		return recoveryRefuse("wrapping_policy_refused")
	}
	return nil
}

func (m *RecoveryManager) Describe(service string, version int) (RecoveryRecord, error) {
	if _, err := nostrAddress(service, "recovery", version); err != nil {
		return RecoveryRecord{}, recoveryRefuse("invalid_address")
	}
	if m.backend == nil {
		return RecoveryRecord{}, recoveryRefuse("unavailable")
	}
	groups, err := m.backend.RecoveryList()
	if err != nil {
		return RecoveryRecord{}, err
	}
	var result RecoveryRecord
	count := 0
	for _, r := range groups {
		if validateRecoveryRecord(r) != nil {
			return RecoveryRecord{}, recoveryRefuse("invalid_record")
		}
		if r.Service == service && r.Version == version {
			result = r
			count++
		}
	}
	if count > 1 {
		return RecoveryRecord{}, recoveryRefuse("duplicate")
	}
	if count == 0 {
		return RecoveryRecord{}, ErrNotFound
	}
	return result, nil
}

type RecoveryDeleteRequest struct {
	NostrIdentity, NamecoinIdentity string
	Version                         int
	ExpectedGroupID                 string
}

func (m *RecoveryManager) Delete(q RecoveryDeleteRequest, terminal RecoveryTerminal) (RecoveryRecord, error) {
	var zero RecoveryRecord
	if ValidateName("service", CodeInvalidService, q.NostrIdentity) != nil || ValidateName("service", CodeInvalidService, q.NamecoinIdentity) != nil || q.Version < 1 || q.Version > 2147483647 {
		return zero, recoveryRefuse("invalid_address")
	}
	if !lowerHex(q.ExpectedGroupID, 16) || m.lock == nil || m.backend == nil {
		return zero, recoveryRefuse("public_pin_required")
	}
	r, err := m.Describe(q.NostrIdentity, q.Version)
	if err != nil {
		return zero, err
	}
	if r.GroupID != q.ExpectedGroupID || r.purposeService(r.Namecoin) != q.NamecoinIdentity {
		return zero, recoveryRefuse("public_pin_mismatch")
	}
	before, _ := json.Marshal(r)
	// Confirmation precedes a creating file lock. The exact public snapshot is
	// compared again under that lock; changed records are never auto-selected.
	if terminal == nil || terminal.ConfirmIdentities(recordRecoveryPlan(r)) != nil {
		return zero, recoveryRefuse("identity_confirmation_failed")
	}
	release, err := m.lock.Lock()
	if err != nil {
		return zero, recoveryRefuse("lock_unavailable")
	}
	defer release()
	current, err := m.Describe(q.NostrIdentity, q.Version)
	if err != nil {
		return zero, err
	}
	after, _ := json.Marshal(current)
	if !bytes.Equal(before, after) {
		return zero, recoveryRefuse("public_pin_mismatch")
	}
	if err := m.backend.RecoveryDelete(r); err != nil {
		return r, recoveryMutationError("delete", r, err)
	}
	return r, nil
}
