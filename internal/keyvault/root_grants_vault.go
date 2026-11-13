package keyvault

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// This file is the production adapter of the root attach seam
// (rootGrantsAttachVault / rootGrantsLockedVault). It holds the existing mutation
// guard, reads only public metadata and ACLs, and performs one create-only add of
// an access object that the finite ACL policy admitted before the add. The
// Keychain/Security.framework side is the private rootGrantsNative seam: Darwin
// binds it to cgo, tests bind a recording fake. Stored values are only exposed
// through a two-phase read plan after Go admits that plan's actual ACL and pins.

var (
	errRootGrantsNativeCode           = errors.New("root grants native: running code is not admitted")
	errRootGrantsNativeACL            = errors.New("root grants native: access object refused")
	errRootGrantsNativeItemMissing    = errors.New("root grants native: selected item changed or disappeared")
	errRootGrantsACLPolicyUnavailable = errors.New("root grants ACL policy: no admitted owner/writer policy")
	errRootGrantsVaultReleased        = errors.New("root grants vault: guard already released")
)

// rootGrantsACLPolicy is the finite owner/writer admission predicate over a
// decoded KVQP1 projection. It is a positive allowlist derived from the observed
// native forms, and it has two entry points because the access object built in
// memory and the item the Keychain stores are not the same ACL set: the intended
// object is admitted before the add and the stored item's ACL after it, each
// against its own form and never against a union of the two.
type rootGrantsACLPolicy interface {
	AdmitIntended(rootqualification.Projection) error
	AdmitStored(rootqualification.Projection) error
}

// rootGrantsNoACLPolicy refuses every projection. It is the fail-closed value
// that production falls back to if the allowlist cannot be constructed, and a
// test double; it is not the production policy.
type rootGrantsNoACLPolicy struct{}

func (rootGrantsNoACLPolicy) AdmitIntended(rootqualification.Projection) error {
	return errRootGrantsACLPolicyUnavailable
}

func (rootGrantsNoACLPolicy) AdmitStored(rootqualification.Projection) error {
	return errRootGrantsACLPolicyUnavailable
}

// rootGrantsAccessDescriptor is the description that every production root item's
// non-partition ACLs carry. It must equal KVRGAccessDescriptor in the native store
// unit; a source-guard test compares the two literals.
const rootGrantsAccessDescriptor = "Root grants key"

// rootGrantsPolicyFor builds the allowlist for one descriptor and refuses
// everything if it cannot (fail closed).
func rootGrantsPolicyFor(descriptor string) rootGrantsACLPolicy {
	policy, err := rootqualification.NewStoragePolicy(descriptor)
	if err != nil {
		return rootGrantsNoACLPolicy{}
	}
	return policy
}

// productionRootGrantsACLPolicy is the single wiring point of the ACL allowlist.
func productionRootGrantsACLPolicy() rootGrantsACLPolicy {
	return rootGrantsPolicyFor(rootGrantsAccessDescriptor)
}

// rootGrantsNativeAdd is one prepared create-only add. The access object that
// ACLFrame describes is the exact object Commit adds with.
type rootGrantsNativeAdd interface {
	ACLFrame() []byte
	// Commit performs the single SecItemAdd. attempted is true only once that call
	// was dispatched; status is 0 or the native OS status.
	Commit(account, metadata string, envelope []byte) (attempted bool, status int)
	Close()
}

// rootGrantsNative is the complete native surface of the root grants adapter.
// Its one item-value read is a one-shot second phase on a retained item reference;
// no update, delete or namespace override exists here.
type rootGrantsNative interface {
	// Startup resolves the ACL SPI and verifies the actual running vault, before
	// any Keychain query.
	Startup() error
	// PairRows and RootRows are attribute-only inventories in the existing
	// framing: account 0x1f metadata 0x1e, repeated.
	PairRows() ([]byte, error)
	RootRows() ([]byte, error)
	PrepareAdd() (rootGrantsNativeAdd, error)
	// Readback returns the stored metadata and the actual ACL frame of exactly one
	// item. It never returns the item value.
	Readback(account string) (metadata, aclFrame []byte, err error)
	// PrepareRead retains the exact item reference selected by account and returns
	// only its metadata and actual ACL projection. ReadValue is a separate one-shot
	// operation on that same retained reference, after Go has checked the ACL and
	// all public pins. Close is mandatory on every path.
	PrepareRead(account string) (rootGrantsNativeRead, error)
}

type rootGrantsNativeRead interface {
	Metadata() []byte
	ACLFrame() []byte
	ReadValue() ([]byte, error)
	Close()
}

const (
	// closed native classes of the two-phase add (see root_grants_store_darwin.h)
	rootGrantsStatusDuplicate = -25299 // errSecDuplicateItem: definite no effect
)

type rootGrantsProductionVault struct {
	lockSource func() (FileLock, error)
	native     rootGrantsNative
	policy     rootGrantsACLPolicy
}

// newRootGrantsProductionVault binds the fixed production pieces: the existing
// vault lock path, the cgo native seam and the production ACL policy. There is
// no option to select a namespace, path, policy or native seam at runtime.
func newRootGrantsProductionVault() (*rootGrantsProductionVault, error) {
	native := newRootGrantsNative()
	if native == nil {
		return nil, recoveryRefuse("operation_unavailable")
	}
	return &rootGrantsProductionVault{lockSource: DefaultFileLock, native: native, policy: productionRootGrantsACLPolicy()}, nil
}

// LockExistingRootGrants takes the SAME flock as the other vault writers without
// creating any prerequisite: a missing guard refuses with nothing created.
func (v *rootGrantsProductionVault) LockExistingRootGrants(ctx context.Context) (rootGrantsLockedVault, error) {
	if v == nil || v.native == nil || v.policy == nil || v.lockSource == nil {
		return nil, recoveryRefuse("operation_unavailable")
	}
	lock, err := v.lockSource()
	if err != nil {
		return nil, recoveryRefuse("lock_unavailable")
	}
	guard, err := lockRootGrantsExisting(ctx, lock)
	if err != nil {
		return nil, err
	}
	return &rootGrantsProductionLocked{vault: v, guard: guard}, nil
}

type rootGrantsProductionLocked struct {
	vault    *rootGrantsProductionVault
	mu       sync.Mutex
	guard    *rootGrantsExistingGuard
	released bool
}

// Every operation holds mu, so Release can neither overlap nor precede a native
// call, and nothing runs outside the existing guard after Release.
func (l *rootGrantsProductionLocked) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	l.guard.Release()
}

type rootGrantsRow struct {
	account  string
	metadata []byte
}

// rootGrantsSplitRows decodes the closed attribute-row framing strictly: every
// row is account 0x1f metadata 0x1e with a non-empty account and metadata, and
// an empty row or a missing final separator is refused rather than skipped.
func rootGrantsSplitRows(raw []byte) ([]rootGrantsRow, error) {
	if len(raw) > 4*1024*1024 {
		return nil, recoveryRefuse("invalid_record")
	}
	if len(raw) == 0 {
		return nil, nil
	}
	parts := bytes.Split(raw, []byte{0x1e})
	if len(parts[len(parts)-1]) != 0 {
		return nil, recoveryRefuse("invalid_record")
	}
	var rows []rootGrantsRow
	for _, part := range parts[:len(parts)-1] {
		fields := bytes.Split(part, []byte{0x1f})
		if len(fields) != 2 || len(fields[0]) == 0 || len(fields[1]) == 0 || len(fields[1]) > recoveryMaxMetadata {
			return nil, recoveryRefuse("invalid_record")
		}
		rows = append(rows, rootGrantsRow{account: string(fields[0]), metadata: bytes.Clone(fields[1])})
	}
	return rows, nil
}

func (l *rootGrantsProductionLocked) begin() error {
	if l.released {
		return errRootGrantsVaultReleased
	}
	return nil
}

// RecoveryPublicMetadata returns the exact stored canonical bytes of ONE retained
// pair record. See rootGrantsPairMetadata.
func (l *rootGrantsProductionLocked) RecoveryPublicMetadata(service string, version int) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.begin(); err != nil {
		return nil, err
	}
	return rootGrantsPairMetadata(l.vault.native, service, version)
}

// rootGrantsPairMetadata reads attributes only. The whole paired namespace must
// validate (no unparsable, duplicate or ambiguous row), exactly one group must
// carry the address, and the result is the stored comment attribute itself, never
// a re-serialization. An absent pair is ErrNotFound.
func rootGrantsPairMetadata(native rootGrantsNative, service string, version int) ([]byte, error) {
	if _, err := nostrAddress(service, "recovery", version); err != nil {
		return nil, recoveryRefuse("invalid_address")
	}
	raw, err := native.PairRows()
	if err != nil {
		return nil, err
	}
	_, groups, err := recoveryRows(raw)
	if err != nil {
		return nil, err
	}
	account, matches := "", 0
	for _, g := range groups {
		if g.Service == service && g.Version == version {
			account = g.Account()
			matches++
		}
	}
	if matches == 0 {
		return nil, ErrNotFound
	}
	if matches > 1 {
		return nil, recoveryRefuse("duplicate")
	}
	rows, err := rootGrantsSplitRows(raw)
	if err != nil {
		return nil, err
	}
	var found []byte
	count := 0
	for _, row := range rows {
		if row.account == account {
			found = row.metadata
			count++
		}
	}
	if count != 1 {
		return nil, recoveryRefuse("invalid_record")
	}
	return found, nil
}

// RootGrantsCollision reports whether the target address is already stored. See
// rootGrantsRootInventory for the forms that refuse instead of being ignored.
func (l *rootGrantsProductionLocked) RootGrantsCollision(address RootGrantsAddress) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.begin(); err != nil {
		return false, err
	}
	target, err := address.Account()
	if err != nil {
		return false, recoveryRefuse("invalid_address")
	}
	rows, err := rootGrantsRootInventory(l.vault.native)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.account == target {
			return true, nil
		}
	}
	return false, nil
}

type rootGrantsRootRow struct {
	account  string
	metadata []byte
	record   RootGrantsRecord
}

// rootGrantsRootInventory inventories the root namespace by attributes only.
// Every row must be a canonical root record whose physical account equals its
// logical address, with no duplicate; anything else refuses instead of being
// ignored, so an unsupported or ambiguous inventory can never look empty.
func rootGrantsRootInventory(native rootGrantsNative) ([]rootGrantsRootRow, error) {
	raw, err := native.RootRows()
	if err != nil {
		return nil, err
	}
	rows, err := rootGrantsSplitRows(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var parsed []rootGrantsRootRow
	for _, row := range rows {
		r, err := ParseRootGrantsRecord(row.metadata)
		if err != nil {
			return nil, err
		}
		logical, err := (RootGrantsAddress{Service: r.Service, Version: r.Version}).Account()
		if err != nil || logical != row.account || seen[row.account] {
			return nil, recoveryRefuse("invalid_record")
		}
		seen[row.account] = true
		parsed = append(parsed, rootGrantsRootRow{account: row.account, metadata: bytes.Clone(row.metadata), record: r})
	}
	return parsed, nil
}

// rootGrantsItemAccount revalidates the sealed packet at the storage boundary.
// Shape validation proves no seal authenticity; it only keeps a malformed or
// misaddressed packet from reaching the Keychain.
func rootGrantsItemAccount(item rootGrantsSealedItem) (string, error) {
	account, err := item.address.Account()
	if err != nil {
		return "", err
	}
	if len(item.metadata) == 0 || len(item.metadata) > recoveryMaxMetadata || len(item.envelope) == 0 || len(item.envelope) > recoveryMaxCiphertext ||
		strings.IndexByte(account, 0) >= 0 || strings.IndexByte(item.metadata, 0) >= 0 {
		return "", recoveryRefuse("invalid_envelope")
	}
	r, err := ParseRootGrantsRecord([]byte(item.metadata))
	if err != nil || r.Service != item.address.Service || r.Version != item.address.Version {
		return "", recoveryRefuse("invalid_envelope")
	}
	if _, err := ParseRootGrantsEnvelope([]byte(item.envelope), r); err != nil {
		return "", err
	}
	return account, nil
}

// prepareAdmittedAdd verifies the running code, builds the intended access object
// natively and applies the ACL policy to its projection. Nothing is stored. Every
// refusal is a definite no-effect error with a closed reason; on success the caller
// owns the prepared add, whose access object is exactly the admitted one.
func (v *rootGrantsProductionVault) prepareAdmittedAdd() (rootGrantsNativeAdd, error) {
	refuse := func(reason rootGrantsAddRefusal) error { return &rootGrantsAddNotApplied{reason: reason} }
	if err := v.native.Startup(); err != nil {
		return nil, refuse(rootGrantsAddCodeRefused)
	}
	add, err := v.native.PrepareAdd()
	if err != nil || add == nil {
		switch {
		case errors.Is(err, errRootGrantsNativeCode):
			return nil, refuse(rootGrantsAddCodeRefused)
		case errors.Is(err, errRootGrantsNativeACL):
			return nil, refuse(rootGrantsAddACLRefused)
		}
		return nil, refuse(rootGrantsAddUnavailable)
	}
	intended, err := rootqualification.DecodeNativeProjection(add.ACLFrame())
	if err != nil || v.policy.AdmitIntended(intended) != nil {
		add.Close()
		return nil, refuse(rootGrantsAddACLRefused)
	}
	return add, nil
}

// admitIntendedACL is the same check made before the helper starts, so an owner
// never enters the recovery words only to learn that the access object would be
// refused at the add. The prepared object is discarded; the add repeats the check.
func (v *rootGrantsProductionVault) admitIntendedACL() error {
	add, err := v.prepareAdmittedAdd()
	if err != nil {
		return err
	}
	add.Close()
	return nil
}

// AddRootGrantsOnly is the sole mutation. Order: packet shape, running code and
// SPI (before any query), intended access object, policy admission of that very
// object, then ONE create-only add. Every refusal before the add is a definite
// no-effect result with a closed reason. After the add was dispatched only a
// definite duplicate is no-effect; everything else is UNKNOWN to the caller.
func (l *rootGrantsProductionLocked) AddRootGrantsOnly(item rootGrantsSealedItem) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	refuse := func(reason rootGrantsAddRefusal) error { return &rootGrantsAddNotApplied{reason: reason} }
	if err := l.begin(); err != nil {
		return refuse(rootGrantsAddUnavailable)
	}
	account, err := rootGrantsItemAccount(item)
	if err != nil {
		return refuse(rootGrantsAddInvalidItem)
	}
	add, err := l.vault.prepareAdmittedAdd()
	if err != nil {
		return err
	}
	defer add.Close()
	envelope := []byte(item.envelope)
	defer clear(envelope)
	attempted, status := add.Commit(account, item.metadata, envelope)
	switch {
	case attempted && status == 0:
		return nil
	case !attempted && status != 0:
		return refuse(rootGrantsAddUnavailable) // failed before the add was dispatched
	case attempted && status == rootGrantsStatusDuplicate:
		return refuse(rootGrantsAddDuplicate)
	}
	// Dispatched and not provably unapplied (or a contradictory native report):
	// the caller records UNKNOWN. The OS status is deliberately not carried into
	// any public diagnostic.
	return errors.New("root grants add outcome unknown")
}

// RootGrantsPublicMetadata reads one item's metadata and actual ACL, never its
// value. The ACL must be admitted by the same policy as the intended object, and
// the metadata must be a canonical record for exactly the requested address.
// Any refusal is an error, which the attach flow reports as UNKNOWN.
func (l *rootGrantsProductionLocked) RootGrantsPublicMetadata(address RootGrantsAddress) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.begin(); err != nil {
		return nil, err
	}
	account, err := address.Account()
	if err != nil {
		return nil, recoveryRefuse("invalid_address")
	}
	metadata, frame, err := l.vault.native.Readback(account)
	if err != nil {
		return nil, err
	}
	actual, err := rootqualification.DecodeNativeProjection(frame)
	if err != nil {
		return nil, err
	}
	if err := l.vault.policy.AdmitStored(actual); err != nil {
		return nil, err
	}
	r, err := ParseRootGrantsRecord(metadata)
	if err != nil || r.Service != address.Service || r.Version != address.Version {
		return nil, recoveryRefuse("invalid_record")
	}
	return bytes.Clone(metadata), nil
}
