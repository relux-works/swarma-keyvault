package keyvault

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Public schemas of the root-grants receipts (S-D contract, section 2).
const (
	RootGrantsReceiptSchema = "keyvault-root-grants-receipt/1"
	RootGrantsPublicSchema  = "keyvault-root-grants-public/1"
	// The sidecar is device-wrapped software secp256k1, not a hardware-generated
	// key; the label follows the existing Nostr projection.
	RootGrantsStorage  = "enclave-wrapped-keychain"
	RootGrantsPresence = "biometry-any-per-signature"
)

// RootGrantsAttachRequest carries every public parameter of one attach. There is
// deliberately no field for words, a scalar, a path, a namespace, a helper
// location, a timeout or a creation time: the vault chooses the time and the
// fixed production pieces choose everything else.
type RootGrantsAttachRequest struct {
	NostrIdentity, NamecoinIdentity string
	Version                         int // the retained pair's group generation
	NostrVersion, NamecoinVersion   int
	GrantsIdentity                  string
	GrantsVersion                   int
	// Independent pins from the owner's retained printout, never read from the vault.
	ExpectedGroupID            string
	ExpectedPairMetadataSHA256 string
	ExpectedNPub               string
	ExpectedNamecoinXPub       string
	ExpectedOrigin             string
}

// RootGrantsReceipt is the public success receipt of an attach. It exists only for
// outcome "stored"; it carries no ciphertext, device blob, wrapping point or
// private value.
type RootGrantsReceipt struct {
	Schema        string               `json:"schema"`
	Mode          string               `json:"mode"`
	Outcome       string               `json:"outcome"`
	Root          RootGrantsProjection `json:"root"`
	Storage       string               `json:"storage"`
	Presence      string               `json:"presence"`
	PrivateExport bool                 `json:"private_export"`
	PairUnchanged bool                 `json:"pair_unchanged"`
}

// NewRootGrantsReceipt admits only a completed, verified attach.
func NewRootGrantsReceipt(r RootGrantsAttachResult) (RootGrantsReceipt, error) {
	if r.Outcome != "stored" || !r.PairUnchanged {
		return RootGrantsReceipt{}, recoveryRefuse("receipt_unavailable")
	}
	return RootGrantsReceipt{Schema: RootGrantsReceiptSchema, Mode: "attach", Outcome: "stored", Root: r.Root,
		Storage: RootGrantsStorage, Presence: RootGrantsPresence, PrivateExport: false, PairUnchanged: true}, nil
}

// RootGrantsPublicReceipt is the JSON result of the public export command.
type RootGrantsPublicReceipt struct {
	Schema string `json:"schema"`
	RootGrantsPublicExport
}

// RootGrantsAttachFailureOf extracts the closed public failure of an attach, so a
// caller can map it to an exit class without parsing text.
func RootGrantsAttachFailureOf(err error) (RootGrantsAttachFailure, bool) {
	var failure *rootGrantsAttachError
	if !errors.As(err, &failure) || failure == nil {
		return RootGrantsAttachFailure{}, false
	}
	return failure.public, true
}

// expectedPair builds the independently pinned binding from the public flags. The
// schema is not a flag: it is read from the retained record, whose exact bytes the
// metadata SHA-256 pin already covers.
func (q RootGrantsAttachRequest) expectedPair() (RootGrantsAddress, RootGrantsPairBinding, error) {
	var none RootGrantsPairBinding
	address := RootGrantsAddress{Service: q.GrantsIdentity, Version: q.GrantsVersion}
	if _, err := address.Account(); err != nil {
		return address, none, recoveryRefuse("invalid_arguments")
	}
	for _, a := range []struct {
		service, purpose string
		version          int
	}{{q.NostrIdentity, "recovery", q.Version}, {q.NostrIdentity, "nostr", q.NostrVersion}, {q.NamecoinIdentity, "namecoin", q.NamecoinVersion}} {
		if _, err := nostrAddress(a.service, a.purpose, a.version); err != nil {
			return address, none, recoveryRefuse("invalid_arguments")
		}
	}
	if !lowerHex(q.ExpectedGroupID, 16) || !lowerHex(q.ExpectedPairMetadataSHA256, 32) {
		return address, none, recoveryRefuse("invalid_arguments")
	}
	pins := RecoveryRequest{ExpectedNPub: q.ExpectedNPub, ExpectedXPub: q.ExpectedNamecoinXPub, ExpectedOrigin: q.ExpectedOrigin}
	if pins.ValidateRestorePins() != nil {
		return address, none, recoveryRefuse("invalid_arguments")
	}
	_, words, err := bech32.Decode(q.ExpectedNPub)
	if err != nil {
		return address, none, recoveryRefuse("invalid_arguments")
	}
	public, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil || len(public) != 32 {
		return address, none, recoveryRefuse("invalid_arguments")
	}
	return address, RootGrantsPairBinding{
		Service: q.NostrIdentity, Version: q.Version, GroupID: q.ExpectedGroupID, MetadataSHA256: q.ExpectedPairMetadataSHA256,
		NostrIdentity: q.NostrIdentity, NostrVersion: q.NostrVersion, NostrPublicKey: hex.EncodeToString(public), NostrNPub: q.ExpectedNPub,
		NamecoinIdentity: q.NamecoinIdentity, NamecoinVersion: q.NamecoinVersion, NamecoinXPub: q.ExpectedNamecoinXPub, NamecoinOrigin: q.ExpectedOrigin,
	}, nil
}

// AttachRootGrants is the only exported attach entry. It binds the fixed
// production vault (existing guard, native Keychain seam, ACL policy) and the
// fixed helper route; no argument can select either. The retained pair is read as
// public metadata and compared with EVERY independently supplied pin BEFORE the
// helper starts; the guard-held preflight then repeats that check.
func AttachRootGrants(ctx context.Context, q RootGrantsAttachRequest) (RootGrantsAttachResult, error) {
	vault, err := newRootGrantsProductionVault()
	if err != nil {
		return RootGrantsAttachResult{}, rootGrantsAttachFailed("operation_unavailable", "preflight", "not_applied", nil)
	}
	return attachRootGrantsPinned(ctx, vault, q, time.Now, attachRootGrantsWithHelper)
}

// rootGrantsAttachRunner is the helper-and-commit stage. Production passes
// attachRootGrantsWithHelper; tests pass a recorder to prove it is never reached
// after a refusal and receives the exact canonical request otherwise.
type rootGrantsAttachRunner func(context.Context, rootGrantsAttachVault, []byte) (RootGrantsAttachResult, error)

func attachRootGrantsPinned(ctx context.Context, vault *rootGrantsProductionVault, q RootGrantsAttachRequest, now func() time.Time, run rootGrantsAttachRunner) (RootGrantsAttachResult, error) {
	var empty RootGrantsAttachResult
	refuse := func(code string) error { return rootGrantsAttachFailed(code, "preflight", "not_applied", nil) }
	if ctx == nil || vault == nil || vault.native == nil || now == nil || run == nil {
		return empty, refuse("invalid_arguments")
	}
	address, expected, err := q.expectedPair()
	if err != nil {
		return empty, refuse("invalid_arguments")
	}
	if ctx.Err() != nil {
		return empty, refuse("canceled")
	}
	if vault.native.Startup() != nil {
		return empty, refuse("code_not_admitted")
	}
	pairRaw, err := rootGrantsPairMetadata(vault.native, q.NostrIdentity, q.Version)
	if err != nil {
		var status *StatusError
		switch {
		case errors.Is(err, ErrNotFound):
			return empty, refuse("retained_record_mismatch")
		case errors.As(err, &status):
			return empty, refuse("operation_unavailable")
		}
		return empty, refuse("inventory_changed")
	}
	record, err := parseRecoveryRecord(pairRaw)
	if err != nil {
		return empty, refuse("retained_record_mismatch")
	}
	expected.Schema = record.Schema
	if validateRootGrantsPair(expected) != nil || rootGrantsMatchPair(pairRaw, expected) != nil {
		return empty, refuse("retained_record_mismatch")
	}
	request := rootGrantsPrivateRequest{Protocol: "keyvault-root-grants-private/1", Engine: "namecoin-root-grants-engine/1",
		Profile: rootGrantsProfile, Mode: "attach", PairMetadata: pairRaw, Pair: expected,
		Service: address.Service, Version: address.Version, Created: now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	encoded, err := json.Marshal(request)
	if err != nil {
		return empty, refuse("invalid_arguments")
	}
	defer clear(encoded)
	if _, err := rootGrantsHelperRequest(encoded); err != nil {
		return empty, rootGrantsHelperAttachErrorAt(err, "preflight")
	}
	result, err := run(ctx, vault, encoded)
	if err != nil {
		if _, ok := RootGrantsAttachFailureOf(err); ok {
			return empty, err
		}
		// An untyped error after the helper stage may follow a possible add: never
		// report it as a refusal.
		return empty, rootGrantsAttachFailed("mutation_unknown", "commit", "unknown", nil)
	}
	if result.Outcome != "stored" || !result.PairUnchanged {
		return empty, rootGrantsAttachFailed("mutation_unknown", "readback", "unknown", nil)
	}
	return result, nil
}

// RootGrantsPublicLookup returns the public export of one stored root. It reads
// attributes and the actual ACL only, under the existing guard, and never an item
// value. The sidecar, its ACL, and its referenced pair (exact metadata digest)
// must all validate; a missing guard, an unparseable or duplicate row, an
// unadmitted ACL or a changed pair refuses. It performs no publication.
func RootGrantsPublicLookup(ctx context.Context, grantsIdentity string, grantsVersion int) (RootGrantsPublicReceipt, error) {
	vault, err := newRootGrantsProductionVault()
	if err != nil {
		return RootGrantsPublicReceipt{}, err
	}
	return rootGrantsPublicLookup(ctx, vault, RootGrantsAddress{Service: grantsIdentity, Version: grantsVersion})
}

func rootGrantsPublicLookup(ctx context.Context, vault *rootGrantsProductionVault, address RootGrantsAddress) (RootGrantsPublicReceipt, error) {
	var none RootGrantsPublicReceipt
	if ctx == nil || vault == nil || vault.native == nil {
		return none, recoveryRefuse("invalid_arguments")
	}
	if _, err := address.Account(); err != nil {
		return none, recoveryRefuse("invalid_address")
	}
	if vault.native.Startup() != nil {
		return none, recoveryRefuse("code_not_admitted")
	}
	locked, err := vault.LockExistingRootGrants(ctx)
	if err != nil {
		return none, err
	}
	defer locked.Release()
	exists, err := locked.RootGrantsCollision(address)
	if err != nil {
		return none, err
	}
	if !exists {
		return none, ErrNotFound
	}
	metadata, err := locked.RootGrantsPublicMetadata(address)
	if err != nil {
		return none, err
	}
	record, err := ParseRootGrantsRecord(metadata)
	if err != nil {
		return none, err
	}
	pairRaw, err := locked.RecoveryPublicMetadata(record.Pair.Service, record.Pair.Version)
	if err != nil {
		return none, err
	}
	export, err := ExportRootGrants(record, pairRaw, record.Pair)
	if err != nil {
		return none, err
	}
	return RootGrantsPublicReceipt{Schema: RootGrantsPublicSchema, RootGrantsPublicExport: export}, nil
}
