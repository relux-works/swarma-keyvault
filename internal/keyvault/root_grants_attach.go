package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// This is an UNWIRED private vault seam, not a general external store. Its real
// implementation must be the sole qualified signed vault, with its actual ACL
// checks and helper/code admission. Fixtures only prove public-data ordering.
// LockExistingRootGrants MUST take the existing mutation guard, refusing a
// missing guard without creating a file/directory or using a bootstrap fallback.
type rootGrantsAttachVault interface {
	LockExistingRootGrants(context.Context) (rootGrantsLockedVault, error)
}

// No old-pair private read, unwrap, update/delete, adoption, migration, wrapping,
// install or prerequisite-creation operation can be expressed by this interface.
type rootGrantsLockedVault interface {
	RecoveryPublicMetadata(service string, version int) ([]byte, error)
	// Collision checks physical AND logical root addresses across every admitted
	// storage form. An unsupported/ambiguous inventory refuses, never ignores it.
	RootGrantsCollision(RootGrantsAddress) (bool, error)
	// Atomic CREATE ONLY in RootGrantsNamespace. Existing items cannot be replaced.
	// The real adapter must enforce sole-vault ACL and authentic qualified-helper
	// sealing before this boundary. Shape validation cannot provide that evidence.
	AddRootGrantsOnly(rootGrantsSealedItem) error
	// Metadata-only readback also checks actual sole qualified vault ACL. It must
	// not read/decrypt any old or new private value to produce a public receipt.
	RootGrantsPublicMetadata(RootGrantsAddress) ([]byte, error)
	Release()
}

type rootGrantsSealedItem struct {
	address  RootGrantsAddress
	metadata string
	envelope string
}

// rootGrantsAddNotApplied is a backend GUARANTEE of zero effect, never inferred
// from a generic OS status or lost response. Its closed reasons carry no native
// diagnostic/private bytes. All other add errors are conservatively UNKNOWN.
type rootGrantsAddRefusal uint8

const (
	rootGrantsAddDuplicate rootGrantsAddRefusal = iota + 1
	rootGrantsAddACLRefused
	rootGrantsAddCodeRefused
	rootGrantsAddWrappingRefused
	// Appended, existing values unchanged: a malformed/misaddressed packet reaching
	// the storage boundary, and a native/keychain failure before the add dispatch.
	rootGrantsAddInvalidItem
	rootGrantsAddUnavailable
)

type rootGrantsAddNotApplied struct{ reason rootGrantsAddRefusal }

func (*rootGrantsAddNotApplied) Error() string { return "Root grants add definitely not applied" }

func rootGrantsAddRefusalCode(err error) string {
	var noEffect *rootGrantsAddNotApplied
	if !errors.As(err, &noEffect) || noEffect == nil {
		return ""
	}
	switch noEffect.reason {
	case rootGrantsAddDuplicate:
		return "duplicate"
	case rootGrantsAddACLRefused:
		return "acl_refused"
	case rootGrantsAddCodeRefused:
		return "code_not_admitted"
	case rootGrantsAddWrappingRefused:
		return "wrapping_policy_refused"
	case rootGrantsAddInvalidItem:
		return "invalid_envelope"
	case rootGrantsAddUnavailable:
		return "operation_unavailable"
	default:
		return "" // unknown guarantee/reason is not accepted
	}
}

type RootGrantsAttachFailure struct {
	Code      string                `json:"code"`
	Phase     string                `json:"phase"`
	Outcome   string                `json:"outcome"`
	Message   string                `json:"message"`
	Reference *RootGrantsProjection `json:"reference,omitempty"`
}

type rootGrantsAttachError struct{ public RootGrantsAttachFailure }

func (e *rootGrantsAttachError) Error() string { return e.public.Message }
func (e *rootGrantsAttachError) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.public)
}

func rootGrantsAttachFailed(code, phase, outcome string, reference *RootGrantsProjection) error {
	message := "Root grants attachment refused; preserve existing items"
	if outcome == "unknown" {
		message = "Root grants attachment outcome unknown; do not retry or delete"
	}
	return &rootGrantsAttachError{public: RootGrantsAttachFailure{Code: code, Phase: phase, Outcome: outcome, Message: message, Reference: reference}}
}

type RootGrantsAttachResult struct {
	Outcome       string               `json:"outcome"`
	Root          RootGrantsProjection `json:"root"`
	PairUnchanged bool                 `json:"pair_unchanged"`
}

// rootGrantsAttachment is one finite attempt and holds only validated public
// metadata and sealed bytes. It exposes no authority/approval boolean or secret
// sink. A real qualified-helper envelope is a SEPARATE dependency: constructing
// this source plan does not authenticate a seal or enroll an owner.
type rootGrantsAttachState uint8

const (
	rootGrantsAttachPrepared rootGrantsAttachState = iota
	rootGrantsAttachActive
	rootGrantsAttachClosed
	rootGrantsAttachUnknown
	rootGrantsAttachStored
)

type rootGrantsAttachment struct {
	state *rootGrantsAttachmentState
}

type rootGrantsAttachmentState struct {
	mu     sync.Mutex
	stage  rootGrantsAttachState
	item   rootGrantsSealedItem
	public RootGrantsProjection
}

func (rootGrantsAttachment) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<root-grants-attachment>")
}
func (rootGrantsAttachment) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}

// newRootGrantsAttachment consumes/clears the opaque prepared scalar on EVERY
// return, after the future helper has sealed its own material. It never accepts
// a mnemonic, scalar, plaintext callback, caller hash or generic approval flag.
func newRootGrantsAttachment(prepared *rootGrantsPrepared, r RootGrantsRecord, envelope RootGrantsEnvelope) (*rootGrantsAttachment, error) {
	defer prepared.clear()
	view, err := prepared.publicView()
	if err != nil || view.Root != r.publicRoot() || view.Pair != r.Pair {
		return nil, rootGrantsAttachFailed("public_pin_mismatch", "prepare", "not_applied", nil)
	}
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		return nil, rootGrantsAttachFailed("invalid_arguments", "prepare", "not_applied", nil)
	}
	sealed, err := CanonicalRootGrantsEnvelope(envelope, r)
	if err != nil {
		return nil, rootGrantsAttachFailed("invalid_envelope", "prepare", "not_applied", nil)
	}
	return &rootGrantsAttachment{state: &rootGrantsAttachmentState{
		item:   rootGrantsSealedItem{address: RootGrantsAddress{Service: r.Service, Version: r.Version}, metadata: string(metadata), envelope: string(sealed)},
		public: rootGrantsProject(r)}}, nil
}

func (a *rootGrantsAttachment) commit(ctx context.Context, vault rootGrantsAttachVault) (result RootGrantsAttachResult, err error) {
	var empty RootGrantsAttachResult
	if a == nil || a.state == nil {
		return empty, rootGrantsAttachFailed("invalid_arguments", "prepare", "not_applied", nil)
	}
	s := a.state
	s.mu.Lock()
	if s.stage != rootGrantsAttachPrepared {
		uncertain := s.stage == rootGrantsAttachActive || s.stage == rootGrantsAttachUnknown
		s.mu.Unlock()
		if uncertain {
			return empty, rootGrantsAttachFailed("mutation_unknown", "commit", "unknown", &s.public)
		}
		return empty, rootGrantsAttachFailed("operation_unavailable", "prepare", "not_applied", nil)
	}
	s.stage = rootGrantsAttachActive // every attempt is terminal; no implicit retry
	s.mu.Unlock()
	addStarted := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		var failure *rootGrantsAttachError
		switch {
		case result.Outcome == "stored":
			s.stage = rootGrantsAttachStored
		case errors.As(err, &failure) && failure.public.Outcome == "unknown":
			s.stage = rootGrantsAttachUnknown
		case addStarted && err == nil: // interrupted/panicking backend after dispatch
			s.stage = rootGrantsAttachUnknown
		default:
			s.stage = rootGrantsAttachClosed
		}
	}()
	if ctx == nil || vault == nil {
		return empty, rootGrantsAttachFailed("invalid_arguments", "prepare", "not_applied", nil)
	}
	if ctx.Err() != nil {
		return empty, rootGrantsAttachFailed("canceled", "lock", "not_applied", nil)
	}
	locked, err := vault.LockExistingRootGrants(ctx)
	if err != nil || locked == nil {
		if locked != nil {
			locked.Release()
		}
		return empty, rootGrantsAttachFailed("lock_unavailable", "lock", "not_applied", nil)
	}
	defer locked.Release()
	pair := s.public.Pair
	readPair := func() error {
		raw, err := locked.RecoveryPublicMetadata(pair.Service, pair.Version)
		if err != nil || rootGrantsMatchPair(raw, pair) != nil {
			return recoveryRefuse("inventory_changed")
		}
		return nil
	}
	if readPair() != nil {
		return empty, rootGrantsAttachFailed("retained_record_mismatch", "preflight", "not_applied", nil)
	}
	collision, err := locked.RootGrantsCollision(s.item.address)
	if err != nil {
		return empty, rootGrantsAttachFailed("inventory_changed", "preflight", "not_applied", nil)
	}
	if collision {
		return empty, rootGrantsAttachFailed("duplicate", "preflight", "not_applied", nil)
	}
	// Recheck the complete pair metadata/pins immediately before the sole add,
	// still under the SAME existing guard. No missing state is manufactured.
	if readPair() != nil {
		return empty, rootGrantsAttachFailed("inventory_changed", "commit", "not_applied", nil)
	}
	if ctx.Err() != nil {
		return empty, rootGrantsAttachFailed("canceled", "commit", "not_applied", nil)
	}
	addStarted = true
	err = locked.AddRootGrantsOnly(s.item)
	if err != nil {
		if code := rootGrantsAddRefusalCode(err); code != "" {
			return empty, rootGrantsAttachFailed(code, "commit", "not_applied", nil)
		}
		return empty, rootGrantsAttachFailed("mutation_unknown", "commit", "unknown", &s.public)
	}
	// From this point even cancellation or malformed/lost readback is UNKNOWN.
	// No rollback, delete, add retry or automatic generation increment exists.
	if ctx.Err() != nil {
		return empty, rootGrantsAttachFailed("mutation_unknown", "readback", "unknown", &s.public)
	}
	readback, err := locked.RootGrantsPublicMetadata(s.item.address)
	if err != nil || !bytes.Equal(readback, []byte(s.item.metadata)) {
		return empty, rootGrantsAttachFailed("mutation_unknown", "readback", "unknown", &s.public)
	}
	if readPair() != nil || ctx.Err() != nil {
		return empty, rootGrantsAttachFailed("mutation_unknown", "readback", "unknown", &s.public)
	}
	return RootGrantsAttachResult{Outcome: "stored", Root: s.public, PairUnchanged: true}, nil
}
