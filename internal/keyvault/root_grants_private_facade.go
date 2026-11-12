package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RootGrantsPrivateSession is helper-local logical Go source, not an enrolled
// key, external SDK, native ABI or custody certificate. Copies share ONE engine
// and absolute deadline. There is no private input/getter/callback or store API.
type RootGrantsPrivateSession struct {
	engine *rootGrantsPrivateEngine
	ctx    context.Context
	cancel context.CancelFunc
}

func (RootGrantsPrivateSession) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<private-root-grants-session>")
}
func (RootGrantsPrivateSession) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}

// RootGrantsPrivateSealed contains canonical PUBLIC metadata and SEALED data
// only. It is not a stored/enrolled/presence/ACL or grant-authority receipt.
type RootGrantsPrivateSealed struct {
	Record   json.RawMessage `json:"record"`
	Envelope json.RawMessage `json:"envelope"`
}

type rootGrantsPrivateRequest struct {
	Protocol     string                `json:"protocol"`
	Engine       string                `json:"engine"`
	Profile      string                `json:"profile"`
	Mode         string                `json:"mode"`
	PairMetadata []byte                `json:"pair_metadata"`
	Pair         RootGrantsPairBinding `json:"pair"`
	Service      string                `json:"service"`
	Version      int                   `json:"version"`
	Created      string                `json:"created"`
}

// OpenRootGrantsPrivate accepts ONLY bounded canonical public request bytes.
// Its original900s deadline starts before decoding; an earlier caller deadline
// wins. It performs no tty, Keychain, native qualification, private read or add.
func OpenRootGrantsPrivate(ctx context.Context, rawPublicRequest []byte) (*RootGrantsPrivateSession, error) {
	return openRootGrantsPrivateWithClock(ctx, rawPublicRequest, rootGrantsWallClock{})
}

func openRootGrantsPrivateWithClock(ctx context.Context, raw []byte, clock rootGrantsClock) (*RootGrantsPrivateSession, error) {
	ctx, cancel, err := rootGrantsNewBudget(ctx, clock)
	if err != nil {
		return nil, rootGrantsPrivateError(err)
	}
	keep := false
	defer func() {
		if !keep {
			cancel()
		}
	}()
	if len(raw) > 262144 {
		return nil, recoveryRefuse("limit_exceeded")
	}
	if len(raw) == 0 {
		return nil, recoveryRefuse("invalid_arguments")
	}
	raw = bytes.Clone(raw)
	defer clear(raw)
	var request rootGrantsPrivateRequest
	if DecodeSingleJSON(raw, &request) != nil {
		return nil, recoveryRefuse("invalid_arguments")
	}
	defer clear(request.PairMetadata)
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(raw, canonical) || len(request.PairMetadata) == 0 {
		return nil, recoveryRefuse("invalid_arguments")
	}
	// Canonical null/missing strings serialize as empty. Check required fields
	// before interpreting an explicitly supplied unsupported version/mode.
	if request.Protocol == "" || request.Engine == "" || request.Profile == "" || request.Mode == "" {
		return nil, recoveryRefuse("invalid_arguments")
	}
	if request.Protocol != "keyvault-root-grants-private/1" || request.Engine != "namecoin-root-grants-engine/1" || request.Profile != rootGrantsProfile {
		return nil, recoveryRefuse("unsupported_version")
	}
	if request.Mode != "attach" {
		return nil, recoveryRefuse("unsupported_operation")
	}
	engine, err := newRootGrantsPrivateEngine(ctx, rootGrantsEngineInput{pairMetadata: request.PairMetadata, pair: request.Pair,
		target: RootGrantsAddress{Service: request.Service, Version: request.Version}, created: request.Created})
	if err != nil {
		if budgetErr := rootGrantsBudgetError(ctx); budgetErr != nil {
			return nil, budgetErr
		}
		return nil, rootGrantsPrivateError(err)
	}
	if err := rootGrantsBudgetError(ctx); err != nil {
		engine.close()
		return nil, rootGrantsPrivateError(err)
	}
	keep = true
	return &RootGrantsPrivateSession{engine: engine, ctx: ctx, cancel: cancel}, nil
}

func (s *RootGrantsPrivateSession) check() error {
	if s == nil || s.engine == nil || s.ctx == nil || s.cancel == nil {
		return recoveryRefuse("operation_unavailable")
	}
	if err := rootGrantsBudgetError(s.ctx); err != nil {
		s.engine.close()
		return rootGrantsPrivateError(err)
	}
	return nil
}

// Prepare has NO fd, reader, phrase, random or callback parameter. Its only
// production source is the existing engine's helper-owned controlling tty.
func (s *RootGrantsPrivateSession) Prepare() (RootGrantsPreparationPublic, error) {
	if err := s.check(); err != nil {
		return RootGrantsPreparationPublic{}, err
	}
	view, err := s.engine.prepare()
	if err != nil {
		if budgetErr := s.check(); budgetErr != nil {
			return RootGrantsPreparationPublic{}, budgetErr
		}
		return RootGrantsPreparationPublic{}, rootGrantsPrivateError(err)
	}
	if err := s.check(); err != nil {
		return RootGrantsPreparationPublic{}, err
	}
	return view, nil
}

func (s *RootGrantsPrivateSession) Seal(publicPoint, deviceBlob []byte) (RootGrantsPrivateSealed, error) {
	var empty RootGrantsPrivateSealed
	if err := s.check(); err != nil {
		return empty, err
	}
	sealed, err := s.engine.seal(publicPoint, deviceBlob)
	if err != nil {
		if budgetErr := s.check(); budgetErr != nil {
			return empty, budgetErr
		}
		return empty, rootGrantsPrivateError(err)
	}
	record, err := ParseRootGrantsRecord(sealed.metadata)
	if err != nil {
		return empty, recoveryRefuse("private_protocol_error")
	}
	envelope, err := CanonicalRootGrantsEnvelope(sealed.envelope, record)
	if err != nil {
		return empty, recoveryRefuse("private_protocol_error")
	}
	if err := s.check(); err != nil {
		return empty, err
	}
	return RootGrantsPrivateSealed{Record: bytes.Clone(sealed.metadata), Envelope: bytes.Clone(envelope)}, nil
}

// Close cancels BEFORE clearing/waiting, so an active tty read can terminate.
// It is idempotent; copies cannot revive a closed private engine or deadline.
func (s *RootGrantsPrivateSession) Close() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
	if s != nil && s.engine != nil {
		s.engine.close()
	}
}

// Fixed Go refusals only. Numeric ROOT status mapping (including input_canceled
// 20 versus canceled14/timeout15), C panic boundaries and frames are native-side
// obligations. Unknown errors never propagate caller/OS/parser diagnostics.
func rootGrantsPrivateError(err error) error {
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal != nil {
		switch refusal.Code {
		case "recovery_invalid_arguments", "recovery_terminal_required", "recovery_invalid_word_number", "recovery_invalid_word_count",
			"recovery_invalid_mnemonic", "recovery_invalid_checksum", "recovery_invalid_derivation", "recovery_retained_record_mismatch",
			"recovery_public_pin_mismatch", "recovery_operation_unavailable", "recovery_wrapping_policy_refused", "recovery_invalid_envelope",
			"recovery_binding_mismatch", "recovery_canceled", "recovery_timeout", "recovery_private_protocol_error", "recovery_limit_exceeded",
			"recovery_unsupported_version", "recovery_unsupported_operation", "recovery_input_canceled":
			return recoveryRefuse(refusal.Code[len("recovery_"):])
		}
	}
	return recoveryRefuse("private_protocol_error")
}
