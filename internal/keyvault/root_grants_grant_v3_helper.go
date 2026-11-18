package keyvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

type rootGrantsGrantV3HelperReview struct {
	Operation         string          `json:"operation"`
	Profile           string          `json:"profile"`
	ObservationPolicy string          `json:"observation_policy"`
	Grant             json.RawMessage `json:"grant"`
	ContractBase64    string          `json:"contract_bytes_base64"`
	Authority         json.RawMessage `json:"authority"`
	Record            json.RawMessage `json:"record"`
	GrantBytes        int             `json:"grant_bytes"`
	ContractBytes     int             `json:"contract_bytes"`
	GrantSHA256       string          `json:"grant_sha256"`
	ContractSHA256    string          `json:"contract_sha256"`
	AuthoritySHA256   string          `json:"authority_sha256"`
	RecordSHA256      string          `json:"record_sha256"`
	MessageSHA256     string          `json:"message_sha256"`
}

// rootGrantsPrivateSigningPurpose supplies only operation-specific validation,
// signature verification, and status mapping. The C1 framing, deadline,
// ordered rechecks, ACK/EOF barrier, child close, and same-child wait stay here.
type rootGrantsPrivateSigningPurpose struct {
	validateRequest    func([]byte) error
	verifySignature    func([]byte, []byte) error
	check              func(context.Context, []byte) error
	controlResponse    func(error) []byte
	refusalFailure     func(uint32) error
	refusalCode        func(error) string
	uncertainRefusal   func(uint32) string
	contextCode        func(error) string
	verificationCode   func(error) string
	failure            func(string, string, bool) error
	requireOutputClose bool
}

type rootGrantsCloseOnceWriter struct {
	io.WriteCloser
	once sync.Once
	err  error
}

func (w *rootGrantsCloseOnceWriter) Close() error {
	w.once.Do(func() { w.err = w.WriteCloser.Close() })
	return w.err
}

type rootGrantsCloseOnceReader struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (r *rootGrantsCloseOnceReader) Close() error {
	r.once.Do(func() { r.err = r.ReadCloser.Close() })
	return r.err
}

func rootGrantsPrivateSigningChildComplete(child *rootGrantsHelperChild) bool {
	return child != nil && child.input != nil && child.output != nil &&
		child.term != nil && child.kill != nil && child.wait != nil
}

// A malformed host result still needs bounded best-effort cleanup. This path
// never manufactures a successful wait or allows a receipt.
func rootGrantsPrivateSigningStopIncompleteChild(child *rootGrantsHelperChild) {
	if child == nil {
		return
	}
	if child.input != nil {
		_ = child.input.Close()
	}
	if child.output != nil {
		_ = child.output.Close()
	}
	if child.term != nil {
		_ = child.term()
	}
	if child.wait == nil {
		if child.kill != nil {
			_ = child.kill()
		}
		return
	}
	waited := rootGrantsWaitChild(child)
	if rootGrantsPrivateSigningWaitBounded(waited) {
		return
	}
	if child.kill != nil {
		_ = child.kill()
		_ = rootGrantsPrivateSigningWaitBounded(waited)
	}
}

func rootGrantsPrivateSigningWaitBounded(waited <-chan error) bool {
	timer := time.NewTimer(rootGrantsHelperGrace)
	defer timer.Stop()
	select {
	case <-waited:
		return true
	case <-timer.C:
		return false
	}
}

// rootGrantsPrivateSigningExchange is the single C1 parent transport for the
// purpose-specific Grant v3 and trust-contract countersign operations.
func rootGrantsPrivateSigningExchange(parent context.Context, raw, pin []byte, host rootGrantsHelperHost,
	purpose rootGrantsPrivateSigningPurpose) ([]byte, int, error) {
	fail := func(code, phase string, attempted bool) error {
		if purpose.failure == nil {
			return recoveryRefuse("private_protocol_error")
		}
		return purpose.failure(code, phase, attempted)
	}
	if parent == nil || host == nil || purpose.verifySignature == nil ||
		purpose.check == nil || purpose.controlResponse == nil ||
		purpose.refusalFailure == nil || purpose.refusalCode == nil || purpose.contextCode == nil ||
		purpose.uncertainRefusal == nil || purpose.verificationCode == nil || purpose.failure == nil {
		return nil, 0, fail("invalid_arguments", "preflight", false)
	}
	if len(pin) != 20 && len(pin) != 32 {
		return nil, 0, fail("code_not_admitted", "preflight", false)
	}
	ctx, cancel := context.WithTimeout(parent, rootGrantsGrantV3AttemptLimit)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, 0, fail(purpose.contextCode(err), "preflight", false)
	}
	if purpose.validateRequest != nil {
		validationInput := bytes.Clone(raw)
		validationErr := purpose.validateRequest(validationInput)
		clear(validationInput)
		if err := ctx.Err(); err != nil {
			return nil, 0, fail(purpose.contextCode(err), "preflight", false)
		}
		if validationErr != nil {
			return nil, 0, validationErr
		}
	}
	verifyErr := host.verify(0, nil)
	if err := ctx.Err(); err != nil {
		return nil, 0, fail(purpose.contextCode(err), "preflight", false)
	}
	if verifyErr != nil {
		return nil, 0, fail("code_not_admitted", "preflight", false)
	}
	child, err := host.start()
	if err != nil || child == nil {
		if child != nil {
			if rootGrantsPrivateSigningChildComplete(child) {
				rootGrantsStopChild(child, nil)
			} else {
				rootGrantsPrivateSigningStopIncompleteChild(child)
			}
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, 0, fail(purpose.contextCode(contextErr), "preflight", false)
		}
		return nil, 0, fail("operation_unavailable", "preflight", false)
	}
	if !rootGrantsPrivateSigningChildComplete(child) {
		rootGrantsPrivateSigningStopIncompleteChild(child)
		return nil, 0, fail("private_protocol_error", "preflight", true)
	}
	child.input = &rootGrantsCloseOnceWriter{WriteCloser: child.input}
	child.output = &rootGrantsCloseOnceReader{ReadCloser: child.output}
	if child.pid <= 0 {
		rootGrantsStopChild(child, nil)
		return nil, 0, fail("code_not_admitted", "preflight", false)
	}
	verifyErr = host.verify(child.pid, pin)
	if err := ctx.Err(); err != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, fail(purpose.contextCode(err), "preflight", false)
	}
	if verifyErr != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, fail("code_not_admitted", "preflight", false)
	}
	owned := bytes.Clone(raw)
	frames := make(chan rootGrantsHelperFrame, 1)
	go func() {
		defer clear(owned)
		if err := rootGrantsWriteFrame(child.input, owned); err != nil {
			frames <- rootGrantsHelperFrame{err: fail("private_protocol_error", "sign", true)}
			return
		}
		rechecks := byte(0)
		var recheckFailure error
		var expectedRefusal uint32
		var frame rootGrantsHelperFrame
		for {
			var stage byte
			var remaining time.Duration
			frame, stage, remaining = rootGrantsReadGrantV3ExchangeFrame(child.output)
			if frame.err != nil {
				frame.err = fail("private_protocol_error", "sign", true)
				break
			}
			if frame.status != 2 {
				if expectedRefusal != 0 && (frame.status != 1 || len(frame.payload) != 4 || binary.BigEndian.Uint32(frame.payload) != expectedRefusal) {
					clear(frame.payload)
					frame.payload = nil
					frame.err = fail("private_protocol_error", "recheck", true)
				}
				break
			}
			clear(frame.payload)
			if expectedRefusal != 0 || stage != rechecks+1 || rechecks >= rootGrantsGrantV3RecheckLimit {
				frame = rootGrantsHelperFrame{err: fail("private_protocol_error", "recheck", false)}
				break
			}
			rechecks++
			if err := ctx.Err(); err != nil {
				frame = rootGrantsHelperFrame{err: fail(purpose.contextCode(err), "recheck", false)}
				break
			}
			readCtx, readCancel := context.WithTimeout(ctx, remaining)
			checkInput := bytes.Clone(owned)
			checkErr := purpose.check(readCtx, checkInput)
			clear(checkInput)
			if checkErr == nil {
				if err := readCtx.Err(); err != nil {
					checkErr = fail(purpose.contextCode(err), "recheck", false)
				}
			}
			if checkErr == nil {
				if err := ctx.Err(); err != nil {
					checkErr = fail(purpose.contextCode(err), "recheck", false)
				}
			}
			readCancel()
			if checkErr != nil {
				recheckFailure = checkErr
			}
			control := purpose.controlResponse(checkErr)
			if !rootGrantsValidPrivateSigningControl(control) {
				frame = rootGrantsHelperFrame{err: fail("private_protocol_error", "recheck", false)}
				break
			}
			if control[0] == 1 {
				expectedRefusal = binary.BigEndian.Uint32(control[5:9])
			}
			if err := rootGrantsWriteRaw(child.input, control); err != nil {
				frame = rootGrantsHelperFrame{err: fail("private_protocol_error", "recheck", false)}
				break
			}
		}
		if frame.err == nil && frame.status == 0 {
			if recheckFailure != nil {
				frame.err = fail(purpose.refusalCode(recheckFailure), "recheck", true)
			} else if rechecks != rootGrantsGrantV3RecheckLimit {
				frame.err = fail("private_protocol_error", "recheck", true)
			} else if len(frame.payload) != 64 {
				frame.err = fail("private_protocol_error", "verify", true)
			} else if verifyErr := func() error {
				requestCopy := bytes.Clone(owned)
				signatureCopy := bytes.Clone(frame.payload)
				defer clear(requestCopy)
				defer clear(signatureCopy)
				return purpose.verifySignature(requestCopy, signatureCopy)
			}(); verifyErr != nil {
				frame.err = fail(purpose.verificationCode(verifyErr), "verify", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = fail(purpose.contextCode(err), "sign", true)
			} else if host.verify(child.pid, pin) != nil {
				frame.err = fail("code_not_admitted", "verify", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = fail(purpose.contextCode(err), "verify", true)
			} else {
				ack := rootGrantsCompletionACK(owned, frame.payload)
				n, writeErr := child.input.Write(ack[:])
				if writeErr != nil || n != len(ack) {
					frame.err = fail("private_protocol_error", "receipt", true)
				}
			}
		}
		if frame.err == nil {
			if err := child.input.Close(); err != nil {
				frame.err = fail("private_protocol_error", "receipt", true)
			} else if err := ctx.Err(); err != nil {
				frame.err = fail(purpose.contextCode(err), "receipt", true)
			} else {
				var trailing [1]byte
				n, readErr := child.output.Read(trailing[:])
				if n != 0 || readErr != io.EOF {
					frame.err = fail("private_protocol_error", "receipt", true)
				}
			}
		} else {
			_ = child.input.Close()
		}
		if frame.err != nil {
			clear(frame.payload)
			frame.payload = nil
		}
		frames <- frame
	}()
	var frame rootGrantsHelperFrame
	select {
	case frame = <-frames:
	case <-ctx.Done():
		rootGrantsStopChild(child, nil)
		go func() { f := <-frames; clear(f.payload) }()
		return nil, 0, fail(purpose.contextCode(ctx.Err()), "sign", true)
	}
	if err := ctx.Err(); err != nil {
		clear(frame.payload)
		rootGrantsStopChild(child, nil)
		return nil, 0, fail(purpose.contextCode(err), "receipt", true)
	}
	if frame.err != nil {
		rootGrantsStopChild(child, nil)
		return nil, 0, frame.err
	}
	waited := rootGrantsWaitChild(child)
	select {
	case exitErr := <-waited:
		if err := child.output.Close(); err != nil && purpose.requireOutputClose {
			clear(frame.payload)
			return nil, 0, fail("private_protocol_error", "receipt", true)
		}
		if err := ctx.Err(); err != nil {
			clear(frame.payload)
			return nil, 0, fail(purpose.contextCode(err), "receipt", true)
		}
		if exitErr != nil {
			clear(frame.payload)
			return nil, 0, fail("private_protocol_error", "receipt", true)
		}
		if frame.status == 1 {
			code := binary.BigEndian.Uint32(frame.payload)
			clear(frame.payload)
			if code == 14 || code == 15 || code == 16 {
				return nil, 0, fail(purpose.uncertainRefusal(code), "sign", true)
			}
			return nil, 0, purpose.refusalFailure(code)
		}
		return frame.payload, child.pid, nil
	case <-ctx.Done():
		clear(frame.payload)
		rootGrantsStopChild(child, waited)
		return nil, 0, fail(purpose.contextCode(ctx.Err()), "receipt", true)
	}
}

func rootGrantsWriteRaw(w io.Writer, raw []byte) error {
	n, err := w.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

func rootGrantsValidPrivateSigningControl(raw []byte) bool {
	if len(raw) == 5 {
		return raw[0] == 0 && binary.BigEndian.Uint32(raw[1:5]) == 0
	}
	if len(raw) != 9 || raw[0] != 1 || binary.BigEndian.Uint32(raw[1:5]) != 4 {
		return false
	}
	code := binary.BigEndian.Uint32(raw[5:9])
	return code >= 1 && code <= 24
}

func RootGrantsGrantV3HelperStatus(err error) int32 {
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil {
		return 16
	}
	switch failure.Code {
	case "invalid_arguments":
		return 1
	case "retained_record_mismatch":
		return 8
	case "public_pin_mismatch":
		return 9
	case "operation_unavailable", "review_refused":
		return 10
	case "code_not_admitted":
		return 21
	case "acl_refused":
		return 22
	case "lock_unavailable":
		return 23
	case "inventory_changed":
		return 24
	case "invalid_envelope":
		return 12
	case "binding_mismatch", "authority_mismatch", "contract_mismatch", "consent_invalid", "review_changed":
		return 13
	case "canceled", "presence_canceled":
		return 14
	case "timeout":
		return 15
	case "limit_exceeded":
		return 17
	case "unsupported_version":
		return 18
	case "unsupported_operation":
		return 19
	default:
		return 16
	}
}

func rootGrantsGrantV3PlanFromHelperRequest(rawRequest []byte) (*RootGrantsGrantV3Plan, error) {
	var wire rootGrantsGrantV3HelperRequest
	if len(rawRequest) == 0 || len(rawRequest) > 262144 || DecodeSingleJSON(rawRequest, &wire) != nil ||
		wire.Schema != "keyvault-root-grants-sign-request/2" || wire.Operation != rootGrantsGrantV3Operation ||
		len(wire.Review) == 0 || len(wire.Envelope) == 0 || wire.PairMetadata == "" {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "preflight", false)
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, rawRequest) {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "preflight", false)
	}
	var review rootGrantsGrantV3HelperReview
	if DecodeSingleJSON(wire.Review, &review) != nil || review.Operation != rootGrantsGrantV3Operation ||
		review.Profile != rootGrantsProfile || review.ObservationPolicy != RootGrantsOfflineReview {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "review", false)
	}
	var authority RootGrantsAuthority
	if DecodeSingleJSON(review.Authority, &authority) != nil {
		return nil, rootGrantsGrantV3Failed("authority_mismatch", "review", false)
	}
	contract, err := rootGrantsContractBytes(review.ContractBase64)
	if err != nil {
		return nil, rootGrantsGrantV3Failed("contract_mismatch", "review", false)
	}
	defer clear(contract)
	plan, err := PrepareRootGrantsGrantV3(review.Grant, contract, review.Authority, review.Record,
		authority.OwnerPrincipal, time.Now())
	if err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "review", false)
	}
	expectedReview, err := plan.ReviewJSON()
	if err != nil || !bytes.Equal(expectedReview, wire.Review) {
		clear(expectedReview)
		return nil, rootGrantsGrantV3Failed("review_changed", "review", false)
	}
	clear(expectedReview)
	policy, err := ParseRootGrantsAuthority(review.Authority)
	if err != nil {
		return nil, rootGrantsGrantV3Failed("authority_mismatch", "review", false)
	}
	pairMetadata, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || hex.EncodeToString(pairMetadata) != wire.PairMetadata {
		clear(pairMetadata)
		return nil, rootGrantsGrantV3Failed("retained_record_mismatch", "review", false)
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: bytes.Clone(review.Record), Envelope: bytes.Clone(wire.Envelope), PairMetadata: pairMetadata}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	if _, err := rootGrantsValidateSigningSnapshot(snapshot, policy); err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "read", false)
	}
	return plan, nil
}

// rootGrantsGrantV3RequireInstalledAuthority compares the complete request
// policy with a fresh policy loaded from the fixed OS-account/address path.
// The loader is injectable only inside this package for isolated tests; the
// helper entry below always supplies LoadRootGrantsAuthority.
func rootGrantsGrantV3RequireInstalledAuthority(plan *RootGrantsGrantV3Plan,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if plan == nil || loadAuthority == nil {
		return rootGrantsGrantV3Failed("operation_unavailable", "authority", false)
	}
	record, err := ParseRootGrantsRecord(plan.record)
	if err != nil {
		return rootGrantsGrantV3Failed("public_pin_mismatch", "authority", false)
	}
	policy, err := ParseRootGrantsAuthority(plan.authority)
	if err != nil || policy.Record.Service != record.Service || policy.Record.Version != record.Version {
		return rootGrantsGrantV3Failed("authority_mismatch", "authority", false)
	}
	address := RootGrantsAddress{Service: record.Service, Version: record.Version}
	installed, err := loadAuthority(address)
	defer clear(installed)
	if err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "authority", false)
	}
	if _, err := ParseRootGrantsAuthority(installed); err != nil || !bytes.Equal(installed, plan.authority) {
		return rootGrantsGrantV3Failed("review_changed", "authority", false)
	}
	return nil
}

// rootGrantsGrantV3CheckInstalledAuthorityFromHelper is the pre-unwrap helper
// gate. Production supplies the fixed OS-account-selected loader; tests inject
// only a public synthetic policy source and never touch an installed file.
func rootGrantsGrantV3CheckInstalledAuthorityFromHelper(ctx context.Context, rawRequest []byte,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if ctx == nil {
		return rootGrantsGrantV3Failed("invalid_arguments", "authority", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "authority", false)
	}
	plan, err := rootGrantsGrantV3PlanFromHelperRequest(rawRequest)
	if err != nil {
		return err
	}
	if err := rootGrantsGrantV3RequireInstalledAuthority(plan, loadAuthority); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "authority", false)
	}
	return nil
}

// RootGrantsGrantV3CheckInstalledAuthorityFromHelper is called by the native
// helper immediately before unwrap. It has no request-selected policy path.
func RootGrantsGrantV3CheckInstalledAuthorityFromHelper(ctx context.Context, rawRequest []byte) error {
	return rootGrantsGrantV3CheckInstalledAuthorityFromHelper(ctx, rawRequest, LoadRootGrantsAuthority)
}

// rootGrantsGrantV3CheckForHelperWithContext runs in the admitted parent vault
// process. The private helper requests a fixed checkpoint; it never opens the
// Keychain or selects a vault guard itself.
func rootGrantsGrantV3CheckForHelperWithContext(ctx context.Context, rawRequest []byte, vault RootGrantsGrantV3SigningVault,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if ctx == nil {
		return rootGrantsGrantV3Failed("invalid_arguments", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "recheck", false)
	}
	if _, err := rootGrantsGrantV3PlanFromHelperRequest(rawRequest); err != nil {
		return err
	}
	var wire rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(rawRequest, &wire) != nil {
		return rootGrantsGrantV3Failed("private_protocol_error", "recheck", false)
	}
	var review rootGrantsGrantV3HelperReview
	if DecodeSingleJSON(wire.Review, &review) != nil {
		return rootGrantsGrantV3Failed("private_protocol_error", "recheck", false)
	}
	policy, err := ParseRootGrantsAuthority(review.Authority)
	if err != nil || vault == nil || loadAuthority == nil {
		return rootGrantsGrantV3Failed("operation_unavailable", "recheck", false)
	}
	address := RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}
	currentAuthority, err := loadAuthority(address)
	if contextErr := ctx.Err(); contextErr != nil {
		clear(currentAuthority)
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(contextErr), "recheck", false)
	}
	if err != nil || !bytes.Equal(currentAuthority, review.Authority) {
		clear(currentAuthority)
		return rootGrantsGrantV3Failed("review_changed", "recheck", false)
	}
	clear(currentAuthority)
	pairMetadata, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || hex.EncodeToString(pairMetadata) != wire.PairMetadata {
		clear(pairMetadata)
		return rootGrantsGrantV3Failed("retained_record_mismatch", "recheck", false)
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: bytes.Clone(review.Record), Envelope: bytes.Clone(wire.Envelope), PairMetadata: pairMetadata}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	if _, err := rootGrantsValidateSigningSnapshot(snapshot, policy); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "recheck", false)
	}
	current, _, err := rootGrantsSnapshotForSigning(ctx, vault, address, policy)
	if err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "recheck", false)
	}
	defer clear(current.Metadata)
	defer clear(current.Envelope)
	defer clear(current.PairMetadata)
	if !rootGrantsSigningSnapshotsEqual(snapshot, current) {
		return rootGrantsGrantV3Failed("review_changed", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "recheck", false)
	}
	return nil
}

// RootGrantsGrantV3SignFromHelper is the linked helper's context-bound signing
// entry. Vault reads are completed by the admitted parent over its private
// control channel before this call; this process receives no vault capability.
func RootGrantsGrantV3SignFromHelper(ctx context.Context, rawRequest, ownedPlaintext []byte) ([]byte, error) {
	return rootGrantsGrantV3SignFromHelperWithAuthorityLoader(ctx, rawRequest, ownedPlaintext,
		LoadRootGrantsAuthority, rand.Reader, nil, nil)
}

// Package-private dependencies support deterministic public-policy and
// final-validation scheduling controls. The production C entry passes the
// fixed loader, cryptographic randomness, and nil hooks.
func rootGrantsGrantV3SignFromHelperWithAuthorityLoader(ctx context.Context, rawRequest, ownedPlaintext []byte,
	loadAuthority func(RootGrantsAddress) ([]byte, error), random io.Reader,
	afterFinalRevalidation, beforePrivateMath func()) ([]byte, error) {
	defer clear(ownedPlaintext)
	if ctx == nil {
		return nil, rootGrantsGrantV3Failed("invalid_arguments", "sign", false)
	}
	plan, err := rootGrantsGrantV3PlanFromHelperRequest(rawRequest)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "sign", false)
	}
	attempt, err := newRootGrantsGrantV3Attempt(ctx, plan)
	if err != nil {
		return nil, err
	}
	attempt.loadAuthority = loadAuthority
	return attempt.signWithTestHooks(ownedPlaintext, random, afterFinalRevalidation, beforePrivateMath)
}

func rootGrantsContractBytes(encoded string) ([]byte, error) {
	contract, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || encoded == "" || base64.StdEncoding.EncodeToString(contract) != encoded || len(contract) == 0 || len(contract) > 65536 {
		clear(contract)
		return nil, recoveryRefuse("contract_mismatch")
	}
	return contract, nil
}
