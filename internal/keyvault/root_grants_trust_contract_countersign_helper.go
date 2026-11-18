package keyvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var errRootGrantsTrustCountersignInvalidBase64 = errors.New("invalid base64")

// rootGrantsTrustContractCountersignReviewWire is the helper-boundary shape,
// not a second trust model. A's review builder remains the sole constructor.
type rootGrantsTrustContractCountersignReviewWire struct {
	Operation           string          `json:"operation"`
	Profile             string          `json:"profile"`
	ContractProfile     string          `json:"contract_profile"`
	ContractBase64      string          `json:"contract_bytes_base64"`
	ContractBytes       int             `json:"contract_bytes"`
	ContractSHA256      string          `json:"contract_sha256"`
	ScopeTextBase64     string          `json:"scope_text_bytes_base64"`
	ScopeTextBytes      int             `json:"scope_text_bytes"`
	ScopeTextSHA256     string          `json:"scope_text_sha256"`
	IssuanceContextJSON json.RawMessage `json:"issuance_context"`
	AuthorityJSON       json.RawMessage `json:"authority"`
	RecordJSON          json.RawMessage `json:"record"`
	AuthoritySHA256     string          `json:"authority_sha256"`
	RecordSHA256        string          `json:"record_sha256"`
}

type rootGrantsTrustContractCountersignHelperRequestData struct {
	Review             rootGrantsTrustContractCountersignReviewWire
	Issuance           RootGrantsTrustContractCountersignIssuanceContext
	Contract           []byte
	ScopeText          []byte
	ScopeTextAvailable bool
	Envelope           []byte
	PairMetadata       []byte
}

func (d *rootGrantsTrustContractCountersignHelperRequestData) clear() {
	if d == nil {
		return
	}
	clear(d.Contract)
	clear(d.ScopeText)
	clear(d.Envelope)
	clear(d.PairMetadata)
	clear(d.Review.IssuanceContextJSON)
	clear(d.Review.AuthorityJSON)
	clear(d.Review.RecordJSON)
	d.Review.ContractBase64 = ""
	d.Review.ScopeTextBase64 = ""
	*d = rootGrantsTrustContractCountersignHelperRequestData{}
}

func (d rootGrantsTrustContractCountersignHelperRequestData) clone() rootGrantsTrustContractCountersignHelperRequestData {
	d.Contract = bytes.Clone(d.Contract)
	d.ScopeText = rootGrantsTrustContractCountersignCloneBytes(d.ScopeText)
	d.Envelope = bytes.Clone(d.Envelope)
	d.PairMetadata = bytes.Clone(d.PairMetadata)
	d.Review.IssuanceContextJSON = bytes.Clone(d.Review.IssuanceContextJSON)
	d.Review.AuthorityJSON = bytes.Clone(d.Review.AuthorityJSON)
	d.Review.RecordJSON = bytes.Clone(d.Review.RecordJSON)
	d.Issuance.Actions = slices.Clone(d.Issuance.Actions)
	d.Issuance.Repos = slices.Clone(d.Issuance.Repos)
	d.Issuance.DerivedV3Scope = slices.Clone(d.Issuance.DerivedV3Scope)
	return d
}

func rootGrantsTrustContractCountersignParseHelperRequest(raw []byte) (rootGrantsTrustContractCountersignHelperRequestData, error) {
	var empty rootGrantsTrustContractCountersignHelperRequestData
	fail := func(code, phase string) (rootGrantsTrustContractCountersignHelperRequestData, error) {
		return empty, rootGrantsTrustContractCountersignFailed(code, phase, false)
	}
	if len(raw) == 0 {
		return fail("invalid_arguments", "preflight")
	}
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{payload: len(raw)}) {
		return fail("limit_exceeded", "preflight")
	}
	var wire rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &wire) != nil {
		return fail("private_protocol_error", "preflight")
	}
	defer clear(wire.Review)
	defer clear(wire.Envelope)
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return fail("private_protocol_error", "preflight")
	}
	clear(canonical)
	if wire.Schema != rootGrantsTrustContractCountersignHelperSchema {
		return fail("unsupported_version", "preflight")
	}
	if wire.Operation != rootGrantsTrustContractCountersignOperation {
		return fail("unsupported_operation", "preflight")
	}
	if len(wire.Review) == 0 || !rootGrantsTrustCanonicalPublicObject(wire.Envelope) {
		return fail("private_protocol_error", "preflight")
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(wire.Review, &review) != nil {
		return fail("private_protocol_error", "review")
	}
	defer clear(review.IssuanceContextJSON)
	defer clear(review.AuthorityJSON)
	defer clear(review.RecordJSON)
	canonicalCarrier, err := json.Marshal(review)
	if err != nil || !bytes.Equal(canonicalCarrier, wire.Review) {
		clear(canonicalCarrier)
		return fail("private_protocol_error", "review")
	}
	clear(canonicalCarrier)
	if review.Operation != rootGrantsTrustContractCountersignOperation {
		return fail("unsupported_operation", "review")
	}
	if review.Profile != rootGrantsTrustContractCountersignProfile || review.ContractProfile != rootGrantsTrustContractProfile {
		return fail("unsupported_version", "review")
	}
	if !rootGrantsTrustCanonicalPublicObject(review.AuthorityJSON) {
		return fail("private_protocol_error", "review")
	}

	if !rootGrantsTrustCanonicalPublicObject(review.IssuanceContextJSON) ||
		!rootGrantsTrustCanonicalPublicObject(review.RecordJSON) {
		return fail("private_protocol_error", "review")
	}
	var authorityShape rootGrantsTrustAuthorityV2
	if DecodeSingleJSON(review.AuthorityJSON, &authorityShape) != nil {
		return fail("private_protocol_error", "review")
	}
	canonicalAuthority, err := json.Marshal(authorityShape)
	if err != nil || !bytes.Equal(canonicalAuthority, review.AuthorityJSON) {
		clear(canonicalAuthority)
		return fail("private_protocol_error", "review")
	}
	clear(canonicalAuthority)
	var issuance RootGrantsTrustContractCountersignIssuanceContext
	if DecodeSingleJSON(review.IssuanceContextJSON, &issuance) != nil {
		return fail("private_protocol_error", "review")
	}
	if issuance.Actions == nil || issuance.Repos == nil || issuance.DerivedV3Scope == nil {
		return fail("private_protocol_error", "review")
	}
	// Canonical shape is a carrier check. Do not run issuance semantics until
	// after the inner LIP contract and scope binding have had their C2 turn.
	canonicalIssuance, err := json.Marshal(issuance)
	if err != nil {
		return fail("private_protocol_error", "review")
	}
	if !bytes.Equal(canonicalIssuance, review.IssuanceContextJSON) {
		clear(canonicalIssuance)
		return fail("private_protocol_error", "review")
	}
	clear(canonicalIssuance)

	var record RootGrantsRecord
	if DecodeSingleJSON(review.RecordJSON, &record) != nil {
		return fail("private_protocol_error", "review")
	}
	canonicalRecord, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonicalRecord, review.RecordJSON) {
		clear(canonicalRecord)
		return fail("private_protocol_error", "review")
	}
	clear(canonicalRecord)
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{
		issuance: len(review.IssuanceContextJSON), authority: len(review.AuthorityJSON), record: len(review.RecordJSON),
		review: len(wire.Review), payload: len(raw),
	}) {
		return fail("limit_exceeded", "preflight")
	}
	if review.ContractBytes < 0 || review.ScopeTextBytes < 0 {
		return fail("private_protocol_error", "review")
	}
	if !lowerHex(review.ContractSHA256, 32) || !lowerHex(review.AuthoritySHA256, 32) || !lowerHex(review.RecordSHA256, 32) {
		return fail("private_protocol_error", "review")
	}
	contract, err := rootGrantsTrustContractCountersignDecodeBase64(review.ContractBase64)
	if err != nil {
		return fail("private_protocol_error", "review")
	}
	scopeText, err := rootGrantsTrustContractCountersignDecodeBase64(review.ScopeTextBase64)
	if err != nil {
		clear(contract)
		return fail("private_protocol_error", "review")
	}
	if len(contract) != review.ContractBytes || len(scopeText) != review.ScopeTextBytes {
		clear(contract)
		clear(scopeText)
		return fail("binding_mismatch", "review")
	}
	available := review.ScopeTextSHA256 != ""
	binding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: contract, ScopeTextBytes: scopeText, ScopeTextAvailable: available,
	})
	if err != nil {
		clear(contract)
		clear(scopeText)
		var trustFailure *RootGrantsTrustError
		if errors.As(err, &trustFailure) && trustFailure != nil {
			return empty, rootGrantsTrustContractCountersignFailed(trustFailure.Code, "contract_parse", false)
		}
		return empty, rootGrantsTrustContractCountersignFailed("private_protocol_error", "contract_parse", false)
	}
	defer clear(binding.ContractBytes)
	defer clear(binding.ScopeTextBytes)
	validatedIssuance, err := rootGrantsTrustContractCountersignIssuanceContextJSON(issuance)
	if err != nil {
		clear(contract)
		clear(scopeText)
		return empty, err
	}
	if !bytes.Equal(validatedIssuance, review.IssuanceContextJSON) {
		clear(validatedIssuance)
		clear(contract)
		clear(scopeText)
		return fail("private_protocol_error", "review")
	}
	clear(validatedIssuance)
	if review.ContractSHA256 != binding.ContractSHA256 ||
		review.AuthoritySHA256 != rootGrantsHashHex(review.AuthorityJSON) ||
		review.RecordSHA256 != rootGrantsHashHex(review.RecordJSON) {
		clear(contract)
		clear(scopeText)
		return fail("binding_mismatch", "review")
	}
	boundContract := binding.Contract
	if issuance.LandlordName != boundContract.LandlordName || issuance.Network != boundContract.Network ||
		issuance.AgentName != boundContract.AgentName || issuance.GranteeKey != boundContract.GranteeKey ||
		!rootGrantsTrustContractCountersignWindowWithinAuthority(boundContract, issuance.NotBefore, issuance.NotAfter, issuance.MaxGrantSeconds) ||
		!slices.Equal(issuance.Actions, boundContract.Actions) || !slices.Equal(issuance.Repos, boundContract.Repos) ||
		issuance.SpendBudget != boundContract.SpendBudget {
		clear(contract)
		clear(scopeText)
		return fail("binding_mismatch", "review")
	}
	canonicalReview, err := CanonicalRootGrantsTrustReview(RootGrantsTrustReviewInput{
		Binding: binding, IssuanceContextJSON: review.IssuanceContextJSON,
		AuthorityJSON: review.AuthorityJSON, RecordJSON: review.RecordJSON,
	})
	if err != nil || !bytes.Equal(canonicalReview, wire.Review) {
		clear(canonicalReview)
		clear(contract)
		clear(scopeText)
		return fail("private_protocol_error", "review")
	}
	clear(canonicalReview)
	if _, err := (RootGrantsAddress{Service: issuance.RootRecord.Service, Version: issuance.RootRecord.Version}).Account(); err != nil {
		clear(contract)
		clear(scopeText)
		return fail("public_pin_mismatch", "review")
	}
	pairMetadata, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || hex.EncodeToString(pairMetadata) != wire.PairMetadata || len(pairMetadata) == 0 {
		clear(contract)
		clear(scopeText)
		clear(pairMetadata)
		return fail("retained_record_mismatch", "review")
	}
	envelope := bytes.Clone(wire.Envelope)
	review.IssuanceContextJSON = bytes.Clone(review.IssuanceContextJSON)
	review.AuthorityJSON = bytes.Clone(review.AuthorityJSON)
	review.RecordJSON = bytes.Clone(review.RecordJSON)
	// The decoded byte copies are owned above; do not retain their redundant
	// Base64 string views for either recheck callback.
	review.ContractBase64 = ""
	review.ScopeTextBase64 = ""
	return rootGrantsTrustContractCountersignHelperRequestData{
		Review: review, Issuance: issuance, Contract: contract, ScopeText: scopeText,
		ScopeTextAvailable: binding.ScopeTextState == RootGrantsTrustScopeTextPresent,
		Envelope:           envelope, PairMetadata: pairMetadata,
	}, nil
}

// RootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper is the
// pre-unwrap gate used by the native helper. It validates the purpose-specific
// request before reading the fixed installed authority source.
func RootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(ctx context.Context, rawRequest []byte) error {
	return rootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(ctx, rawRequest, LoadRootGrantsAuthority)
}

func rootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(ctx context.Context, rawRequest []byte,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if ctx == nil || loadAuthority == nil {
		return rootGrantsTrustContractCountersignFailed("invalid_arguments", "authority", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "authority", false)
	}
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(rawRequest)
	if err != nil {
		return err
	}
	defer data.clear()
	authority, binding, err := rootGrantsTrustContractCountersignBindHelperAuthority(&data)
	if err != nil {
		return err
	}
	defer clear(authority.approvedContractBytes)
	defer clear(binding.ContractBytes)
	defer clear(binding.ScopeTextBytes)
	return rootGrantsTrustContractCountersignCheckInstalledAuthorityData(ctx, data, loadAuthority)
}

// RootGrantsTrustContractCountersignSignFromHelper consumes only the native
// helper's owned, record-bound plaintext and signs SHA-256 of the exact raw
// trust-contract bytes after rechecking the fixed installed authority.
func RootGrantsTrustContractCountersignSignFromHelper(ctx context.Context, rawRequest, ownedPlaintext []byte) ([]byte, error) {
	return rootGrantsTrustContractCountersignSignFromHelperWithDependencies(ctx, rawRequest, ownedPlaintext,
		LoadRootGrantsAuthority, rand.Reader)
}

func rootGrantsTrustContractCountersignSignFromHelperWithDependencies(ctx context.Context, rawRequest, ownedPlaintext []byte,
	loadAuthority func(RootGrantsAddress) ([]byte, error), random io.Reader) ([]byte, error) {
	return rootGrantsTrustContractCountersignSignFromHelperWithRuntime(ctx, rawRequest, ownedPlaintext,
		loadAuthority, random, func() int64 { return time.Now().Unix() }, signNostrWithAux)
}

// Runtime dependencies are internal; callers cannot supply time or signing authority on the wire.
func rootGrantsTrustContractCountersignSignFromHelperWithRuntime(ctx context.Context, rawRequest, ownedPlaintext []byte,
	loadAuthority func(RootGrantsAddress) ([]byte, error), random io.Reader, now func() int64,
	sign func([]byte, []byte, [32]byte) ([]byte, error)) ([]byte, error) {
	defer clear(ownedPlaintext)
	if ctx == nil || loadAuthority == nil || now == nil || sign == nil {
		return nil, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	if err := ctx.Err(); err != nil {
		return nil, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "preflight", false)
	}
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(rawRequest)
	if err != nil {
		return nil, err
	}
	defer data.clear()
	authority, binding, err := rootGrantsTrustContractCountersignBindHelperAuthority(&data)
	if err != nil {
		return nil, err
	}
	defer clear(authority.approvedContractBytes)
	defer clear(binding.ContractBytes)
	defer clear(binding.ScopeTextBytes)

	if !rootGrantsTrustContractCountersignPlaintextBindsRecord(ownedPlaintext, data.Review.RecordJSON) {
		return nil, rootGrantsTrustContractCountersignFailed("binding_mismatch", "unwrap", false)
	}
	private, err := nostrPrivate(ownedPlaintext[36:])
	if err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "unwrap", false)
	}
	public := schnorr.SerializePubKey(private.PubKey())
	private.Zero()
	expectedPublic, err := hex.DecodeString(authority.Record.PublicKey)
	if err != nil || len(expectedPublic) != 32 || subtle.ConstantTimeCompare(public, expectedPublic) != 1 {
		clear(expectedPublic)
		return nil, rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "unwrap", false)
	}
	clear(expectedPublic)
	clear(public)

	if err := rootGrantsTrustContractCountersignCheckInstalledAuthorityData(ctx, data, loadAuthority); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "sign", false)
	}
	if random == nil {
		return nil, rootGrantsTrustContractCountersignFailed("operation_unavailable", "sign", false)
	}
	var aux [32]byte
	defer clear(aux[:])
	if _, err := io.ReadFull(random, aux[:]); err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("operation_unavailable", "sign", false)
	}
	digest, err := hex.DecodeString(rootGrantsHashHex(data.Contract))
	if err != nil || len(digest) != 32 {
		clear(digest)
		return nil, rootGrantsTrustContractCountersignFailed("signature_verification_failed", "sign", false)
	}
	defer clear(digest)
	// Entropy and installed-authority reads may block. Cancellation retains
	// precedence, then sample wall time immediately before the private effect.
	if err := ctx.Err(); err != nil {
		return nil, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "sign", false)
	}
	if !rootGrantsTrustContractCountersignSigningTimeValid(now(), authority.NotBefore, authority.NotAfter, binding.Contract.NotAfter) {
		return nil, rootGrantsTrustContractCountersignFailed("binding_mismatch", "sign", false)
	}
	signature, err := sign(ownedPlaintext[36:], digest, aux)
	if err != nil {
		clear(signature)
		return nil, rootGrantsTrustContractCountersignFailed("signature_verification_failed", "sign", true)
	}
	if err := rootGrantsTrustContractVerifyRawSignature(data.Contract, authority.Record.PublicKey, signature); err != nil {
		clear(signature)
		return nil, rootGrantsTrustContractCountersignFailed("signature_verification_failed", "verify", true)
	}
	if err := ctx.Err(); err != nil {
		clear(signature)
		return nil, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "sign", true)
	}
	return signature, nil
}

// Whole signed Unix seconds keep negative/out-of-range runtime time fail-closed.
// Contract start is enforced by readers, so pre-contract-start countersigning is allowed.
func rootGrantsTrustContractCountersignSigningTimeValid(now, authorityNotBefore, authorityNotAfter, contractNotAfter int64) bool {
	return authorityNotBefore <= now && now <= authorityNotAfter && now <= contractNotAfter
}

func rootGrantsTrustContractCountersignWindowWithinAuthority(contract RootGrantsTrustContract, authorityNotBefore,
	authorityNotAfter, maxGrantSeconds int64) bool {
	if authorityNotBefore < 0 || authorityNotAfter <= authorityNotBefore || maxGrantSeconds < 1 ||
		contract.NotBefore < authorityNotBefore || contract.NotAfter > authorityNotAfter || contract.NotAfter <= contract.NotBefore {
		return false
	}
	return contract.NotAfter-contract.NotBefore <= maxGrantSeconds
}

func rootGrantsTrustContractCountersignBindHelperAuthority(data *rootGrantsTrustContractCountersignHelperRequestData) (
	rootGrantsTrustAuthorityV2, RootGrantsTrustBinding, error) {
	var emptyAuthority rootGrantsTrustAuthorityV2
	var emptyBinding RootGrantsTrustBinding
	if data == nil {
		return emptyAuthority, emptyBinding, rootGrantsTrustContractCountersignFailed("invalid_arguments", "authority", false)
	}
	initialBinding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: data.Contract, ScopeTextBytes: data.ScopeText, ScopeTextAvailable: data.ScopeTextAvailable,
	})
	if err != nil {
		return emptyAuthority, emptyBinding, rootGrantsTrustContractCountersignFromError(err, "contract_parse", false)
	}
	defer clear(initialBinding.ContractBytes)
	defer clear(initialBinding.ScopeTextBytes)
	var record RootGrantsRecord
	if DecodeSingleJSON(data.Review.RecordJSON, &record) != nil {
		return emptyAuthority, emptyBinding, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	if !rootGrantsTrustContractCountersignRecordPinsMatch(record, data.Review.RecordJSON, data.Issuance.RootRecord, data.Issuance.RootGeneration) {
		return emptyAuthority, emptyBinding, rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "authority", false)
	}
	var authorityHeader rootGrantsTrustAuthorityV2
	if DecodeSingleJSON(data.Review.AuthorityJSON, &authorityHeader) != nil {
		return emptyAuthority, emptyBinding, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	address := RootGrantsAddress{Service: data.Issuance.RootRecord.Service, Version: data.Issuance.RootRecord.Version}
	return rootGrantsTrustContractCountersignBindAuthority(data.Review.AuthorityJSON, address, authorityHeader.OwnerPrincipal,
		data.Issuance, data.Contract, data.ScopeText, data.ScopeTextAvailable, initialBinding)
}

func rootGrantsTrustContractCountersignAuthorityFailure(err error) error {
	converted := rootGrantsTrustContractCountersignFromError(err, "authority", false)
	var failure *RootGrantsGrantV3Failure
	if errors.As(converted, &failure) && failure != nil && failure.Phase == "authority" {
		switch failure.Code {
		case "authority_mismatch":
			return rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
		case "invalid_arguments":
			return rootGrantsTrustContractCountersignFailed("private_protocol_error", "authority", false)
		}
	}
	return converted
}

// recordPinsMatch checks the decoded full sidecar against the issuance's five authority pins without rebuilding the wire bytes.
func rootGrantsTrustContractCountersignRecordPinsMatch(record RootGrantsRecord, recordJSON []byte,
	expected RootGrantsAuthorityRecord, rootGeneration int) bool {
	if record.Schema != "keyvault-root-grants/1" || record.Purpose != "root-grants" ||
		record.Profile != rootGrantsTrustContractCountersignProfile || record.Derivation != "bip85-hdseed-wif/1" ||
		record.Path != "m/83696968h/2h/7h" || record.Algorithm != "secp256k1-bip340+ecdsa" ||
		record.Presence != "biometry-any-per-signature" || record.Version < 1 || record.Version > 2_147_483_647 ||
		!rootGrantsGrantKey(record.PublicKey) || record.SealPublicKey != "02"+record.PublicKey || !lowerHex(record.SealScript, 25) ||
		len(record.WrappingPoint) != 65 || !lowerHex(record.WrappingFingerprint, 32) ||
		rootGrantsHashHex(record.WrappingPoint) != record.WrappingFingerprint {
		return false
	}
	return record.Service == expected.Service && record.Version == expected.Version &&
		rootGeneration == record.Version && rootGrantsHashHex(recordJSON) == expected.MetadataSHA256 &&
		record.PublicKey == expected.PublicKey && record.SealScript == expected.SealScript
}

func rootGrantsTrustContractCountersignCheckInstalledAuthorityData(ctx context.Context,
	data rootGrantsTrustContractCountersignHelperRequestData,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if ctx == nil || loadAuthority == nil {
		return rootGrantsTrustContractCountersignFailed("invalid_arguments", "authority", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "authority", false)
	}
	address := RootGrantsAddress{Service: data.Issuance.RootRecord.Service, Version: data.Issuance.RootRecord.Version}
	installed, err := loadAuthority(address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(contextErr), "authority", false)
		}
		return rootGrantsTrustContractCountersignFromError(err, "authority", false)
	}
	defer clear(installed)
	if err := ctx.Err(); err != nil {
		return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "authority", false)
	}
	if len(installed) > rootGrantsTrustContractCountersignNestedMaxBytes {
		return rootGrantsTrustContractCountersignFailed("limit_exceeded", "authority", false)
	}
	if !bytes.Equal(installed, data.Review.AuthorityJSON) {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	return nil
}

func rootGrantsTrustContractCountersignPlaintextBindsRecord(ownedPlaintext, recordJSON []byte) bool {
	if len(ownedPlaintext) != 68 || !bytes.Equal(ownedPlaintext[:4], []byte("KVG1")) {
		return false
	}
	bindingInput := make([]byte, 0, len("keyvault-root-grants/plaintext/1\x00")+len(recordJSON))
	bindingInput = append(bindingInput, "keyvault-root-grants/plaintext/1\x00"...)
	bindingInput = append(bindingInput, recordJSON...)
	digestHex := rootGrantsHashHex(bindingInput)
	clear(bindingInput)
	expected, err := hex.DecodeString(digestHex)
	if err != nil {
		clear(expected)
		return false
	}
	defer clear(expected)
	return subtle.ConstantTimeCompare(ownedPlaintext[4:36], expected) == 1
}

func rootGrantsTrustContractCountersignDecodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		clear(b)
		return nil, errRootGrantsTrustCountersignInvalidBase64
	}
	return b, nil
}

func rootGrantsTrustContractCountersignHelperExchange(parent context.Context, raw, pin []byte,
	host rootGrantsHelperHost, check func(context.Context, rootGrantsTrustContractCountersignHelperRequestData) error) ([]byte, int, error) {
	if parent == nil || host == nil || check == nil {
		return nil, 0, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	if len(pin) != 20 && len(pin) != 32 {
		return nil, 0, rootGrantsTrustContractCountersignFailed("code_not_admitted", "preflight", false)
	}
	if err := parent.Err(); err != nil {
		return nil, 0, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "preflight", false)
	}
	if len(raw) == 0 {
		return nil, 0, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	if len(raw) > 262144 {
		return nil, 0, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	ownedRequest := bytes.Clone(raw)
	defer clear(ownedRequest)
	var parsed rootGrantsTrustContractCountersignHelperRequestData
	parsedOK := false
	defer parsed.clear()
	validate := func(request []byte) error {
		if parsedOK {
			return rootGrantsTrustContractCountersignFailed("private_protocol_error", "preflight", false)
		}
		candidate, err := rootGrantsTrustContractCountersignParseHelperRequest(request)
		if err != nil {
			return err
		}
		parsed = candidate
		parsedOK = true
		return nil
	}
	verify := func(request, signature []byte) error {
		if !parsedOK || !bytes.Equal(request, ownedRequest) {
			return rootGrantsTrustContractCountersignFailed("private_protocol_error", "verify", true)
		}
		return rootGrantsTrustContractVerifyRawSignature(parsed.Contract, parsed.Issuance.IssuerKey, signature)
	}
	recheck := func(ctx context.Context, request []byte) error {
		if !parsedOK || !bytes.Equal(request, ownedRequest) {
			return rootGrantsTrustContractCountersignFailed("private_protocol_error", "recheck", false)
		}
		checkInput := parsed.clone()
		defer checkInput.clear()
		return check(ctx, checkInput)
	}
	return rootGrantsPrivateSigningExchange(parent, ownedRequest, pin, host, rootGrantsPrivateSigningPurpose{
		validateRequest:  validate,
		verifySignature:  verify,
		check:            recheck,
		controlResponse:  rootGrantsTrustContractCountersignControlResponse,
		refusalFailure:   rootGrantsTrustContractCountersignHelperRefusalFailure,
		refusalCode:      rootGrantsTrustContractCountersignRefusalCode,
		uncertainRefusal: rootGrantsTrustContractCountersignHelperRefusalName,
		contextCode:      rootGrantsTrustContractCountersignContextCode,
		verificationCode: func(err error) string {
			var failure *RootGrantsGrantV3Failure
			if errors.As(err, &failure) && failure != nil {
				return failure.Code
			}
			return "signature_verification_failed"
		},
		failure:            rootGrantsTrustContractCountersignFailed,
		requireOutputClose: true,
	})
}
