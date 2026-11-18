package keyvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// ReviewRootGrantsTrustContractCountersign loads only the fixed-source
// authority for q.Address and returns a receipt after the helper barrier and a
// second full-key signature verification.
func ReviewRootGrantsTrustContractCountersign(ctx context.Context, q RootGrantsTrustContractCountersignRequest) (RootGrantsTrustContractCountersignReceipt, error) {
	if ctx == nil {
		return RootGrantsTrustContractCountersignReceipt{}, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	return rootGrantsTrustContractCountersignWith(ctx, q, LoadRootGrantsAuthority,
		newRootGrantsGrantV3SigningVault(), newRootGrantsTrustContractCountersignHelper())
}

// rootGrantsTrustContractCountersignWith is the package-private fixture seam.
// Its loader is the only source boundary; production always supplies
// LoadRootGrantsAuthority and the existing guarded root vault.
func rootGrantsTrustContractCountersignWith(ctx context.Context, q RootGrantsTrustContractCountersignRequest,
	loadAuthority func(RootGrantsAddress) ([]byte, error), vault RootGrantsGrantV3SigningVault,
	helper RootGrantsTrustContractCountersignHelper) (RootGrantsTrustContractCountersignReceipt, error) {
	var empty RootGrantsTrustContractCountersignReceipt
	if ctx == nil || loadAuthority == nil || vault == nil || helper == nil {
		return empty, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	if !rootGrantsTrustContractCountersignInputsWithinBound(q) {
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	if !rootGrantsOwnerPrincipal(q.OwnerPrincipal) {
		return empty, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	if _, err := q.Address.Account(); err != nil {
		return empty, rootGrantsTrustContractCountersignFailed("invalid_arguments", "preflight", false)
	}
	// Measure the supplied typed context's canonical JSON bytes before parsing
	// the contract. This is a size-only preflight; semantic context checks stay
	// after the contract's C2 binding stage.
	contextBytes, err := json.Marshal(q.IssuanceContext)
	if err != nil {
		return empty, rootGrantsTrustContractCountersignFailed("private_protocol_error", "preflight", false)
	}
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{issuance: len(contextBytes)}) {
		clear(contextBytes)
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	clear(contextBytes)
	owned := rootGrantsTrustContractCountersignCloneRequest(q)
	defer clear(owned.Contract)
	defer clear(owned.ScopeText)

	issuance := owned.IssuanceContext
	initialBinding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: owned.Contract, ScopeTextBytes: owned.ScopeText, ScopeTextAvailable: owned.ScopeText != nil,
	})
	if err != nil {
		return empty, rootGrantsTrustContractCountersignFromError(err, "preflight", false)
	}
	defer clear(initialBinding.ContractBytes)
	defer clear(initialBinding.ScopeTextBytes)
	if err := rootGrantsTrustContractCountersignContextMatchesContract(issuance, initialBinding.Contract); err != nil {
		return empty, err
	}
	if issuance.RootRecord.Service != owned.Address.Service || issuance.RootRecord.Version != owned.Address.Version {
		return empty, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	issuanceJSON, err := rootGrantsTrustContractCountersignIssuanceContextJSON(issuance)
	if err != nil {
		return empty, err
	}
	defer clear(issuanceJSON)
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{issuance: len(issuanceJSON)}) {
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	if err := ctx.Err(); err != nil {
		return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "preflight", false)
	}

	authorityJSON, err := loadAuthority(owned.Address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(contextErr), "authority", false)
		}
		return empty, rootGrantsTrustContractCountersignFromError(err, "authority", false)
	}
	defer clear(authorityJSON)
	if len(authorityJSON) == 0 || !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{authority: len(authorityJSON)}) {
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	authority, binding, err := rootGrantsTrustContractCountersignBindAuthority(
		authorityJSON, owned.Address, owned.OwnerPrincipal, issuance, owned.Contract, owned.ScopeText,
		owned.ScopeText != nil, initialBinding)
	if err != nil {
		return empty, err
	}
	defer clear(binding.ContractBytes)
	defer clear(binding.ScopeTextBytes)
	snapshot, err := vault.ReadRootGrantsForSigning(ctx, owned.Address, authority.Record.MetadataSHA256)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(contextErr), "read", false)
		}
		return empty, rootGrantsTrustContractCountersignFromError(err, "read", false)
	}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	rootRecord, err := rootGrantsTrustContractCountersignValidateSnapshot(snapshot, owned.Address, authority.Record)
	if err != nil {
		return empty, err
	}
	recordJSON := bytes.Clone(snapshot.Metadata)
	if len(recordJSON) == 0 || !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{record: len(recordJSON)}) {
		clear(recordJSON)
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	defer clear(recordJSON)
	if err := ctx.Err(); err != nil {
		return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "read", false)
	}

	envelope, err := ParseRootGrantsEnvelope(snapshot.Envelope, rootRecord)
	if err != nil {
		return empty, rootGrantsTrustContractCountersignFailed("invalid_envelope", "read", false)
	}
	defer clear(envelope.EnclaveBlob)
	defer clear(envelope.Point)
	defer clear(envelope.Ciphertext)
	envelopeJSON, err := CanonicalRootGrantsEnvelope(envelope, rootRecord)
	if err != nil {
		return empty, rootGrantsTrustContractCountersignFailed("invalid_envelope", "read", false)
	}
	defer clear(envelopeJSON)
	reviewJSON, err := CanonicalRootGrantsTrustReview(RootGrantsTrustReviewInput{
		Binding: binding, IssuanceContextJSON: issuanceJSON, AuthorityJSON: authorityJSON, RecordJSON: recordJSON,
	})
	if err != nil {
		return empty, rootGrantsTrustContractCountersignFromError(err, "review", false)
	}
	defer clear(reviewJSON)
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{
		issuance: len(issuanceJSON), authority: len(authorityJSON), record: len(recordJSON), review: len(reviewJSON),
	}) {
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "preflight", false)
	}
	request, err := rootGrantsTrustContractCountersignHelperRequest(reviewJSON, envelopeJSON, snapshot.PairMetadata)
	if err != nil {
		return empty, err
	}
	defer clear(request)
	if len(request) == 0 || !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{
		issuance: len(issuanceJSON), authority: len(authorityJSON), record: len(recordJSON), review: len(reviewJSON), payload: len(request),
	}) {
		return empty, rootGrantsTrustContractCountersignFailed("limit_exceeded", "review", false)
	}
	if err := ctx.Err(); err != nil {
		return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "sign", false)
	}
	helperInput := bytes.Clone(request)
	signature, err := helper.ReviewSignTrustContractCountersign(ctx, helperInput)
	clear(helperInput)
	if err != nil {
		clear(signature)
		return empty, rootGrantsTrustContractCountersignFromError(err, "sign", true)
	}
	defer clear(signature)
	if err := ctx.Err(); err != nil {
		return empty, rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "verify", true)
	}
	if err := rootGrantsTrustContractVerifyRawSignature(owned.Contract, authority.Record.PublicKey, signature); err != nil {
		return empty, err
	}

	return RootGrantsTrustContractCountersignReceipt{
		Schema:            rootGrantsTrustContractCountersignReceiptSchema,
		Operation:         rootGrantsTrustContractCountersignOperation,
		ContractProfile:   rootGrantsTrustContractProfile,
		ContractSHA256:    binding.ContractSHA256,
		ScopeText:         binding.ScopeTextState,
		ScopeTextSHA256:   binding.ScopeTextSHA256,
		RootRecordService: authority.Record.Service,
		RootRecordVersion: authority.Record.Version,
		RootRecordSHA256:  authority.Record.MetadataSHA256,
		RootGeneration:    int(authority.RootGeneration),
		IssuerKey:         authority.Record.PublicKey,
		LandlordName:      issuance.LandlordName,
		Network:           issuance.Network,
		Genesis:           issuance.Genesis,
		AgentName:         issuance.AgentName,
		GranteeKey:        issuance.GranteeKey,
		GranteeName:       issuance.GranteeName,
		NotBefore:         binding.Contract.NotBefore,
		NotAfter:          binding.Contract.NotAfter,
		Seal:              issuance.Seal,
		Actions:           slices.Clone(issuance.Actions),
		Repos:             slices.Clone(issuance.Repos),
		SpendBudget:       issuance.SpendBudget,
		DerivedV3Scope:    slices.Clone(issuance.DerivedV3Scope),
		LandlordSig:       hex.EncodeToString(signature),
		Outcome:           "signed",
	}, nil
}

func rootGrantsTrustContractCountersignContextMatchesContract(issuance RootGrantsTrustContractCountersignIssuanceContext,
	contract RootGrantsTrustContract) error {
	if issuance.LandlordName != contract.LandlordName || issuance.AgentName != contract.AgentName ||
		issuance.GranteeKey != contract.GranteeKey ||
		!rootGrantsTrustContractCountersignWindowWithinAuthority(contract, issuance.NotBefore, issuance.NotAfter, issuance.MaxGrantSeconds) ||
		!slices.Equal(issuance.Actions, contract.Actions) ||
		!slices.Equal(issuance.Repos, contract.Repos) || issuance.SpendBudget != contract.SpendBudget {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	return nil
}

func rootGrantsTrustContractCountersignBindAuthority(authorityJSON []byte, address RootGrantsAddress, ownerPrincipal string,
	issuance RootGrantsTrustContractCountersignIssuanceContext, contractBytes, scopeText []byte, scopeTextAvailable bool,
	initialBinding RootGrantsTrustBinding) (rootGrantsTrustAuthorityV2, RootGrantsTrustBinding, error) {
	var empty rootGrantsTrustAuthorityV2
	authority, binding, err := rootGrantsTrustAuthorityV2ForCountersign(
		authorityJSON, contractBytes, scopeText, scopeTextAvailable, address, ownerPrincipal)
	if err != nil {
		return empty, RootGrantsTrustBinding{}, rootGrantsTrustContractCountersignAuthorityFailure(err)
	}
	if !bytes.Equal(binding.ContractBytes, initialBinding.ContractBytes) ||
		!bytes.Equal(binding.ScopeTextBytes, initialBinding.ScopeTextBytes) ||
		binding.ContractSHA256 != initialBinding.ContractSHA256 || binding.ScopeTextState != initialBinding.ScopeTextState ||
		binding.ScopeTextSHA256 != initialBinding.ScopeTextSHA256 {
		clear(binding.ContractBytes)
		clear(binding.ScopeTextBytes)
		return empty, RootGrantsTrustBinding{}, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	if err := rootGrantsTrustContractCountersignContextMatchesAuthority(issuance, authority, address, ownerPrincipal, binding); err != nil {
		clear(binding.ContractBytes)
		clear(binding.ScopeTextBytes)
		return empty, RootGrantsTrustBinding{}, err
	}
	approved := authority.approvedContractBytesCopy()
	if !bytes.Equal(approved, contractBytes) || !bytes.Equal(approved, binding.ContractBytes) {
		clear(approved)
		clear(binding.ContractBytes)
		clear(binding.ScopeTextBytes)
		return empty, RootGrantsTrustBinding{}, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	clear(approved)
	return authority, binding, nil
}

func rootGrantsTrustContractCountersignContextMatchesAuthority(issuance RootGrantsTrustContractCountersignIssuanceContext,
	authority rootGrantsTrustAuthorityV2, address RootGrantsAddress, ownerPrincipal string, binding RootGrantsTrustBinding) error {
	if authority.OwnerPrincipal != ownerPrincipal || authority.Record != issuance.RootRecord ||
		address.Service != authority.Record.Service || address.Version != authority.Record.Version ||
		int64(issuance.RootGeneration) != authority.RootGeneration || authority.RootGeneration != int64(authority.Record.Version) ||
		authority.LandlordName != issuance.LandlordName || authority.Network != issuance.Network || authority.Genesis != issuance.Genesis ||
		authority.Record.PublicKey != issuance.IssuerKey || authority.AgentName != issuance.AgentName || authority.AgentKey != issuance.AgentKey ||
		authority.GranteeKey != issuance.GranteeKey || authority.GranteeName != issuance.GranteeName ||
		authority.NotBefore != issuance.NotBefore || authority.NotAfter != issuance.NotAfter ||
		authority.MaxGrantSeconds != issuance.MaxGrantSeconds || authority.MaxBudgetSat != issuance.MaxBudgetSat ||
		authority.Seal != issuance.Seal || !slices.Equal(authority.Scope, issuance.DerivedV3Scope) ||
		!slices.Equal(issuance.DerivedV3Scope, rootGrantsTrustContractCountersignDerivedV3Scope(issuance.Actions)) ||
		binding.ContractSHA256 == "" || binding.ScopeTextState != RootGrantsTrustScopeTextNone && binding.ScopeTextState != RootGrantsTrustScopeTextPresent {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	if authority.MaxBudgetSat != 0 || issuance.SpendBudget != 0 || slices.Contains(issuance.Actions, "spend") {
		return rootGrantsTrustContractCountersignFailed("spend_not_authorized", "authority", false)
	}
	return nil
}

func rootGrantsTrustContractCountersignValidateSnapshot(snapshot RootGrantsSigningSnapshot, address RootGrantsAddress,
	expected RootGrantsAuthorityRecord) (RootGrantsRecord, error) {
	if len(snapshot.Metadata) == 0 || len(snapshot.Envelope) == 0 || len(snapshot.PairMetadata) == 0 {
		return RootGrantsRecord{}, rootGrantsTrustContractCountersignFailed("invalid_envelope", "read", false)
	}
	if len(snapshot.Metadata) > 32768 || len(snapshot.Envelope) > 65536 || len(snapshot.PairMetadata) > 32768 {
		return RootGrantsRecord{}, rootGrantsTrustContractCountersignFailed("limit_exceeded", "read", false)
	}
	record, err := ParseRootGrantsRecord(snapshot.Metadata)
	if err != nil || record.Service != address.Service || record.Version != address.Version ||
		record.Service != expected.Service || record.Version != expected.Version ||
		rootGrantsHashHex(snapshot.Metadata) != expected.MetadataSHA256 || record.PublicKey != expected.PublicKey ||
		record.SealScript != expected.SealScript {
		return RootGrantsRecord{}, rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "read", false)
	}
	envelope, err := ParseRootGrantsEnvelope(snapshot.Envelope, record)
	if err != nil {
		return RootGrantsRecord{}, rootGrantsTrustContractCountersignFailed("invalid_envelope", "read", false)
	}
	clear(envelope.EnclaveBlob)
	clear(envelope.Point)
	clear(envelope.Ciphertext)
	if rootGrantsMatchPair(snapshot.PairMetadata, record.Pair) != nil {
		return RootGrantsRecord{}, rootGrantsTrustContractCountersignFailed("retained_record_mismatch", "read", false)
	}
	return record, nil
}

func rootGrantsTrustContractCountersignFromError(err error, phase string, attempted bool) error {
	if err == nil {
		return nil
	}
	var failure *RootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		return failure
	}
	var trustFailure *RootGrantsTrustError
	if errors.As(err, &trustFailure) && trustFailure != nil {
		if trustFailure.Rule > 0 {
			phase = "contract_parse"
		}
		return rootGrantsTrustContractCountersignFailed(trustFailure.Code, phase, attempted)
	}
	return rootGrantsTrustContractCountersignFailed(rootGrantsGrantV3RefusalCode(err), phase, attempted)
}

func rootGrantsTrustContractCountersignCheckForHelperWithContext(ctx context.Context, request []byte,
	vault RootGrantsGrantV3SigningVault, loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	return rootGrantsTrustContractCountersignCheckForHelperWithClock(ctx, request, vault, loadAuthority,
		func() int64 { return time.Now().Unix() })
}

// Both ordered parent rechecks use this path; time is a runtime dependency.
func rootGrantsTrustContractCountersignCheckForHelperWithClock(ctx context.Context, request []byte,
	vault RootGrantsGrantV3SigningVault, loadAuthority func(RootGrantsAddress) ([]byte, error), now func() int64) error {
	if ctx == nil || vault == nil || loadAuthority == nil || now == nil {
		return rootGrantsTrustContractCountersignFailed("invalid_arguments", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "recheck", false)
	}
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(request)
	if err != nil {
		return err
	}
	defer data.clear()
	address := RootGrantsAddress{Service: data.Issuance.RootRecord.Service, Version: data.Issuance.RootRecord.Version}
	currentAuthority, err := loadAuthority(address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(contextErr), "recheck", false)
		}
		return rootGrantsTrustContractCountersignFromError(err, "recheck", false)
	}
	defer clear(currentAuthority)
	if len(currentAuthority) == 0 || len(currentAuthority) > rootGrantsTrustContractCountersignNestedMaxBytes {
		return rootGrantsTrustContractCountersignFailed("limit_exceeded", "recheck", false)
	}
	if !bytes.Equal(currentAuthority, data.Review.AuthorityJSON) {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "recheck", false)
	}
	snapshot, err := vault.ReadRootGrantsForSigning(ctx, address, data.Issuance.RootRecord.MetadataSHA256)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(contextErr), "recheck", false)
		}
		return rootGrantsTrustContractCountersignFromError(err, "recheck", false)
	}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	rootRecord, err := rootGrantsTrustContractCountersignValidateSnapshot(snapshot, address, data.Issuance.RootRecord)
	if err != nil {
		return rootGrantsTrustContractCountersignFromError(err, "recheck", false)
	}
	if err := rootGrantsTrustContractCountersignValidateEnvelope(data.Envelope, rootRecord); err != nil {
		return err
	}
	if !bytes.Equal(snapshot.Envelope, data.Envelope) {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "recheck", false)
	}
	if !bytes.Equal(snapshot.PairMetadata, data.PairMetadata) {
		return rootGrantsTrustContractCountersignFailed("retained_record_mismatch", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsTrustContractCountersignFailed(rootGrantsTrustContractCountersignContextCode(err), "recheck", false)
	}
	// These exact carrier bytes have already passed admission above. Read their
	// signed windows after the snapshot/cancellation checks, then sample runtime time.
	var authority rootGrantsTrustAuthorityV2
	if DecodeSingleJSON(currentAuthority, &authority) != nil {
		return rootGrantsTrustContractCountersignFailed("private_protocol_error", "recheck", false)
	}
	contract, err := ParseRootGrantsTrustContract(data.Contract)
	if err != nil {
		return rootGrantsTrustContractCountersignFromError(err, "recheck", false)
	}
	if !rootGrantsTrustContractCountersignSigningTimeValid(now(), authority.NotBefore, authority.NotAfter, contract.NotAfter) {
		return rootGrantsTrustContractCountersignFailed("binding_mismatch", "recheck", false)
	}
	return nil
}

func rootGrantsTrustContractCountersignValidateEnvelope(raw []byte, record RootGrantsRecord) error {
	var envelope RootGrantsEnvelope
	if DecodeSingleJSON(raw, &envelope) != nil {
		return rootGrantsTrustContractCountersignFailed("private_protocol_error", "recheck", false)
	}
	defer clear(envelope.EnclaveBlob)
	defer clear(envelope.Point)
	defer clear(envelope.Ciphertext)
	canonical, err := CanonicalRootGrantsEnvelope(envelope, record)
	if err != nil {
		return rootGrantsTrustContractCountersignFailed("invalid_envelope", "recheck", false)
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, raw) {
		return rootGrantsTrustContractCountersignFailed("private_protocol_error", "recheck", false)
	}
	return nil
}
