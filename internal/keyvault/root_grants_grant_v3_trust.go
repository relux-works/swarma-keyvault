package keyvault

import (
	"bytes"
	"errors"
	"slices"
	"time"
)

// rootGrantsPrepareTrustGrantV3 is the authority/2-only final Grant branch.
// It shares the existing Grant plan and digest, but never parses trust bytes as
// a rental ContractV1 or interprets an empty scope as broad authority.
func rootGrantsPrepareTrustGrantV3(grantBytes, contractBytes, authorityBytes, metadata []byte,
	expectedOwner string, at time.Time) (*RootGrantsGrantV3Plan, error) {
	authority, err := rootGrantsParseTrustAuthorityV2(authorityBytes)
	if err != nil {
		return nil, rootGrantsGrantV3TrustError(err)
	}
	if !rootGrantsOwnerPrincipal(expectedOwner) || expectedOwner != authority.OwnerPrincipal {
		return nil, recoveryRefuse("authority_mismatch")
	}
	record, err := ParseRootGrantsRecord(metadata)
	if err != nil || rootGrantsHashHex(metadata) != authority.Record.MetadataSHA256 ||
		record.Service != authority.Record.Service || record.Version != authority.Record.Version ||
		record.PublicKey != authority.Record.PublicKey || record.SealScript != authority.Record.SealScript {
		return nil, recoveryRefuse("public_pin_mismatch")
	}

	// The syntax-only stage shares the existing Grant v3 wire checks while
	// deferring consent verification until after the trust-specific bindings.
	grant, err := rootGrantsParseGrantV3Syntax(grantBytes)
	if err != nil {
		return nil, err
	}
	if rootGrantsHashHex(contractBytes) != grant.ContractSHA256 {
		return nil, recoveryRefuse("contract_mismatch")
	}
	contract, err := ParseRootGrantsTrustContract(contractBytes)
	if err != nil {
		return nil, rootGrantsGrantV3TrustError(err)
	}
	if err := ValidateRootGrantsTrustContractInstance(contract); err != nil {
		return nil, rootGrantsGrantV3TrustError(err)
	}
	approvedBytes := authority.approvedContractBytesCopy()
	if !bytes.Equal(contractBytes, approvedBytes) {
		clear(approvedBytes)
		return nil, recoveryRefuse("authority_mismatch")
	}
	clear(approvedBytes)

	derivedScope := rootGrantsTrustDerivedGrantV3Scope(contract.Actions)
	grantBudget := int64(0)
	if grant.Budget != nil {
		grantBudget = *grant.Budget
	}
	if grant.ContractSHA256 != rootGrantsHashHex(contractBytes) ||
		grant.Network != contract.Network || grant.LandlordName != contract.LandlordName ||
		grant.AgentName != contract.AgentName || grant.GranteeKey != contract.GranteeKey ||
		grant.NotBefore != contract.NotBefore || grant.NotAfter != contract.NotAfter ||
		!slices.Equal(grant.Scope, derivedScope) || grantBudget != contract.SpendBudget {
		return nil, recoveryRefuse("contract_mismatch")
	}
	if grant.Genesis != authority.Genesis || grant.LandlordName != authority.LandlordName ||
		grant.Network != authority.Network || grant.AgentName != authority.AgentName ||
		grant.IssuerKey != authority.Record.PublicKey || grant.GranteeKey != authority.GranteeKey ||
		grant.GranteeName != authority.GranteeName || grant.Seal != authority.Seal ||
		!slices.Equal(authority.Scope, derivedScope) || contract.NotBefore < authority.NotBefore ||
		contract.NotAfter > authority.NotAfter || contract.NotAfter-contract.NotBefore > authority.MaxGrantSeconds ||
		grantBudget > authority.MaxBudgetSat || at.Unix() < authority.NotBefore || at.Unix() >= authority.NotAfter ||
		at.Unix() >= grant.NotAfter {
		return nil, recoveryRefuse("authority_mismatch")
	}

	// Consent is intentionally last in the trust binding order. ParseRootGrants
	// retains its unchanged rental path and continues checking the existing
	// complete kind-8181 consent fields and signatures here.
	if err := rootGrantsValidateGrantV3Consent(grant, at); err != nil {
		return nil, err
	}
	digest, err := rootGrantsGrantV3Digest(grantBytes)
	if err != nil {
		return nil, err
	}
	return &RootGrantsGrantV3Plan{
		grant: bytes.Clone(grantBytes), contract: bytes.Clone(contractBytes),
		authority: bytes.Clone(authorityBytes), record: bytes.Clone(metadata), message: digest,
	}, nil
}

func rootGrantsGrantV3TrustError(err error) error {
	var trustErr *RootGrantsTrustError
	if errors.As(err, &trustErr) && trustErr != nil {
		return rootGrantsGrantV3Failed(trustErr.Code, "review", false)
	}
	return err
}
