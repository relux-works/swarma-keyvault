package keyvault

import (
	"bytes"
	"slices"
)

const (
	RootGrantsTrustScopeTextNone    = "none"
	RootGrantsTrustScopeTextPresent = "present"
)

// RootGrantsTrustBindingInput carries only the exact public contract and
// scope-text octets. ScopeTextAvailable distinguishes absent text from an
// explicitly supplied empty byte string.
type RootGrantsTrustBindingInput struct {
	ContractBytes      []byte
	ScopeTextBytes     []byte
	ScopeTextAvailable bool
}

// RootGrantsTrustBinding owns the public bytes used for its computed hashes.
// It proves neither installed authority nor a service or chain effect.
type RootGrantsTrustBinding struct {
	Contract        RootGrantsTrustContract
	ContractBytes   []byte
	ContractSHA256  string
	ScopeTextBytes  []byte
	ScopeTextState  string
	ScopeTextSHA256 string
}

// BindRootGrantsTrustContract parses the exact public bytes, applies this
// operation's root-only/no-spend policy, and binds optional scope text by its
// exact octets. It reads no authority store or private state.
func BindRootGrantsTrustContract(input RootGrantsTrustBindingInput) (RootGrantsTrustBinding, error) {
	contractBytes := bytes.Clone(input.ContractBytes)
	scopeTextBytes := bytes.Clone(input.ScopeTextBytes)
	contract, err := ParseRootGrantsTrustContract(contractBytes)
	if err != nil {
		return RootGrantsTrustBinding{}, err
	}
	if err := ValidateRootGrantsTrustContractInstance(contract); err != nil {
		return RootGrantsTrustBinding{}, err
	}
	if !input.ScopeTextAvailable && len(scopeTextBytes) != 0 {
		return RootGrantsTrustBinding{}, rootGrantsTrustFailure("invalid_arguments", 0)
	}

	state := RootGrantsTrustScopeTextNone
	scopeHash := ""
	if contract.ScopeTextSHA256 == "" {
		if len(scopeTextBytes) != 0 {
			return RootGrantsTrustBinding{}, rootGrantsTrustFailure("scope_text_unexpected", 0)
		}
	} else {
		if !input.ScopeTextAvailable {
			return RootGrantsTrustBinding{}, rootGrantsTrustFailure("scope_text_unavailable", 0)
		}
		scopeHash = rootGrantsHashHex(scopeTextBytes)
		if scopeHash != contract.ScopeTextSHA256 {
			return RootGrantsTrustBinding{}, rootGrantsTrustFailure("scope_text_hash_mismatch", 0)
		}
		state = RootGrantsTrustScopeTextPresent
	}

	return RootGrantsTrustBinding{
		Contract:        contract,
		ContractBytes:   contractBytes,
		ContractSHA256:  rootGrantsHashHex(contractBytes),
		ScopeTextBytes:  scopeTextBytes,
		ScopeTextState:  state,
		ScopeTextSHA256: scopeHash,
	}, nil
}

// ValidateRootGrantsTrustContractInstance applies this caller's root-only,
// no-spend policy to a contract returned by ParseRootGrantsTrustContract.
// It reads only the parsed public model and does not check scope-text bytes,
// installed authority, signing, or service effects.
func ValidateRootGrantsTrustContractInstance(contract RootGrantsTrustContract) error {
	if contract.ParentGrantID != "" || contract.Ordinal != 0 || contract.Delegate.Depth != 0 {
		return rootGrantsTrustFailure("delegation_not_authorized", 0)
	}
	if slices.Contains(contract.Actions, "spend") || contract.SpendBudget != 0 {
		return rootGrantsTrustFailure("spend_not_authorized", 0)
	}
	return nil
}
