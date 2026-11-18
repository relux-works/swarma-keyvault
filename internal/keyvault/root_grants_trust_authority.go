package keyvault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"slices"
)

const rootGrantsTrustAuthorityV2Schema = "namecoin-root-grants-authority/2"
const rootGrantsTrustContractV2Profile = "swarma-trust-contract/2"
const rootGrantsTrustContractCountersignOperation = "review-sign-trust-contract-countersign"

type rootGrantsTrustAuthorityV2ApprovedContract struct {
	Profile             string `json:"profile"`
	ContractBytesBase64 string `json:"contract_bytes_base64"`
	ContractSHA256      string `json:"contract_sha256"`
}

// rootGrantsTrustAuthorityV2 is the private, ordered authority/2 wire model.
// It contains public policy only; decoding it does not establish installation,
// root custody, or permission to sign.
type rootGrantsTrustAuthorityV2 struct {
	Schema                string                                     `json:"schema"`
	OwnerPrincipal        string                                     `json:"owner_principal"`
	LandlordName          string                                     `json:"landlord_name"`
	Network               string                                     `json:"network"`
	Genesis               string                                     `json:"genesis"`
	Record                RootGrantsAuthorityRecord                  `json:"record"`
	RootGeneration        int64                                      `json:"root_generation"`
	Operations            []string                                   `json:"operations"`
	AgentName             string                                     `json:"agent_name"`
	AgentKey              string                                     `json:"agent_key"`
	GranteeKey            string                                     `json:"grantee_key"`
	GranteeName           string                                     `json:"grantee_name"`
	Scope                 []string                                   `json:"scope"`
	NotBefore             int64                                      `json:"not_before"`
	NotAfter              int64                                      `json:"not_after"`
	MaxGrantSeconds       int64                                      `json:"max_grant_seconds"`
	MaxBudgetSat          int64                                      `json:"max_budget_sat"`
	Seal                  RootGrantsGrantPoint                       `json:"seal"`
	ApprovedContract      rootGrantsTrustAuthorityV2ApprovedContract `json:"approved_contract"`
	ObservationPolicy     string                                     `json:"observation_policy"`
	approvedContractBytes []byte                                     `json:"-"`
}

// rootGrantsDecodeTrustAuthorityV2Wire enforces the authority/2 envelope,
// canonical member order, field rules and exact approved-contract byte pin.
// It deliberately does not parse trust/2: callers must pass those exact bytes
// through A's owned parser and policy binder before using this projection.
func rootGrantsDecodeTrustAuthorityV2Wire(raw []byte) (rootGrantsTrustAuthorityV2, error) {
	fail := func(code string) (rootGrantsTrustAuthorityV2, error) {
		return rootGrantsTrustAuthorityV2{}, recoveryRefuse(code)
	}
	if len(raw) > 32768 {
		return fail("limit_exceeded")
	}
	owned := bytes.Clone(raw)
	if len(owned) == 0 {
		return fail("invalid_arguments")
	}
	var authority rootGrantsTrustAuthorityV2
	if DecodeSingleJSON(owned, &authority) != nil {
		return fail("invalid_arguments")
	}
	canonical, err := json.Marshal(authority)
	if err != nil || !bytes.Equal(canonical, owned) {
		return fail("invalid_arguments")
	}
	if authority.Schema != rootGrantsTrustAuthorityV2Schema {
		return fail("unsupported_version")
	}
	if !slices.Equal(authority.Operations, []string{rootGrantsTrustContractCountersignOperation, rootGrantsGrantV3Operation}) {
		return fail("unsupported_operation")
	}
	if authority.ObservationPolicy != RootGrantsOfflineReview {
		return fail("operation_unavailable")
	}
	_, addressErr := (RootGrantsAddress{Service: authority.Record.Service, Version: authority.Record.Version}).Account()
	if addressErr != nil || !rootGrantsOwnerPrincipal(authority.OwnerPrincipal) || !rootGrantsGrantName(authority.LandlordName) ||
		!rootGrantsNetwork(authority.Network, authority.Genesis) || !lowerHex(authority.Record.MetadataSHA256, 32) ||
		!rootGrantsGrantKey(authority.Record.PublicKey) || authority.Record.SealScript != rootGrantsGrantSealScript(authority.Record.PublicKey) ||
		authority.RootGeneration < 0 || authority.RootGeneration != int64(authority.Record.Version) ||
		!rootGrantsGrantName(authority.AgentName) || authority.AgentName == authority.LandlordName || !rootGrantsGrantKey(authority.AgentKey) ||
		!rootGrantsGrantKey(authority.GranteeKey) || authority.GranteeName != "" && !rootGrantsGrantName(authority.GranteeName) ||
		!rootGrantsGrantScope(authority.Scope) || authority.NotBefore < 0 || authority.NotAfter <= authority.NotBefore ||
		authority.NotAfter > rootGrantsLastUnixSecond || authority.MaxGrantSeconds < 1 ||
		authority.MaxGrantSeconds > authority.NotAfter-authority.NotBefore || authority.MaxBudgetSat != 0 ||
		!lowerHex(authority.Seal.TxID, 32) {
		return fail("authority_mismatch")
	}
	if authority.ApprovedContract.Profile != rootGrantsTrustContractV2Profile {
		return fail("unsupported_version")
	}
	if !lowerHex(authority.ApprovedContract.ContractSHA256, 32) {
		return fail("authority_mismatch")
	}
	contractBytes, err := base64.StdEncoding.Strict().DecodeString(authority.ApprovedContract.ContractBytesBase64)
	if err != nil || base64.StdEncoding.EncodeToString(contractBytes) != authority.ApprovedContract.ContractBytesBase64 {
		return fail("invalid_arguments")
	}
	if len(contractBytes) == 0 || rootGrantsHashHex(contractBytes) != authority.ApprovedContract.ContractSHA256 {
		clear(contractBytes)
		return fail("authority_mismatch")
	}
	authority.approvedContractBytes = bytes.Clone(contractBytes)
	clear(contractBytes)
	return authority, nil
}

// rootGrantsParseTrustAuthorityV2 validates the pinned trust/2 contract through
// A's parser and root-only instance policy, then checks its authority bindings.
// A successful parse is public fixture policy; it proves no installation or
// native authority.
func rootGrantsParseTrustAuthorityV2(raw []byte) (rootGrantsTrustAuthorityV2, error) {
	authority, err := rootGrantsDecodeTrustAuthorityV2Wire(raw)
	if err != nil {
		return rootGrantsTrustAuthorityV2{}, err
	}
	contractBytes := authority.approvedContractBytesCopy()
	defer clear(contractBytes)
	contract, err := ParseRootGrantsTrustContract(contractBytes)
	if err != nil {
		return rootGrantsTrustAuthorityV2{}, err
	}
	if err := ValidateRootGrantsTrustContractInstance(contract); err != nil {
		return rootGrantsTrustAuthorityV2{}, err
	}
	if !rootGrantsTrustAuthorityBindsContract(authority, contract) {
		return rootGrantsTrustAuthorityV2{}, recoveryRefuse("authority_mismatch")
	}
	return authority, nil
}

func rootGrantsTrustAuthorityBindsContract(authority rootGrantsTrustAuthorityV2, contract RootGrantsTrustContract) bool {
	derivedScope := rootGrantsTrustDerivedGrantV3Scope(contract.Actions)
	return contract.Profile == rootGrantsTrustContractV2Profile &&
		contract.Network == authority.Network && contract.LandlordName == authority.LandlordName &&
		contract.AgentName == authority.AgentName && contract.GranteeKey == authority.GranteeKey &&
		contract.NotBefore >= authority.NotBefore && contract.NotAfter <= authority.NotAfter &&
		contract.NotAfter-contract.NotBefore <= authority.MaxGrantSeconds && contract.SpendBudget == 0 &&
		slices.Equal(authority.Scope, derivedScope)
}

// rootGrantsParseGrantV3Authority selects only an explicit authority/2 schema;
// every other input retains the existing strict authority/1 parser and errors.
func rootGrantsParseGrantV3Authority(raw []byte) (RootGrantsAuthority, error) {
	if !rootGrantsGrantV3AuthorityV2Requested(raw) {
		return ParseRootGrantsAuthority(raw)
	}
	authority, err := rootGrantsParseTrustAuthorityV2(raw)
	if err != nil {
		return RootGrantsAuthority{}, rootGrantsGrantV3TrustError(err)
	}
	return authority.commonProjection(), nil
}

func rootGrantsGrantV3AuthorityV2Requested(raw []byte) bool {
	var envelope struct {
		Schema string `json:"schema"`
	}
	// The version probe must tolerate the other authority/2 members. The full
	// selected parser below still enforces exact schema, order and canonicality.
	return json.Unmarshal(raw, &envelope) == nil && envelope.Schema == rootGrantsTrustAuthorityV2Schema
}

// rootGrantsTrustAuthorityV2ForCountersign accepts carried public bytes only.
// Its caller owns the fixed-source load; this function accepts no path or store.
func rootGrantsTrustAuthorityV2ForCountersign(authorityJSON, contractBytes, scopeTextBytes []byte,
	scopeTextAvailable bool, address RootGrantsAddress, ownerPrincipal string) (
	rootGrantsTrustAuthorityV2, RootGrantsTrustBinding, error) {
	var empty rootGrantsTrustAuthorityV2
	var emptyBinding RootGrantsTrustBinding
	if len(authorityJSON) > 32768 {
		return empty, emptyBinding, recoveryRefuse("limit_exceeded")
	}
	contractOwned := bytes.Clone(contractBytes)
	binding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: contractOwned, ScopeTextBytes: scopeTextBytes, ScopeTextAvailable: scopeTextAvailable,
	})
	clear(contractOwned)
	if err != nil {
		return empty, emptyBinding, err
	}
	authority, err := rootGrantsParseTrustAuthorityV2(authorityJSON)
	if err != nil {
		return empty, emptyBinding, err
	}
	approvedBytes := authority.approvedContractBytesCopy()
	defer clear(approvedBytes)
	if !bytes.Equal(binding.ContractBytes, approvedBytes) || !rootGrantsTrustAuthorityBindsContract(authority, binding.Contract) {
		return empty, emptyBinding, recoveryRefuse("authority_mismatch")
	}
	if _, err := address.Account(); err != nil || !rootGrantsOwnerPrincipal(ownerPrincipal) ||
		ownerPrincipal != authority.OwnerPrincipal || address.Service != authority.Record.Service ||
		address.Version != authority.Record.Version || authority.RootGeneration != int64(address.Version) {
		return empty, emptyBinding, recoveryRefuse("authority_mismatch")
	}
	return authority, binding, nil
}

func rootGrantsTrustDerivedGrantV3Scope(actions []string) []string {
	scope := make([]string, 0)
	for _, action := range actions {
		switch action {
		case "land":
			scope = append(scope, "repository.push")
		case "spend":
			scope = append(scope, "pay")
		}
	}
	slices.Sort(scope)
	return scope
}

func (authority rootGrantsTrustAuthorityV2) approvedContractBytesCopy() []byte {
	return bytes.Clone(authority.approvedContractBytes)
}

// commonProjection is only for the existing public snapshot validator. It is
// not a rental-policy parse and is never sufficient to authorize a Grant.
func (authority rootGrantsTrustAuthorityV2) commonProjection() RootGrantsAuthority {
	return RootGrantsAuthority{
		Schema: authority.Schema, OwnerPrincipal: authority.OwnerPrincipal, LandlordName: authority.LandlordName,
		Network: authority.Network, Genesis: authority.Genesis, Record: authority.Record,
		Operations: slices.Clone(authority.Operations), AgentName: authority.AgentName, AgentKey: authority.AgentKey,
		GranteeKey: authority.GranteeKey, GranteeName: authority.GranteeName, Scope: slices.Clone(authority.Scope),
		NotBefore: authority.NotBefore, NotAfter: authority.NotAfter, MaxGrantSeconds: authority.MaxGrantSeconds,
		MaxBudgetSat: authority.MaxBudgetSat, Seal: authority.Seal, ObservationPolicy: authority.ObservationPolicy,
	}
}
