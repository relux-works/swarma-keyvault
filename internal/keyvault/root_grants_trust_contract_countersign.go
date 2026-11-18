package keyvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

const (
	rootGrantsTrustContractCountersignHelperSchema    = "keyvault-root-grants-sign-request/2"
	rootGrantsTrustContractCountersignProfile         = "namecoin-landlord-root/1"
	rootGrantsTrustContractCountersignReceiptSchema   = "keyvault-root-grants-trust-contract-countersign-receipt/1"
	rootGrantsTrustContractCountersignNestedMaxBytes  = 32768
	rootGrantsTrustContractCountersignReviewMaxBytes  = 262144
	rootGrantsTrustContractCountersignPayloadMaxBytes = 262144
)

type rootGrantsTrustContractCountersignJSONSizes struct {
	issuance  int
	authority int
	record    int
	review    int
	payload   int
}

// These lengths are measured on the exact UTF-8 JSON slices, including braces
// and escapes. The complete payload excludes the four-byte private-helper frame.
func rootGrantsTrustContractCountersignJSONSizesWithinBound(s rootGrantsTrustContractCountersignJSONSizes) bool {
	return s.issuance >= 0 && s.issuance <= rootGrantsTrustContractCountersignNestedMaxBytes &&
		s.authority >= 0 && s.authority <= rootGrantsTrustContractCountersignNestedMaxBytes &&
		s.record >= 0 && s.record <= rootGrantsTrustContractCountersignNestedMaxBytes &&
		s.review >= 0 && s.review <= rootGrantsTrustContractCountersignReviewMaxBytes &&
		s.payload >= 0 && s.payload <= rootGrantsTrustContractCountersignPayloadMaxBytes
}

// RootGrantsTrustContractCountersignIssuanceContext is the closed public
// context bound to the existing versioned root record and authority.
type RootGrantsTrustContractCountersignIssuanceContext struct {
	RootRecord      RootGrantsAuthorityRecord `json:"root_record"`
	RootGeneration  int                       `json:"root_generation"`
	LandlordName    string                    `json:"landlord_name"`
	Network         string                    `json:"network"`
	Genesis         string                    `json:"genesis"`
	IssuerKey       string                    `json:"issuer_key"`
	AgentName       string                    `json:"agent_name"`
	AgentKey        string                    `json:"agent_key"`
	GranteeKey      string                    `json:"grantee_key"`
	GranteeName     string                    `json:"grantee_name"`
	NotBefore       int64                     `json:"not_before"`
	NotAfter        int64                     `json:"not_after"`
	MaxGrantSeconds int64                     `json:"max_grant_seconds"`
	MaxBudgetSat    int64                     `json:"max_budget_sat"`
	Seal            RootGrantsGrantPoint      `json:"seal"`
	Actions         []string                  `json:"actions"`
	Repos           []string                  `json:"repos"`
	SpendBudget     int64                     `json:"spend_budget"`
	DerivedV3Scope  []string                  `json:"derived_v3_scope"`
}

// RootGrantsTrustContractCountersignRequest is an in-process typed request.
// It accepts no caller digest, policy path, signing option, or private key.
type RootGrantsTrustContractCountersignRequest struct {
	Address         RootGrantsAddress
	OwnerPrincipal  string
	Contract        []byte
	ScopeText       []byte
	IssuanceContext RootGrantsTrustContractCountersignIssuanceContext
}

// RootGrantsTrustContractCountersignReceipt contains only public binding facts
// and a locally verified landlord signature; it makes no issuance claim.
// NotBefore and NotAfter are the signed contract window. The authority window
// remains in the authority-bound issuance evidence, not in this receipt.
type RootGrantsTrustContractCountersignReceipt struct {
	Schema            string               `json:"schema"`
	Operation         string               `json:"operation"`
	ContractProfile   string               `json:"contract_profile"`
	ContractSHA256    string               `json:"contract_sha256"`
	ScopeText         string               `json:"scope_text"`
	ScopeTextSHA256   string               `json:"scope_text_sha256"`
	RootRecordService string               `json:"root_record_service"`
	RootRecordVersion int                  `json:"root_record_version"`
	RootRecordSHA256  string               `json:"root_record_sha256"`
	RootGeneration    int                  `json:"root_generation"`
	IssuerKey         string               `json:"issuer_key"`
	LandlordName      string               `json:"landlord_name"`
	Network           string               `json:"network"`
	Genesis           string               `json:"genesis"`
	AgentName         string               `json:"agent_name"`
	GranteeKey        string               `json:"grantee_key"`
	GranteeName       string               `json:"grantee_name"`
	NotBefore         int64                `json:"not_before"`
	NotAfter          int64                `json:"not_after"`
	Seal              RootGrantsGrantPoint `json:"seal"`
	Actions           []string             `json:"actions"`
	Repos             []string             `json:"repos"`
	SpendBudget       int64                `json:"spend_budget"`
	DerivedV3Scope    []string             `json:"derived_v3_scope"`
	LandlordSig       string               `json:"landlord_sig"`
	Outcome           string               `json:"outcome"`
}

func rootGrantsTrustContractCountersignFailed(code, phase string, attempted bool) error {
	result := rootGrantsGrantV3Failed(code, phase, attempted)
	var failure *RootGrantsGrantV3Failure
	if errors.As(result, &failure) && failure != nil {
		if attempted || code == "canceled" || code == "timeout" || rootGrantsTrustContractCountersignHelperStatusCode(code) == 16 {
			failure.Outcome = "unknown"
		}
		failure.Message = "Root trust contract countersign attempt ended"
	}
	return result
}

// RootGrantsTrustContractCountersignHelper is the helper boundary for one
// purpose-specific call. Success returns only full-key-verified raw signature bytes.
type RootGrantsTrustContractCountersignHelper interface {
	ReviewSignTrustContractCountersign(context.Context, []byte) ([]byte, error)
}

// rootGrantsTrustContractCountersignInputsWithinBound checks a lower bound on
// the eventual helper request size before cloning or marshaling caller data.
// Exact serialized size is enforced on the finished request.
func rootGrantsTrustContractCountersignInputsWithinBound(q RootGrantsTrustContractCountersignRequest) bool {
	const maxRequestBytes = rootGrantsTrustContractCountersignPayloadMaxBytes
	total := 0
	add := func(n int) bool {
		if n < 0 || n > maxRequestBytes-total {
			return false
		}
		total += n
		return true
	}
	addString := func(value string) bool { return add(len(value)) }
	addStrings := func(values []string) bool {
		count := len(values)
		if count > maxRequestBytes/3+1 {
			return false
		}
		minimumJSONOverhead := count * 2
		if count > 0 {
			minimumJSONOverhead += count - 1
		}
		if !add(minimumJSONOverhead) {
			return false
		}
		for _, value := range values {
			if !addString(value) {
				return false
			}
		}
		return true
	}
	addBase64 := func(size int) bool {
		if size < 0 || size > maxRequestBytes {
			return false
		}
		return add(base64.StdEncoding.EncodedLen(size))
	}

	context := q.IssuanceContext
	return addBase64(len(q.Contract)) && addBase64(len(q.ScopeText)) &&
		addString(q.Address.Service) && addString(q.OwnerPrincipal) &&
		addString(context.RootRecord.Service) && addString(context.RootRecord.MetadataSHA256) &&
		addString(context.RootRecord.PublicKey) && addString(context.RootRecord.SealScript) &&
		addString(context.LandlordName) && addString(context.Network) && addString(context.Genesis) &&
		addString(context.IssuerKey) && addString(context.AgentName) && addString(context.AgentKey) &&
		addString(context.GranteeKey) && addString(context.GranteeName) && addString(context.Seal.TxID) &&
		addStrings(context.Actions) && addStrings(context.Repos) && addStrings(context.DerivedV3Scope)
}

type unavailableRootGrantsTrustContractCountersignHelper struct{}

func (unavailableRootGrantsTrustContractCountersignHelper) ReviewSignTrustContractCountersign(context.Context, []byte) ([]byte, error) {
	return nil, rootGrantsTrustContractCountersignFailed("operation_unavailable", "sign", false)
}

func rootGrantsTrustContractCountersignCloneRequest(q RootGrantsTrustContractCountersignRequest) RootGrantsTrustContractCountersignRequest {
	q.Contract = bytes.Clone(q.Contract)
	q.ScopeText = rootGrantsTrustContractCountersignCloneBytes(q.ScopeText)
	q.IssuanceContext.Actions = slices.Clone(q.IssuanceContext.Actions)
	q.IssuanceContext.Repos = slices.Clone(q.IssuanceContext.Repos)
	q.IssuanceContext.DerivedV3Scope = slices.Clone(q.IssuanceContext.DerivedV3Scope)
	return q
}

func rootGrantsTrustContractCountersignCloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	copyOfB := make([]byte, len(b))
	copy(copyOfB, b)
	return copyOfB
}

func rootGrantsTrustContractCountersignDerivedV3Scope(actions []string) []string {
	scope := make([]string, 0, 2)
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

// rootGrantsTrustContractVerifyRawSignature verifies SHA-256 over the exact
// contract octets with the bound x-only issuer key. It deliberately does not
// use the domain-prefixed Grant v3 digest.
func rootGrantsTrustContractVerifyRawSignature(contract []byte, issuerKey string, signature []byte) error {
	if !lowerHex(issuerKey, 32) {
		return rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "verify", true)
	}
	if len(contract) == 0 || len(signature) != 64 {
		return rootGrantsTrustContractCountersignFailed("signature_verification_failed", "verify", true)
	}
	key, _ := hex.DecodeString(issuerKey)
	defer clear(key)
	digest, err := hex.DecodeString(rootGrantsHashHex(contract))
	if err != nil || len(digest) != 32 {
		clear(digest)
		return rootGrantsTrustContractCountersignFailed("signature_verification_failed", "verify", true)
	}
	defer clear(digest)
	if err := VerifyNostr(key, digest, signature); err != nil {
		return rootGrantsTrustContractCountersignFailed("signature_verification_failed", "verify", true)
	}
	return nil
}

func rootGrantsTrustContractCountersignIssuanceContextJSON(c RootGrantsTrustContractCountersignIssuanceContext) ([]byte, error) {
	if c.RootRecord.Version < 0 || c.RootGeneration < 0 || c.RootGeneration != c.RootRecord.Version ||
		c.NotBefore < 0 || c.NotAfter < 0 || c.MaxGrantSeconds < 0 || c.MaxBudgetSat < 0 || c.SpendBudget < 0 ||
		c.Actions == nil || c.Repos == nil || c.DerivedV3Scope == nil {
		return nil, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	if c.MaxBudgetSat != 0 || c.SpendBudget != 0 || slices.Contains(c.Actions, "spend") {
		return nil, rootGrantsTrustContractCountersignFailed("spend_not_authorized", "authority", false)
	}
	if c.IssuerKey != c.RootRecord.PublicKey {
		return nil, rootGrantsTrustContractCountersignFailed("public_pin_mismatch", "authority", false)
	}
	if c.NotAfter <= c.NotBefore || c.MaxGrantSeconds < 1 || c.MaxGrantSeconds > c.NotAfter-c.NotBefore ||
		c.NotAfter > rootGrantsLastUnixSecond {
		return nil, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	if !slices.Equal(c.DerivedV3Scope, rootGrantsTrustContractCountersignDerivedV3Scope(c.Actions)) {
		return nil, rootGrantsTrustContractCountersignFailed("binding_mismatch", "authority", false)
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	var decoded RootGrantsTrustContractCountersignIssuanceContext
	if DecodeSingleJSON(canonical, &decoded) != nil {
		clear(canonical)
		return nil, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	return canonical, nil
}

func rootGrantsTrustContractCountersignHelperRequest(review, envelope, pairMetadata []byte) ([]byte, error) {
	if len(review) == 0 || len(envelope) == 0 || len(pairMetadata) == 0 || !json.Valid(review) || !json.Valid(envelope) {
		return nil, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{review: len(review)}) {
		return nil, rootGrantsTrustContractCountersignFailed("limit_exceeded", "review", false)
	}
	wire := rootGrantsGrantV3HelperRequest{
		Schema:       rootGrantsTrustContractCountersignHelperSchema,
		Operation:    rootGrantsTrustContractCountersignOperation,
		Review:       json.RawMessage(bytes.Clone(review)),
		Envelope:     json.RawMessage(bytes.Clone(envelope)),
		PairMetadata: hex.EncodeToString(pairMetadata),
	}
	request, err := json.Marshal(wire)
	if err != nil {
		return nil, rootGrantsTrustContractCountersignFailed("private_protocol_error", "review", false)
	}
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{payload: len(request)}) {
		clear(request)
		return nil, rootGrantsTrustContractCountersignFailed("limit_exceeded", "review", false)
	}
	return request, nil
}

func rootGrantsTrustContractCountersignHelperStatusCode(code string) int32 {
	switch code {
	case "invalid_arguments":
		return 1
	case "terminal_required":
		return 2
	case "invalid_word_number":
		return 3
	case "invalid_word_count":
		return 4
	case "invalid_mnemonic":
		return 5
	case "invalid_checksum":
		return 6
	case "invalid_derivation":
		return 7
	case "retained_record_mismatch":
		return 8
	case "public_pin_mismatch":
		return 9
	case "operation_unavailable", "review_refused":
		return 10
	case "wrapping_policy_refused":
		return 11
	case "invalid_envelope":
		return 12
	case "binding_mismatch", "authority_mismatch", "contract_mismatch", "review_changed",
		"delegation_not_authorized", "spend_not_authorized", "scope_text_unavailable",
		"scope_text_unexpected", "scope_text_hash_mismatch", "CONTRACT_ENCODING", "CONTRACT_PROFILE",
		"CONTRACT_FIELD", "CONTRACT_ACTIONS", "CONTRACT_REPOS", "CONTRACT_BUDGET", "CONTRACT_NOTE",
		"CONTRACT_PARENT", "CONTRACT_DELEGATE", "DELEGATE_NO_NOTARY":
		return 13
	case "canceled", "presence_canceled":
		return 14
	case "timeout":
		return 15
	case "private_protocol_error":
		return 16
	case "limit_exceeded":
		return 17
	case "unsupported_version":
		return 18
	case "unsupported_operation":
		return 19
	case "input_canceled":
		return 20
	case "code_not_admitted":
		return 21
	case "acl_refused":
		return 22
	case "lock_unavailable":
		return 23
	case "inventory_changed":
		return 24
	default:
		return 16
	}
}

// RootGrantsTrustContractCountersignHelperStatus maps the purpose-specific
// failure through the existing closed parent-control status frame.
func RootGrantsTrustContractCountersignHelperStatus(err error) int32 {
	if err == nil {
		return 0
	}
	frame := rootGrantsTrustContractCountersignControlResponse(err)
	if !rootGrantsValidPrivateSigningControl(frame) || frame[0] != 1 {
		return 16
	}
	return int32(binary.BigEndian.Uint32(frame[5:9]))
}

func rootGrantsTrustContractCountersignControlResponse(err error) []byte {
	if err == nil {
		return []byte{0, 0, 0, 0, 0}
	}
	codeName := "private_protocol_error"
	var failure *RootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		codeName = failure.Code
		mapped := rootGrantsTrustContractCountersignHelperStatusCode(codeName)
		if failure.Outcome == "unknown" && mapped != 14 && mapped != 15 {
			codeName = "private_protocol_error"
		}
	} else {
		var trustErr *RootGrantsTrustError
		if errors.As(err, &trustErr) && trustErr != nil {
			codeName = trustErr.Code
		} else {
			if errors.Is(err, context.DeadlineExceeded) {
				codeName = "timeout"
			} else if errors.Is(err, context.Canceled) {
				codeName = "canceled"
			} else {
				var refusal *Refusal
				if errors.As(err, &refusal) && refusal != nil {
					codeName = rootGrantsGrantV3RefusalCode(err)
				}
			}
		}
	}
	code := rootGrantsTrustContractCountersignHelperStatusCode(codeName)
	if code < 1 || code > 24 {
		code = 16
	}
	frame := []byte{1, 0, 0, 0, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:], uint32(code))
	return frame
}

func rootGrantsTrustContractCountersignHelperRefusalName(code uint32) string {
	switch code {
	case 14:
		return "canceled"
	case 15:
		return "timeout"
	case 16:
		return "private_protocol_error"
	default:
		return rootGrantsGrantV3RefusalCode(rootGrantsHelperRefusal(code))
	}
}

func rootGrantsTrustContractCountersignHelperRefusalFailure(code uint32) error {
	name := rootGrantsTrustContractCountersignHelperRefusalName(code)
	attempted := code == 14 || code == 15 || code == 16
	return rootGrantsTrustContractCountersignFailed(name, "sign", attempted)
}

func rootGrantsTrustContractCountersignRefusalCode(err error) string {
	var failure *RootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Code
	}
	var trustErr *RootGrantsTrustError
	if errors.As(err, &trustErr) && trustErr != nil {
		return trustErr.Code
	}
	return rootGrantsGrantV3RefusalCode(err)
}

func rootGrantsTrustContractCountersignContextCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "canceled"
}
