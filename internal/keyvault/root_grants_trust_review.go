package keyvault

import (
	"bytes"
	"encoding/base64"
	"strconv"
)

const (
	rootGrantsTrustReviewOperation = "review-sign-trust-contract-countersign"
	rootGrantsTrustReviewProfile   = "namecoin-landlord-root/1"
)

// RootGrantsTrustReviewInput is assembled only after B/C validate each nested
// public object against its closed schema and exact field order. This builder
// independently checks canonical JSON syntax and recomputes all byte hashes.
type RootGrantsTrustReviewInput struct {
	Binding             RootGrantsTrustBinding
	IssuanceContextJSON []byte
	AuthorityJSON       []byte
	RecordJSON          []byte
}

// CanonicalRootGrantsTrustReview emits the exact ordered trust-countersign
// review object. It accepts no caller-provided digest and performs no authority
// selection or private operation.
func CanonicalRootGrantsTrustReview(input RootGrantsTrustReviewInput) ([]byte, error) {
	binding, err := rootGrantsTrustReviewCheckedBinding(input.Binding)
	if err != nil {
		return nil, err
	}
	if len(input.IssuanceContextJSON) > 262144 || len(input.AuthorityJSON) > 262144 || len(input.RecordJSON) > 262144 {
		return nil, rootGrantsTrustFailure("limit_exceeded", 0)
	}
	if !rootGrantsTrustCanonicalPublicObject(input.IssuanceContextJSON) ||
		!rootGrantsTrustCanonicalPublicObject(input.AuthorityJSON) || !rootGrantsTrustCanonicalPublicObject(input.RecordJSON) {
		return nil, rootGrantsTrustFailure("private_protocol_error", 0)
	}

	contractBase64 := base64.StdEncoding.EncodeToString(binding.ContractBytes)
	scopeBase64 := base64.StdEncoding.EncodeToString(binding.ScopeTextBytes)
	authorityDigest := rootGrantsHashHex(input.AuthorityJSON)
	recordDigest := rootGrantsHashHex(input.RecordJSON)

	result := make([]byte, 0, len(binding.ContractBytes)+len(binding.ScopeTextBytes)+len(input.IssuanceContextJSON)+
		len(input.AuthorityJSON)+len(input.RecordJSON)+512)
	result = append(result, `{"operation":"`+rootGrantsTrustReviewOperation+`","profile":"`+rootGrantsTrustReviewProfile+
		`","contract_profile":"`+rootGrantsTrustContractProfile+`","contract_bytes_base64":"`+contractBase64+`","contract_bytes":`...)
	result = strconv.AppendInt(result, int64(len(binding.ContractBytes)), 10)
	result = append(result, `,"contract_sha256":"`+binding.ContractSHA256+`","scope_text_bytes_base64":"`+scopeBase64+
		`","scope_text_bytes":`...)
	result = strconv.AppendInt(result, int64(len(binding.ScopeTextBytes)), 10)
	result = append(result, `,"scope_text_sha256":"`+binding.ScopeTextSHA256+`","issuance_context":`...)
	result = append(result, input.IssuanceContextJSON...)
	result = append(result, `,"authority":`...)
	result = append(result, input.AuthorityJSON...)
	result = append(result, `,"record":`...)
	result = append(result, input.RecordJSON...)
	result = append(result, `,"authority_sha256":"`+authorityDigest+`","record_sha256":"`+recordDigest+`"}`...)
	if len(result) > 262144 {
		return nil, rootGrantsTrustFailure("limit_exceeded", 0)
	}
	return result, nil
}

func rootGrantsTrustReviewCheckedBinding(input RootGrantsTrustBinding) (RootGrantsTrustBinding, error) {
	if input.ScopeTextState != RootGrantsTrustScopeTextNone && input.ScopeTextState != RootGrantsTrustScopeTextPresent {
		return RootGrantsTrustBinding{}, rootGrantsTrustFailure("private_protocol_error", 0)
	}
	canonical, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: input.ContractBytes, ScopeTextBytes: input.ScopeTextBytes,
		ScopeTextAvailable: input.ScopeTextState == RootGrantsTrustScopeTextPresent,
	})
	if err != nil {
		return RootGrantsTrustBinding{}, rootGrantsTrustFailure("private_protocol_error", 0)
	}
	modelBytes, err := CanonicalRootGrantsTrustContract(input.Contract)
	if err != nil || !bytes.Equal(modelBytes, canonical.ContractBytes) ||
		!bytes.Equal(input.ContractBytes, canonical.ContractBytes) || !bytes.Equal(input.ScopeTextBytes, canonical.ScopeTextBytes) ||
		input.ContractSHA256 != canonical.ContractSHA256 || input.ScopeTextState != canonical.ScopeTextState ||
		input.ScopeTextSHA256 != canonical.ScopeTextSHA256 {
		return RootGrantsTrustBinding{}, rootGrantsTrustFailure("private_protocol_error", 0)
	}
	return canonical, nil
}

func rootGrantsTrustCanonicalPublicObject(raw []byte) bool {
	if len(raw) == 0 || !rootGrantsTrustJSONDepthWithin(raw, 32) {
		return false
	}
	value, ok := rootGrantsTrustParseDocument(raw)
	return ok && value.kind == rootGrantsTrustJSONObject && !rootGrantsTrustHasDuplicateMembers(value)
}

func rootGrantsTrustJSONDepthWithin(raw []byte, maxDepth int) bool {
	depth := 0
	inString := false
	escaped := false
	for _, b := range raw {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return !inString && depth == 0
}
