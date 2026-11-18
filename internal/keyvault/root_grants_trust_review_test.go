package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Claim: the serializer emits the exact 14-member review order and derives every byte count and digest from owned canonical public inputs.
func TestRootGrantsTrustReviewCanonicalOrderAndHashes(t *testing.T) {
	input := trustReviewTestInput(t)
	contractBefore := bytes.Clone(input.Binding.ContractBytes)
	scopeBefore := bytes.Clone(input.Binding.ScopeTextBytes)
	modelBefore := trustReviewTestCloneInput(input).Binding.Contract
	contextBefore := bytes.Clone(input.IssuanceContextJSON)
	authorityBefore := bytes.Clone(input.AuthorityJSON)
	recordBefore := bytes.Clone(input.RecordJSON)

	got, err := CanonicalRootGrantsTrustReview(input)
	if err != nil {
		t.Fatal("canonical review refused:", err)
	}
	contractDigest := sha256.Sum256(input.Binding.ContractBytes)
	scopeDigest := sha256.Sum256(input.Binding.ScopeTextBytes)
	authorityDigest := sha256.Sum256(input.AuthorityJSON)
	recordDigest := sha256.Sum256(input.RecordJSON)
	want := `{"operation":"review-sign-trust-contract-countersign","profile":"namecoin-landlord-root/1","contract_profile":"swarma-trust-contract/2","contract_bytes_base64":"` +
		base64.StdEncoding.EncodeToString(input.Binding.ContractBytes) + `","contract_bytes":` +
		strconvItoa(len(input.Binding.ContractBytes)) + `,"contract_sha256":"` + hex.EncodeToString(contractDigest[:]) +
		`","scope_text_bytes_base64":"` + base64.StdEncoding.EncodeToString(input.Binding.ScopeTextBytes) + `","scope_text_bytes":` +
		strconvItoa(len(input.Binding.ScopeTextBytes)) + `,"scope_text_sha256":"` + hex.EncodeToString(scopeDigest[:]) +
		`","issuance_context":` + string(input.IssuanceContextJSON) + `,"authority":` + string(input.AuthorityJSON) +
		`,"record":` + string(input.RecordJSON) + `,"authority_sha256":"` + hex.EncodeToString(authorityDigest[:]) +
		`","record_sha256":"` + hex.EncodeToString(recordDigest[:]) + `"}`
	if string(got) != want {
		t.Fatalf("review bytes differ\n got: %s\nwant: %s", got, want)
	}
	got[0] = ' '
	if !bytes.Equal(contractBefore, input.Binding.ContractBytes) || !bytes.Equal(scopeBefore, input.Binding.ScopeTextBytes) ||
		!bytes.Equal(contextBefore, input.IssuanceContextJSON) || !bytes.Equal(authorityBefore, input.AuthorityJSON) ||
		!bytes.Equal(recordBefore, input.RecordJSON) || !reflect.DeepEqual(modelBefore, input.Binding.Contract) {
		t.Fatal("review serializer modified caller-owned bytes")
	}
}

// Claim: noncanonical, duplicate, truncated, or inconsistent review inputs refuse with no partial serialized object.
func TestRootGrantsTrustReviewRefusalsHaveNoPartialOutput(t *testing.T) {
	base := trustReviewTestInput(t)
	mutate := func(input RootGrantsTrustReviewInput, old, replacement string) RootGrantsTrustReviewInput {
		t.Helper()
		input.RecordJSON = []byte(strings.Replace(string(input.RecordJSON), old, replacement, 1))
		return input
	}
	table := []struct {
		name  string
		input RootGrantsTrustReviewInput
		code  string
	}{
		{name: "whitespace", input: mutate(base, `"version":1`, `"version": 1`), code: "private_protocol_error"},
		{name: "duplicate key", input: mutate(base, `"version":1`, `"version":1,"version":1`), code: "private_protocol_error"},
		{name: "trailing bytes", input: func() RootGrantsTrustReviewInput {
			c := base
			c.RecordJSON = append(bytes.Clone(base.RecordJSON), ' ')
			return c
		}(), code: "private_protocol_error"},
		{name: "non-object", input: func() RootGrantsTrustReviewInput { c := base; c.RecordJSON = []byte(`[]`); return c }(), code: "private_protocol_error"},
		{name: "wrong binding digest", input: func() RootGrantsTrustReviewInput {
			c := base
			c.Binding.ContractSHA256 = strings.Repeat("0", 64)
			return c
		}(), code: "private_protocol_error"},
		{name: "wrong binding model", input: func() RootGrantsTrustReviewInput { c := base; c.Binding.Contract.Note = "changed"; return c }(), code: "private_protocol_error"},
		{name: "wrong scope state", input: func() RootGrantsTrustReviewInput { c := base; c.Binding.ScopeTextState = "unknown"; return c }(), code: "private_protocol_error"},
	}
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			before := trustReviewTestCloneInput(tc.input)
			got, err := CanonicalRootGrantsTrustReview(tc.input)
			if err == nil || got != nil {
				t.Fatalf("refusal returned review bytes: %q err=%v", got, err)
			}
			trustContractTestWantLocalError(t, err, tc.code)
			if !reflect.DeepEqual(tc.input, before) {
				t.Fatal("review serializer modified caller-owned input")
			}
		})
	}
	if _, err := CanonicalRootGrantsTrustReview(base); err != nil {
		t.Fatalf("valid neighboring review failed: %v", err)
	}
}

// Claim: an oversized declared public review object is a non-LIP limit refusal before JSON parsing.
func TestRootGrantsTrustReviewBoundedNestedInputs(t *testing.T) {
	input := trustReviewTestInput(t)
	input.AuthorityJSON = []byte(`{"authority":"` + strings.Repeat("x", 262144) + `"}`)
	got, err := CanonicalRootGrantsTrustReview(input)
	if err == nil || got != nil {
		t.Fatalf("oversized nested input accepted or returned output: %q err=%v", got, err)
	}
	trustContractTestWantLocalError(t, err, "limit_exceeded")
}

func trustReviewTestInput(t *testing.T) RootGrantsTrustReviewInput {
	t.Helper()
	text := []byte{'s', 'c', 'o', 'p', 'e', '\r', '\n', 0xff}
	contract := trustContractTestRoot()
	textDigest := sha256.Sum256(text)
	contract.ScopeTextSHA256 = hex.EncodeToString(textDigest[:])
	contractBytes := trustContractTestCanonical(t, contract)
	binding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: contractBytes, ScopeTextBytes: text, ScopeTextAvailable: true,
	})
	if err != nil {
		t.Fatal("synthetic public binding refused:", err)
	}
	return RootGrantsTrustReviewInput{
		Binding:             binding,
		IssuanceContextJSON: []byte(`{"context":1}`),
		AuthorityJSON:       []byte(`{"authority":1}`),
		RecordJSON:          []byte(`{"version":1}`),
	}
}

func strconvItoa(value int) string {
	return strconv.Itoa(value)
}

func trustReviewTestCloneInput(input RootGrantsTrustReviewInput) RootGrantsTrustReviewInput {
	input.Binding.ContractBytes = bytes.Clone(input.Binding.ContractBytes)
	input.Binding.ScopeTextBytes = bytes.Clone(input.Binding.ScopeTextBytes)
	input.Binding.Contract.Actions = slices.Clone(input.Binding.Contract.Actions)
	input.Binding.Contract.Repos = slices.Clone(input.Binding.Contract.Repos)
	input.Binding.Contract.Delegate.Actions = slices.Clone(input.Binding.Contract.Delegate.Actions)
	input.Binding.Contract.Delegate.Slots = slices.Clone(input.Binding.Contract.Delegate.Slots)
	input.Binding.Contract.Delegate.Notaries = slices.Clone(input.Binding.Contract.Delegate.Notaries)
	input.IssuanceContextJSON = bytes.Clone(input.IssuanceContextJSON)
	input.AuthorityJSON = bytes.Clone(input.AuthorityJSON)
	input.RecordJSON = bytes.Clone(input.RecordJSON)
	return input
}
