package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
)

// Claim: the binder hashes the exact public contract and scope bytes, owns its returned slices, and preserves empty versus present scope state.
func TestRootGrantsTrustBindingExactBytesAndOwnedOutput(t *testing.T) {
	root := trustContractTestRoot()
	contractBytes := trustContractTestCanonical(t, root)
	contractBefore := bytes.Clone(contractBytes)
	withoutScope, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{ContractBytes: contractBytes})
	if err != nil || withoutScope.ScopeTextState != RootGrantsTrustScopeTextNone || withoutScope.ScopeTextSHA256 != "" {
		t.Fatalf("empty scope control failed: binding=%#v err=%v", withoutScope, err)
	}
	contractHash := sha256.Sum256(contractBytes)
	if withoutScope.ContractSHA256 != hex.EncodeToString(contractHash[:]) || !bytes.Equal(withoutScope.ContractBytes, contractBytes) {
		t.Fatal("contract binding did not hash the exact canonical input")
	}
	withoutScope.ContractBytes[0] = ' '
	withoutScope.Contract.Actions[0] = "mutated"
	if !bytes.Equal(contractBytes, contractBefore) || !reflect.DeepEqual(root.Actions, []string{"instruct"}) {
		t.Fatal("binding output aliases caller input or the synthetic model")
	}

	scopeText := []byte("first line\r\nsecond line\n")
	scopeDigest := sha256.Sum256(scopeText)
	root.ScopeTextSHA256 = hex.EncodeToString(scopeDigest[:])
	contractBytes = trustContractTestCanonical(t, root)
	scopeBefore := bytes.Clone(scopeText)
	binding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: contractBytes, ScopeTextBytes: scopeText, ScopeTextAvailable: true,
	})
	if err != nil || binding.ScopeTextState != RootGrantsTrustScopeTextPresent || binding.ScopeTextSHA256 != root.ScopeTextSHA256 {
		t.Fatalf("exact scope control failed: binding=%#v err=%v", binding, err)
	}
	if !bytes.Equal(binding.ScopeTextBytes, scopeText) || !bytes.Equal(binding.ContractBytes, contractBytes) {
		t.Fatal("binding did not retain exact public input bytes")
	}
	binding.ScopeTextBytes[0] = 'X'
	if !bytes.Equal(scopeText, scopeBefore) {
		t.Fatal("binding scope output aliases caller input")
	}
}

// Claim: the binder returns the exact refusal for absent, unexpected, and changed scope bytes and for valid public forms outside this root-only instance.
func TestRootGrantsTrustBindingRefusalsAndPositiveNeighbor(t *testing.T) {
	root := trustContractTestRoot()
	emptyContract := trustContractTestCanonical(t, root)
	scopeText := []byte("same bytes, exact line endings\r\n")
	scopeDigest := sha256.Sum256(scopeText)
	root.ScopeTextSHA256 = hex.EncodeToString(scopeDigest[:])
	textContract := trustContractTestCanonical(t, root)

	delegatedContract := trustContractTestCanonical(t, trustContractTestDelegated())
	spend := trustContractTestRoot()
	spend.Actions = []string{"spend"}
	spend.SpendBudget = 1
	spendContract := trustContractTestCanonical(t, spend)
	invalidContract := bytes.Clone(emptyContract)
	invalidContract = bytes.Replace(invalidContract, []byte(`"network":"regtest"`), []byte(`"network":"other"`), 1)

	cases := []struct {
		name  string
		input RootGrantsTrustBindingInput
		code  string
	}{
		{name: "valid absent empty scope", input: RootGrantsTrustBindingInput{ContractBytes: emptyContract}},
		{name: "scope unavailable", input: RootGrantsTrustBindingInput{ContractBytes: textContract}, code: "scope_text_unavailable"},
		{name: "scope unexpectedly present", input: RootGrantsTrustBindingInput{ContractBytes: emptyContract, ScopeTextBytes: []byte("unexpected"), ScopeTextAvailable: true}, code: "scope_text_unexpected"},
		{name: "scope hash mismatch", input: RootGrantsTrustBindingInput{ContractBytes: textContract, ScopeTextBytes: []byte("same bytes, exact line endings\n"), ScopeTextAvailable: true}, code: "scope_text_hash_mismatch"},
		{name: "valid delegated profile denied by instance", input: RootGrantsTrustBindingInput{ContractBytes: delegatedContract}, code: "delegation_not_authorized"},
		{name: "valid spend profile denied by instance", input: RootGrantsTrustBindingInput{ContractBytes: spendContract}, code: "spend_not_authorized"},
		{name: "invalid contract remains parser finding", input: RootGrantsTrustBindingInput{ContractBytes: invalidContract}, code: "CONTRACT_FIELD"},
		{name: "availability contradicts bytes", input: RootGrantsTrustBindingInput{ContractBytes: emptyContract, ScopeTextBytes: []byte("unavailable"), ScopeTextAvailable: false}, code: "invalid_arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contractBefore := bytes.Clone(tc.input.ContractBytes)
			scopeBefore := bytes.Clone(tc.input.ScopeTextBytes)
			got, err := BindRootGrantsTrustContract(tc.input)
			if tc.code == "" {
				if err != nil || got.Contract.Profile != rootGrantsTrustContractProfile {
					t.Fatalf("valid control failed: binding=%#v err=%v", got, err)
				}
			} else {
				if err == nil || !reflect.DeepEqual(got, RootGrantsTrustBinding{}) {
					t.Fatalf("refusal returned partial binding: %#v err=%v", got, err)
				}
				if tc.code == "CONTRACT_FIELD" {
					trustContractTestWantError(t, err, tc.code)
				} else {
					trustContractTestWantLocalError(t, err, tc.code)
				}
			}
			if !bytes.Equal(tc.input.ContractBytes, contractBefore) || !bytes.Equal(tc.input.ScopeTextBytes, scopeBefore) {
				t.Fatal("binder modified caller-owned input bytes")
			}
		})
	}
	if got, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{ContractBytes: emptyContract}); err != nil || got.ScopeTextState != RootGrantsTrustScopeTextNone {
		t.Fatalf("valid neighboring root was refused: binding=%#v err=%v", got, err)
	}
}

// Claim: the parsed-model instance validator accepts a root control and refuses delegated or spend-enabled public forms without mutation.
func TestRootGrantsTrustContractInstanceValidator(t *testing.T) {
	root, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, trustContractTestRoot()))
	if err != nil {
		t.Fatalf("valid root parse failed: %v", err)
	}
	if err := ValidateRootGrantsTrustContractInstance(root); err != nil {
		t.Fatalf("valid root instance refused: %v", err)
	}

	textRoot := trustContractTestRoot()
	textRoot.ScopeTextSHA256 = rootGrantsHashHex([]byte("synthetic scope text"))
	textRootBytes := trustContractTestCanonical(t, textRoot)
	textRoot, err = ParseRootGrantsTrustContract(textRootBytes)
	if err != nil || ValidateRootGrantsTrustContractInstance(textRoot) != nil {
		t.Fatalf("valid root policy check incorrectly requires scope bytes: parseErr=%v policyErr=%v", err, ValidateRootGrantsTrustContractInstance(textRoot))
	}
	if _, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{ContractBytes: textRootBytes}); err == nil {
		t.Fatal("binding accepted a nonempty scope hash without its exact text bytes")
	} else {
		trustContractTestWantLocalError(t, err, "scope_text_unavailable")
	}

	delegated, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, trustContractTestDelegated()))
	if err != nil {
		t.Fatalf("valid delegated parse failed: %v", err)
	}
	spend := trustContractTestRoot()
	spend.Actions = []string{"spend"}
	spend.SpendBudget = 1
	spend, err = ParseRootGrantsTrustContract(trustContractTestCanonical(t, spend))
	if err != nil {
		t.Fatalf("valid spend parse failed: %v", err)
	}

	for _, tc := range []struct {
		name    string
		value   RootGrantsTrustContract
		wantErr string
	}{
		{name: "delegation", value: delegated, wantErr: "delegation_not_authorized"},
		{name: "spend", value: spend, wantErr: "spend_not_authorized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := CanonicalRootGrantsTrustContract(tc.value)
			if err != nil {
				t.Fatalf("valid public model did not canonicalize: %v", err)
			}
			trustContractTestWantLocalError(t, ValidateRootGrantsTrustContractInstance(tc.value), tc.wantErr)
			after, err := CanonicalRootGrantsTrustContract(tc.value)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("validator modified the model: afterErr=%v", err)
			}
		})
	}
}

func trustContractTestWantLocalError(t *testing.T, err error, code string) {
	t.Helper()
	trustErr, ok := err.(*RootGrantsTrustError)
	if !ok || trustErr.Code != code || trustErr.Rule != 0 {
		t.Fatalf("expected local %s, got %T %#v", code, err, err)
	}
}
