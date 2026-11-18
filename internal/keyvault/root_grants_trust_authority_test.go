package keyvault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func rootGrantsTrustAuthorityV2WireFixture(t *testing.T) (rootGrantsTrustAuthorityV2, []byte) {
	t.Helper()
	f := grantV3FullFixture(t)
	contract, contractBytes := rootGrantsTrustContractFixture(t, f, []string{"instruct", "review"})
	authority := rootGrantsTrustAuthorityV2ForContractFixture(t, f, contract, contractBytes)
	raw, err := json.Marshal(authority)
	if err != nil {
		t.Fatal("marshal synthetic authority", err)
	}
	clear(contractBytes)
	return authority, raw
}

func rootGrantsTrustAuthorityV2ForContractFixture(t *testing.T, f grantV3Fixture,
	contract RootGrantsTrustContract, contractBytes []byte) rootGrantsTrustAuthorityV2 {
	t.Helper()
	authority := rootGrantsTrustAuthorityV2{
		Schema: rootGrantsTrustAuthorityV2Schema, OwnerPrincipal: f.p.OwnerPrincipal,
		LandlordName: f.p.LandlordName, Network: f.p.Network, Genesis: f.p.Genesis,
		Record: f.p.Record, RootGeneration: int64(f.r.Version),
		Operations: []string{rootGrantsTrustContractCountersignOperation, rootGrantsGrantV3Operation},
		AgentName:  f.p.AgentName, AgentKey: f.p.AgentKey, GranteeKey: f.p.GranteeKey,
		GranteeName: f.p.GranteeName, Scope: []string{}, NotBefore: 0, NotAfter: 2000,
		MaxGrantSeconds: 1000, MaxBudgetSat: 0, Seal: f.g.Seal,
		ApprovedContract: rootGrantsTrustAuthorityV2ApprovedContract{
			Profile:             contract.Profile,
			ContractBytesBase64: base64.StdEncoding.EncodeToString(contractBytes),
			ContractSHA256:      rootGrantsHashHex(contractBytes),
		},
		ObservationPolicy: RootGrantsOfflineReview,
	}
	return authority
}

func rootGrantsTrustContractFixture(t *testing.T, f grantV3Fixture, actions []string) (RootGrantsTrustContract, []byte) {
	t.Helper()
	contract := RootGrantsTrustContract{
		Profile: rootGrantsTrustContractV2Profile, Network: f.p.Network,
		LandlordName: f.p.LandlordName, AgentName: f.p.AgentName, GranteeKey: f.p.GranteeKey,
		Actions: slices.Clone(actions), Repos: []string{}, SpendBudget: 0,
		NotBefore: 100, NotAfter: 1000, ScopeTextSHA256: "", ParentGrantID: "", Ordinal: 0,
		Delegate: RootGrantsTrustDelegate{Depth: 0, Actions: []string{}, Budget: 0,
			Slots: []RootGrantsTrustDelegateSlot{}, Notaries: []RootGrantsTrustNotary{}, Checkpoint: ""},
		Note: "synthetic public fixture",
	}
	canonical, err := CanonicalRootGrantsTrustContract(contract)
	if err != nil {
		t.Fatal("canonical synthetic trust contract", err)
	}
	return contract, canonical
}

// Claim: the ordered authority/2 wire decoder keeps its exact approved bytes
// and recomputed pin as owned public data; this is only the outer wire layer.
func TestRootGrantsTrustAuthorityV2WirePositiveAndOwned(t *testing.T) {
	_, raw := rootGrantsTrustAuthorityV2WireFixture(t)
	original := bytes.Clone(raw)
	parsed, err := rootGrantsDecodeTrustAuthorityV2Wire(raw)
	if err != nil {
		t.Fatal("synthetic authority/2 wire refused", err)
	}
	contractBytes, err := base64.StdEncoding.DecodeString(parsed.ApprovedContract.ContractBytesBase64)
	if err != nil || !bytes.Equal(contractBytes, parsed.approvedContractBytes) ||
		rootGrantsHashHex(parsed.approvedContractBytes) != parsed.ApprovedContract.ContractSHA256 {
		t.Fatal("approved contract bytes do not match their exact pin")
	}
	clear(contractBytes)
	for i := range raw {
		raw[i] = 'x'
	}
	if !bytes.Equal(original, func() []byte {
		canonical, marshalErr := json.Marshal(parsed)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return canonical
	}()) {
		t.Fatal("caller mutation changed the parsed authority projection")
	}
	projection := parsed.commonProjection()
	projection.Scope = append(projection.Scope, "repository.push")
	if len(parsed.Scope) != 0 || parsed.Scope == nil || projection.Schema != rootGrantsTrustAuthorityV2Schema {
		t.Fatal("common public projection aliases or changes trust policy")
	}
}

// Claim: malformed or mixed authority/2 representations refuse without a
// partial projection, while the adjacent canonical fixture remains accepted.
func TestRootGrantsTrustAuthorityV2WireCanonicalRefusals(t *testing.T) {
	_, raw := rootGrantsTrustAuthorityV2WireFixture(t)
	text := string(raw)
	firstComma := bytes.Index(raw, []byte(`,"owner_principal"`))
	secondCommaRelative := bytes.Index(raw[firstComma+1:], []byte(`,"landlord_name"`))
	if firstComma < 0 || secondCommaRelative < 0 {
		t.Fatal("fixture does not contain the expected leading member order")
	}
	secondComma := firstComma + 1 + secondCommaRelative
	reordered := append([]byte{'{'}, raw[firstComma+1:secondComma]...)
	reordered = append(reordered, ',')
	reordered = append(reordered, raw[1:firstComma]...)
	reordered = append(reordered, raw[secondComma:]...)
	duplicate := strings.Replace(text, `,"owner_principal"`, `,"schema":"namecoin-root-grants-authority/2","owner_principal"`, 1)
	extra := strings.TrimSuffix(text, "}") + `,"extra":true}`
	missing := strings.Replace(text, `,"observation_policy":"offline-document-review/1"`, "", 1)
	wrongType := strings.Replace(text, `"max_budget_sat":0`, `"max_budget_sat":0.0`, 1)
	wrongVersion := strings.Replace(text, rootGrantsTrustAuthorityV2Schema, "namecoin-root-grants-authority/1", 1)
	wrongContractProfile := strings.Replace(text, rootGrantsTrustContractV2Profile, "swarma-trust-contract/1", 1)
	badBase64 := strings.Replace(text, `"contract_bytes_base64":"`, `"contract_bytes_base64":"!`, 1)
	changedHash := strings.Replace(text, `"contract_sha256":"`, `"contract_sha256":"0`, 1)
	whitespace := text + "\n"
	leadingWhitespace := " " + text
	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"reordered", reordered, "invalid_arguments"},
		{"duplicate-member", []byte(duplicate), "invalid_arguments"},
		{"extra-member", []byte(extra), "invalid_arguments"},
		{"missing-member", []byte(missing), "invalid_arguments"},
		{"wrong-json-type", []byte(wrongType), "invalid_arguments"},
		{"authority-1-never-falls-through", []byte(wrongVersion), "unsupported_version"},
		{"trust-1-pin-never-falls-through", []byte(wrongContractProfile), "unsupported_version"},
		{"malformed-base64", []byte(badBase64), "invalid_arguments"},
		{"changed-contract-with-old-digest", []byte(changedHash), "authority_mismatch"},
		{"trailing-newline", []byte(whitespace), "invalid_arguments"},
		{"leading-whitespace", []byte(leadingWhitespace), "invalid_arguments"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			before := bytes.Clone(test.raw)
			parsed, err := rootGrantsDecodeTrustAuthorityV2Wire(test.raw)
			rootGrantsWantRefusal(t, err, test.code)
			if parsed.Schema != "" || parsed.approvedContractBytes != nil || !bytes.Equal(test.raw, before) {
				t.Fatal("refusal returned partial data or mutated input")
			}
		})
	}
	if _, err := rootGrantsDecodeTrustAuthorityV2Wire(raw); err != nil {
		t.Fatal("valid neighbor refused", err)
	}
}

// Claim: authority/2 rejects invalid owner, record, generation, key, window,
// duration, scope, budget, operation and fixed-profile values independently.
func TestRootGrantsTrustAuthorityV2WirePolicyBounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rootGrantsTrustAuthorityV2)
		code   string
	}{
		{"owner", func(a *rootGrantsTrustAuthorityV2) { a.OwnerPrincipal = "other" }, "authority_mismatch"},
		{"record-service", func(a *rootGrantsTrustAuthorityV2) { a.Record.Service = "bad service" }, "authority_mismatch"},
		{"record-hash", func(a *rootGrantsTrustAuthorityV2) { a.Record.MetadataSHA256 = strings.Repeat("A", 64) }, "authority_mismatch"},
		{"issuer-key", func(a *rootGrantsTrustAuthorityV2) { a.Record.PublicKey = strings.Repeat("0", 64) }, "authority_mismatch"},
		{"root-generation", func(a *rootGrantsTrustAuthorityV2) { a.RootGeneration++ }, "authority_mismatch"},
		{"agent-key", func(a *rootGrantsTrustAuthorityV2) { a.AgentKey = "short" }, "authority_mismatch"},
		{"grantee-key", func(a *rootGrantsTrustAuthorityV2) { a.GranteeKey = "short" }, "authority_mismatch"},
		{"window-order", func(a *rootGrantsTrustAuthorityV2) { a.NotBefore = a.NotAfter }, "authority_mismatch"},
		{"window-end", func(a *rootGrantsTrustAuthorityV2) { a.NotAfter = rootGrantsLastUnixSecond + 1 }, "authority_mismatch"},
		{"duration", func(a *rootGrantsTrustAuthorityV2) { a.MaxGrantSeconds = a.NotAfter - a.NotBefore + 1 }, "authority_mismatch"},
		{"nonzero-budget", func(a *rootGrantsTrustAuthorityV2) { a.MaxBudgetSat = 1 }, "authority_mismatch"},
		{"unsorted-scope", func(a *rootGrantsTrustAuthorityV2) { a.Scope = []string{"pay", "deliver"} }, "authority_mismatch"},
		{"wildcard-scope", func(a *rootGrantsTrustAuthorityV2) { a.Scope = []string{"*"} }, "authority_mismatch"},
		{"operations-order", func(a *rootGrantsTrustAuthorityV2) {
			a.Operations[0], a.Operations[1] = a.Operations[1], a.Operations[0]
		}, "unsupported_operation"},
		{"observation-policy", func(a *rootGrantsTrustAuthorityV2) { a.ObservationPolicy = "online" }, "operation_unavailable"},
		{"contract-profile", func(a *rootGrantsTrustAuthorityV2) { a.ApprovedContract.Profile = "swarma-trust-contract/1" }, "unsupported_version"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			authority, _ := rootGrantsTrustAuthorityV2WireFixture(t)
			test.mutate(&authority)
			raw, err := json.Marshal(authority)
			if err != nil {
				t.Fatal(err)
			}
			parsed, parseErr := rootGrantsDecodeTrustAuthorityV2Wire(raw)
			rootGrantsWantRefusal(t, parseErr, test.code)
			if parsed.Schema != "" || parsed.approvedContractBytes != nil {
				t.Fatal("policy refusal returned a partial authority")
			}
			if _, err := rootGrantsDecodeTrustAuthorityV2Wire(func() []byte {
				_, valid := rootGrantsTrustAuthorityV2WireFixture(t)
				return valid
			}()); err != nil {
				t.Fatal("valid neighboring authority refused", err)
			}
		})
	}
}

// Claim: trust actions derive only their explicitly mapped Grant v3 scope;
// empty trust scope remains an empty set, not a wildcard.
func TestRootGrantsTrustDerivedGrantV3ScopeIsNarrow(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		want    []string
	}{
		{"no-v3-actions", []string{"instruct", "review"}, []string{}},
		{"land-only", []string{"land"}, []string{"repository.push"}},
		{"review-and-land", []string{"land", "review"}, []string{"repository.push"}},
		{"public-spend-derivation", []string{"spend"}, []string{"pay"}},
		{"sorted-combined-derivation", []string{"land", "spend"}, []string{"pay", "repository.push"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := rootGrantsTrustDerivedGrantV3Scope(test.actions)
			if !slices.Equal(got, test.want) {
				t.Fatalf("derived scope = %#v, want %#v", got, test.want)
			}
			if len(test.want) == 0 && got == nil {
				t.Fatal("empty derived scope must be a non-nil empty set")
			}
		})
	}
}

// Claim: only an explicit authority/2 schema selects the trust branch; malformed
// and unknown authority inputs still fail the authority/1 parser instead of
// reaching the rental Grant checks.
func TestRootGrantsGrantV3AuthorityTrustBranchSelection(t *testing.T) {
	validV2, _ := rootGrantsTrustAuthorityV2WireFixture(t)
	rawV2, err := json.Marshal(validV2)
	if err != nil {
		t.Fatal(err)
	}
	if !rootGrantsGrantV3AuthorityV2Requested(rawV2) {
		t.Fatal("explicit authority/2 was not selected")
	}
	projected, err := rootGrantsParseGrantV3Authority(rawV2)
	if err != nil || projected.Schema != rootGrantsTrustAuthorityV2Schema {
		t.Fatal("canonical authority/2 did not reach its strict parser", err)
	}
	if _, err := ParseRootGrantsAuthority(rawV2); err == nil {
		t.Fatal("public authority/1 parser reinterpreted authority/2")
	}
	f := grantV3FullFixture(t)
	rawV1, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	if rootGrantsGrantV3AuthorityV2Requested(rawV1) {
		t.Fatal("authority/1 was selected as trust authority")
	}
	if _, err := rootGrantsParseGrantV3Authority(rawV1); err != nil {
		t.Fatal("authority/1 rental neighbor refused", err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"schema":"namecoin-root-grants-authority/1"}`),
		[]byte(`{"schema":"namecoin-root-grants-authority/3"}`),
		[]byte(`{"schema":"namecoin-root-grants-authority/2","extra":true}`),
		[]byte(`{"schema":"namecoin-root-grants-authority/1","schema":"namecoin-root-grants-authority/2"}`),
	} {
		if _, err := rootGrantsParseGrantV3Authority(raw); err == nil {
			t.Fatalf("noncanonical, mixed, or unknown authority reached a Grant branch: %s", raw)
		}
	}
}
