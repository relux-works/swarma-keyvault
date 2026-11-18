package keyvault

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Claim: synthetic depth-zero, delegated, and spend contracts remain valid parser controls and canonical serialization is byte-stable.
func TestRootGrantsTrustContractCanonicalPositiveControls(t *testing.T) {
	root := trustContractTestRoot()
	rootRaw := trustContractTestCanonical(t, root)
	parsed, err := ParseRootGrantsTrustContract(rootRaw)
	if err != nil || !reflect.DeepEqual(parsed, root) {
		t.Fatalf("depth-zero control failed: parsed=%#v err=%v", parsed, err)
	}
	serialized, err := CanonicalRootGrantsTrustContract(parsed)
	if err != nil || !bytes.Equal(serialized, rootRaw) {
		t.Fatalf("canonical round-trip changed bytes: err=%v", err)
	}
	serialized[0] = ' '
	if rootRaw[0] != '{' {
		t.Fatal("canonical serializer shared caller-owned bytes")
	}

	delegated := trustContractTestDelegated()
	delegatedRaw := trustContractTestCanonical(t, delegated)
	if got, err := ParseRootGrantsTrustContract(delegatedRaw); err != nil || !reflect.DeepEqual(got, delegated) {
		t.Fatalf("public depth-one control failed: parsed=%#v err=%v", got, err)
	}

	spend := root
	spend.Actions = []string{"spend"}
	spend.SpendBudget = 1
	spendRaw := trustContractTestCanonical(t, spend)
	if got, err := ParseRootGrantsTrustContract(spendRaw); err != nil || !reflect.DeepEqual(got, spend) {
		t.Fatalf("public spend control failed: parsed=%#v err=%v", got, err)
	}

	landed := root
	landed.Actions = []string{"instruct", "land"}
	landed.Repos = []string{"https://example.com/repo"}
	landedRaw := trustContractTestCanonical(t, landed)
	if got, err := ParseRootGrantsTrustContract(landedRaw); err != nil || !reflect.DeepEqual(got, landed) {
		t.Fatalf("public land/repository control failed: parsed=%#v err=%v", got, err)
	}

	boundedNote := root
	boundedNote.Note = strings.Repeat("n", 280)
	if got, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, boundedNote)); err != nil || !reflect.DeepEqual(got, boundedNote) {
		t.Fatalf("280-byte informational note control failed: parsed=%#v err=%v", got, err)
	}

	parented := root
	parented.ParentGrantID = strings.Repeat("c", 64)
	parented.Ordinal = 1
	if got, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, parented)); err != nil || !reflect.DeepEqual(got, parented) {
		t.Fatalf("syntactically valid public parent/ordinal control failed: parsed=%#v err=%v", got, err)
	}

	escaped := root
	escaped.Note = `quote " and slash \\ remain literal`
	escapedRaw := trustContractTestCanonical(t, escaped)
	if got, err := ParseRootGrantsTrustContract(escapedRaw); err != nil || !reflect.DeepEqual(got, escaped) {
		t.Fatalf("canonical quote/backslash control failed: parsed=%#v err=%v", got, err)
	}
}

// Claim: the parser reports the first local LIP finding, returns no partial model, and never modifies the supplied bytes.
func TestRootGrantsTrustContractFirstFailureAndReadonlyControls(t *testing.T) {
	base := trustContractTestCanonical(t, trustContractTestRoot())
	longNote := strings.Repeat("x", 281)
	mutate := func(old, replacement string) []byte {
		t.Helper()
		updated := strings.Replace(string(base), old, replacement, 1)
		if updated == string(base) {
			t.Fatalf("fixture token not found: %s", old)
		}
		return []byte(updated)
	}
	table := []struct {
		name string
		raw  []byte
		code string
	}{
		{name: "lexical whitespace before fields", raw: []byte(strings.Replace(string(base), ",", ", ", 1)), code: "CONTRACT_ENCODING"},
		{name: "lexical final newline", raw: append(append([]byte(nil), base...), '\n'), code: "CONTRACT_ENCODING"},
		{name: "lexical trailing value", raw: append(append([]byte(nil), base...), []byte("{}")...), code: "CONTRACT_ENCODING"},
		{name: "lexical truncation", raw: base[:len(base)-1], code: "CONTRACT_ENCODING"},
		{name: "lexical fractional number", raw: mutate(`"spend_budget":0`, `"spend_budget":0.0`), code: "CONTRACT_ENCODING"},
		{name: "lexical negative number", raw: mutate(`"spend_budget":0`, `"spend_budget":-1`), code: "CONTRACT_ENCODING"},
		{name: "lexical integer overflow", raw: mutate(`"spend_budget":0`, `"spend_budget":9223372036854775808`), code: "CONTRACT_ENCODING"},
		{name: "lexical forbidden escape", raw: mutate(`"landlord_name":"id/root"`, `"landlord_name":"id/\u0072oot"`), code: "CONTRACT_ENCODING"},
		{name: "lexical forbidden slash escape", raw: mutate(`"landlord_name":"id/root"`, `"landlord_name":"id\/root"`), code: "CONTRACT_ENCODING"},
		{name: "lexical duplicate top member", raw: mutate(`"profile":`, `"profile":"swarma-trust-contract/2","profile":`), code: "CONTRACT_ENCODING"},
		{name: "lexical duplicate top scalar field", raw: mutate(`"network":"regtest"`, `"network":"regtest","network":"regtest"`), code: "CONTRACT_ENCODING"},
		{name: "delegate duplicate member belongs to Rule 9", raw: mutate(`"depth":0`, `"depth":0,"depth":0`), code: "CONTRACT_DELEGATE"},
		{name: "lexical unknown top member", raw: mutate(`,"note":""}`, `,"note":"","extra":0}`), code: "CONTRACT_ENCODING"},
		{name: "lexical reordered members", raw: mutate(`{"profile":"swarma-trust-contract/2","network":`, `{"network":`), code: "CONTRACT_ENCODING"},
		{name: "lexical wrong top member type", raw: mutate(`"spend_budget":0`, `"spend_budget":"0"`), code: "CONTRACT_ENCODING"},
		{name: "lexical boolean", raw: mutate(`"spend_budget":0`, `"spend_budget":true`), code: "CONTRACT_ENCODING"},
		{name: "lexical null", raw: mutate(`"spend_budget":0`, `"spend_budget":null`), code: "CONTRACT_ENCODING"},
		{name: "forbidden boolean inside action array", raw: mutate(`"actions":["instruct"]`, `"actions":["instruct",true]`), code: "CONTRACT_ENCODING"},
		{name: "forbidden null inside repository array", raw: mutate(`"repos":[]`, `"repos":[null]`), code: "CONTRACT_ENCODING"},
		{name: "lexical exponent", raw: mutate(`"spend_budget":0`, `"spend_budget":1e0`), code: "CONTRACT_ENCODING"},
		{name: "lexical leading zero", raw: mutate(`"spend_budget":0`, `"spend_budget":01`), code: "CONTRACT_ENCODING"},
		{name: "lexical nested noncanonical number", raw: mutate(`"budget":0`, `"budget":0.0`), code: "CONTRACT_ENCODING"},
		{name: "lexical non-ASCII string", raw: mutate(`"note":""`, `"note":"é"`), code: "CONTRACT_ENCODING"},
		{name: "lexical raw control byte", raw: mutate(`"note":""`, "\"note\":\"\t\""), code: "CONTRACT_ENCODING"},
		{name: "wrong top-level JSON type", raw: []byte(`[]`), code: "CONTRACT_ENCODING"},
		{name: "missing top member", raw: mutate(`,"note":""`, ``), code: "CONTRACT_ENCODING"},
		{name: "profile literal", raw: mutate(`"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/1"`), code: "CONTRACT_PROFILE"},
		{name: "network value", raw: mutate(`"network":"regtest"`, `"network":"testnet"`), code: "CONTRACT_FIELD"},
		{name: "not-after supported range", raw: mutate(`"not_after":100`, `"not_after":253402300800`), code: "CONTRACT_FIELD"},
		{name: "landlord name", raw: mutate(`"landlord_name":"id/root"`, `"landlord_name":"root"`), code: "CONTRACT_FIELD"},
		{name: "agent and landlord differ", raw: mutate(`"agent_name":"id/agent"`, `"agent_name":"id/root"`), code: "CONTRACT_FIELD"},
		{name: "grantee x-only point", raw: mutate(`"grantee_key":"`+grantV3TestK+`"`, `"grantee_key":"`+strings.Repeat("0", 64)+`"`), code: "CONTRACT_FIELD"},
		{name: "scope hash shape", raw: mutate(`"scope_text_sha256":""`, `"scope_text_sha256":"ABC"`), code: "CONTRACT_FIELD"},
		{name: "not-before range", raw: mutate(`"not_before":1`, `"not_before":253402300800`), code: "CONTRACT_FIELD"},
		{name: "not-after ordering", raw: mutate(`"not_after":100`, `"not_after":1`), code: "CONTRACT_FIELD"},
		{name: "action set", raw: mutate(`"actions":["instruct"]`, `"actions":["unknown"]`), code: "CONTRACT_ACTIONS"},
		{name: "empty actions", raw: mutate(`"actions":["instruct"]`, `"actions":[]`), code: "CONTRACT_ACTIONS"},
		{name: "action ordering", raw: mutate(`"actions":["instruct"]`, `"actions":["review","instruct"]`), code: "CONTRACT_ACTIONS"},
		{name: "duplicate action", raw: mutate(`"actions":["instruct"]`, `"actions":["instruct","instruct"]`), code: "CONTRACT_ACTIONS"},
		{name: "repository relation", raw: mutate(`"repos":[]`, `"repos":["https://example.com/repo"]`), code: "CONTRACT_REPOS"},
		{name: "repository grammar", raw: mutate(`"repos":[]`, `"repos":["https://Example.com/repo"]`), code: "CONTRACT_REPOS"},
		{name: "spend budget relation", raw: mutate(`"spend_budget":0`, `"spend_budget":1`), code: "CONTRACT_BUDGET"},
		{name: "spend action without budget", raw: mutate(`"actions":["instruct"]`, `"actions":["spend"]`), code: "CONTRACT_BUDGET"},
		{name: "note bound", raw: mutate(`"note":""`, `"note":"`+longNote+`"`), code: "CONTRACT_NOTE"},
		{name: "parent ordinal relation", raw: mutate(`"parent_grant_id":""`, `"parent_grant_id":"`+strings.Repeat("0", 64)+`"`), code: "CONTRACT_PARENT"},
		{name: "parent identifier format", raw: mutate(`"parent_grant_id":""`, `"parent_grant_id":"bad"`), code: "CONTRACT_PARENT"},
		{name: "ordinal maximum", raw: mutate(`"ordinal":0`, `"ordinal":17`), code: "CONTRACT_PARENT"},
		{name: "delegate outer type", raw: mutate(`"checkpoint":""`, `"checkpoint":0`), code: "CONTRACT_DELEGATE"},
		{name: "delegate value", raw: mutate(`"checkpoint":""`, `"checkpoint":"not-a-hash"`), code: "CONTRACT_DELEGATE"},
	}
	delegateObject := `"delegate":{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""}`
	table = append(table, struct {
		name string
		raw  []byte
		code string
	}{name: "delegate outer null", raw: trustContractTestReplace(t, base, delegateObject, `"delegate":null`), code: "CONTRACT_DELEGATE"})
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte(nil), tc.raw...)
			got, err := ParseRootGrantsTrustContract(tc.raw)
			if err == nil || !reflect.DeepEqual(got, RootGrantsTrustContract{}) || !bytes.Equal(tc.raw, before) {
				t.Fatalf("refusal returned partial model or modified bytes: got=%#v err=%v", got, err)
			}
			trustContractTestWantError(t, err, tc.code)
		})
	}
	if got, err := ParseRootGrantsTrustContract(base); err != nil || got.Profile != rootGrantsTrustContractProfile {
		t.Fatalf("valid neighbor failed: parsed=%#v err=%v", got, err)
	}
	v1 := []byte(`{"profile":"swarma-trust-contract/1","network":"regtest","landlord_name":"id/root","agent_name":"id/agent","grantee_key":"` + grantV3TestK + `","actions":["instruct"],"repos":[],"spend_budget":0,"not_before":1,"not_after":100,"note":""}`)
	_, err := ParseRootGrantsTrustContract(v1)
	trustContractTestWantError(t, err, "CONTRACT_PROFILE")
	spend := trustContractTestRoot()
	spend.Actions = []string{"spend"}
	spend.SpendBudget = 1
	spendBase := trustContractTestCanonical(t, spend)
	tooMuch := strings.Replace(string(spendBase), `"spend_budget":1`, `"spend_budget":2100000000000001`, 1)
	_, err = ParseRootGrantsTrustContract([]byte(tooMuch))
	trustContractTestWantError(t, err, "CONTRACT_BUDGET")
}

// Claim: repository ordering, uniqueness, size, count, land coupling, and the
// two-label host rule reject invalid cases; valid one- and sixteen-repository controls parse.
// Limit: host validation does not prove DNS resolution or reachability.
func TestRootGrantsTrustContractRepositoryBounds(t *testing.T) {
	makeRepos := func(count int) []string {
		values := make([]string, count)
		for i := range values {
			values[i] = fmt.Sprintf("https://example.com/r%02d", i)
		}
		return values
	}
	landed := trustContractTestRoot()
	landed.Actions = []string{"instruct", "land"}
	landed.Repos = makeRepos(1)
	if _, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, landed)); err != nil {
		t.Fatalf("valid one-repository control failed: %v", err)
	}
	landed.Repos = makeRepos(16)
	valid16 := trustContractTestCanonical(t, landed)
	if _, err := ParseRootGrantsTrustContract(valid16); err != nil {
		t.Fatalf("valid sixteen-repository boundary failed: %v", err)
	}

	longURL := "https://example.com/" + strings.Repeat("x", 181)
	shortURL := "https://example.com/r00"
	validOne := landed
	validOne.Repos = []string{shortURL}
	validOneBytes := trustContractTestCanonical(t, validOne)
	singleLabelHost := trustContractTestReplace(t, validOneBytes, `"`+shortURL+`"`, `"https://repo/r00"`)
	tooLong := trustContractTestReplace(t, validOneBytes, `"`+shortURL+`"`, `"`+longURL+`"`)
	tooMany := trustContractTestReplace(t, valid16, `"https://example.com/r15"]`, `"https://example.com/r15","https://example.com/r16"]`)

	twoRepos := landed
	twoRepos.Repos = []string{"https://example.com/a", "https://example.com/b"}
	twoRepoBytes := trustContractTestCanonical(t, twoRepos)
	reversed := trustContractTestReplace(t, twoRepoBytes, `"https://example.com/a","https://example.com/b"`, `"https://example.com/b","https://example.com/a"`)
	duplicate := trustContractTestReplace(t, twoRepoBytes, `"https://example.com/b"`, `"https://example.com/a"`)

	landWithoutRepos := trustContractTestReplace(t, trustContractTestCanonical(t, trustContractTestRoot()), `"actions":["instruct"]`, `"actions":["instruct","land"]`)
	landWithoutLand := trustContractTestReplace(t, validOneBytes, `"actions":["instruct","land"]`, `"actions":["instruct"]`)
	badPath := trustContractTestReplace(t, validOneBytes, `"https://example.com/r00"`, `"https://example.com/"`)

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "url over 200 bytes", raw: tooLong},
		{name: "seventeen repositories", raw: tooMany},
		{name: "unsorted repositories", raw: reversed},
		{name: "duplicate repository", raw: duplicate},
		{name: "land without repository", raw: landWithoutRepos},
		{name: "repository without land", raw: landWithoutLand},
		{name: "empty path segment", raw: badPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trustContractTestRefusal(t, tc.raw, "CONTRACT_REPOS")
		})
	}
	trustContractTestRefusal(t, singleLabelHost, "CONTRACT_REPOS")
}

// Claim: the inclusive 8192-byte LIP limit reaches semantic validation, while byte 8193 is rule-1 encoding failure.
func TestRootGrantsTrustContractInnerSizeBoundary(t *testing.T) {
	base := trustContractTestCanonical(t, trustContractTestRoot())
	for _, size := range []int{rootGrantsTrustContractMaxSize, rootGrantsTrustContractMaxSize + 1} {
		noteLength := size - len(base)
		raw := []byte(strings.Replace(string(base), `"note":""`, `"note":"`+strings.Repeat("x", noteLength)+`"`, 1))
		if len(raw) != size {
			t.Fatalf("constructed %d-byte case as %d bytes", size, len(raw))
		}
		_, err := ParseRootGrantsTrustContract(raw)
		if size == rootGrantsTrustContractMaxSize {
			trustContractTestWantError(t, err, "CONTRACT_NOTE")
		} else {
			trustContractTestWantError(t, err, "CONTRACT_ENCODING")
		}
	}
}

// Claim: Rule 8 beats Rule 9, and Rule 9b beats other semantic delegate-value failures after Rule 9a.
// Claim: Rule 9b rejects depth-one empty-notary delegates before malformed slot shape; a valid delegated neighbor remains accepted.
func TestRootGrantsTrustContractDelegatePrecedence(t *testing.T) {
	base := trustContractTestCanonical(t, trustContractTestRoot())
	parentAndBadDelegate := strings.Replace(string(base), `"parent_grant_id":""`, `"parent_grant_id":"`+strings.Repeat("0", 64)+`"`, 1)
	parentAndBadDelegate = strings.Replace(parentAndBadDelegate, `"ordinal":0`, `"ordinal":1`, 1)
	parentAndBadDelegate = strings.Replace(parentAndBadDelegate, `"depth":0`, `"depth":1`, 1)
	parentAndBadDelegate = strings.Replace(parentAndBadDelegate, `"checkpoint":""`, `"checkpoint":"bad"`, 1)
	_, err := ParseRootGrantsTrustContract([]byte(parentAndBadDelegate))
	trustContractTestWantError(t, err, "CONTRACT_PARENT")

	invalidSlot := `{"executor":"id/executor","grantee":"` + grantV3TestK + `","cap":1}`
	noNotary := strings.Replace(string(base), `"delegate":{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""}`,
		`"delegate":{"depth":1,"actions":["spend"],"budget":2,"slots":[`+invalidSlot+`],"notaries":[],"checkpoint":"bad"}`, 1)
	_, err = ParseRootGrantsTrustContract([]byte(noNotary))
	trustContractTestWantError(t, err, "DELEGATE_NO_NOTARY")

	if _, err := ParseRootGrantsTrustContract(trustContractTestCanonical(t, trustContractTestDelegated())); err != nil {
		t.Fatalf("valid delegated neighbor failed: %v", err)
	}
}

// Claim: Rule 9a rejects malformed delegate row shapes, while Rule 9c reports value failures in a structurally valid public delegate.
func TestRootGrantsTrustContractDelegateShapeAndValues(t *testing.T) {
	valid := trustContractTestCanonical(t, trustContractTestDelegated())
	notaryOwner := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	txid := strings.Repeat("a", 64)
	shapeCases := []struct {
		name string
		old  string
		new  string
	}{
		{name: "delegate member order", old: `{"depth":1,"actions":["instruct"]`, new: `{"actions":["instruct"],"depth":1`},
		{name: "delegate depth boolean type", old: `"depth":1`, new: `"depth":true`},
		{name: "delegate unknown member", old: `,"checkpoint":"` + strings.Repeat("b", 64) + `"}`, new: `,"checkpoint":"` + strings.Repeat("b", 64) + `","extra":0}`},
		{name: "delegate missing member", old: `,"checkpoint":"` + strings.Repeat("b", 64) + `"`, new: ``},
		{name: "slot member order", old: `"executor":"id/executor","grantee":"` + grantV3TestK + `"`, new: `"grantee":"id/executor","executor":"` + grantV3TestK + `"`},
		{name: "slot field type", old: `"cap":0`, new: `"cap":"0"`},
		{name: "duplicate slot member", old: `"cap":0`, new: `"cap":0,"cap":0`},
		{name: "slot null type", old: `"cap":0`, new: `"cap":null`},
		{name: "slot unknown member", old: `,"notary":"id/notary"}`, new: `,"notary":"id/notary","extra":0}`},
		{name: "slot missing member", old: `,"notary":"id/notary"`, new: ``},
		{name: "notary member order", old: `{"name":"id/notary","registration":{"txid":"` + txid + `","vout":0},"owner":"` + notaryOwner + `"}`,
			new: `{"owner":"` + notaryOwner + `","registration":{"txid":"` + txid + `","vout":0},"name":"id/notary"}`},
		{name: "notary field type", old: `"owner":"` + notaryOwner + `"`, new: `"owner":0`},
		{name: "duplicate notary member", old: `"owner":"` + notaryOwner + `"`, new: `"owner":"` + notaryOwner + `","owner":"` + notaryOwner + `"`},
		{name: "registration member order", old: `{"txid":"` + txid + `","vout":0}`, new: `{"vout":0,"txid":"` + txid + `"}`},
		{name: "registration field type", old: `"vout":0`, new: `"vout":"0"`},
		{name: "duplicate registration member", old: `"vout":0`, new: `"vout":0,"vout":0`},
		{name: "registration missing member", old: `,"vout":0`, new: ``},
	}
	for _, tc := range shapeCases {
		t.Run("shape/"+tc.name, func(t *testing.T) {
			raw := trustContractTestReplace(t, valid, tc.old, tc.new)
			trustContractTestRefusal(t, raw, "CONTRACT_DELEGATE")
		})
	}
	valueCases := []struct {
		name string
		old  string
		new  string
	}{
		{name: "depth", old: `"depth":1`, new: `"depth":2`},
		{name: "delegate action", old: `"actions":["instruct"],"budget":0`, new: `"actions":["spend"],"budget":0`},
		{name: "delegate action empty", old: `"actions":["instruct"],"budget":0`, new: `"actions":[],"budget":0`},
		{name: "delegate budget", old: `"budget":0`, new: `"budget":1`},
		{name: "no delegate slots", old: `"slots":[{"executor":"id/executor","grantee":"` + grantV3TestK + `","cap":0,"notary":"id/notary"}]`, new: `"slots":[]`},
		{name: "slot cap", old: `"cap":0`, new: `"cap":1`},
		{name: "slot executor equals landlord", old: `"executor":"id/executor"`, new: `"executor":"id/root"`},
		{name: "slot grantee key", old: `"grantee":"` + grantV3TestK + `"`, new: `"grantee":"` + strings.Repeat("0", 64) + `"`},
		{name: "slot notary reference", old: `"notary":"id/notary"`, new: `"notary":"id/missing"`},
		{name: "notary registration value", old: `"txid":"` + txid + `"`, new: `"txid":"bad"`},
		{name: "registration vout range", old: `"vout":0`, new: `"vout":4294967296`},
		{name: "notary owner key", old: `"owner":"` + notaryOwner + `"`, new: `"owner":"bad"`},
		{name: "checkpoint", old: `"checkpoint":"` + strings.Repeat("b", 64) + `"`, new: `"checkpoint":"bad"`},
	}
	for _, tc := range valueCases {
		t.Run("value/"+tc.name, func(t *testing.T) {
			raw := trustContractTestReplace(t, valid, tc.old, tc.new)
			trustContractTestRefusal(t, raw, "CONTRACT_DELEGATE")
		})
	}
	nonSubset := strings.Replace(string(valid), `"actions":["instruct","review"]`, `"actions":["instruct"]`, 1)
	nonSubset = strings.Replace(nonSubset, `,"delegate":{"depth":1,"actions":["instruct"]`, `,"delegate":{"depth":1,"actions":["review"]`, 1)
	trustContractTestRefusal(t, []byte(nonSubset), "CONTRACT_DELEGATE")
	tooManySlots := strings.Replace(string(valid), `"slots":[{"executor":"id/executor","grantee":"`+grantV3TestK+`","cap":0,"notary":"id/notary"}]`,
		`"slots":[`+strings.TrimSuffix(strings.Repeat(`{"executor":"id/executor","grantee":"`+grantV3TestK+`","cap":0,"notary":"id/notary"},`, 17), `,`)+`]`, 1)
	trustContractTestRefusal(t, []byte(tooManySlots), "CONTRACT_DELEGATE")
	notaries := make([]string, 5)
	for i := range notaries {
		name := fmt.Sprintf("id/notary%02d", i)
		registration := fmt.Sprintf("%064x", i+1)
		notaries[i] = `{"name":"` + name + `","registration":{"txid":"` + registration + `","vout":0},"owner":"` + notaryOwner + `"}`
	}
	tooManyNotaries := strings.Replace(string(valid), `"notaries":[{"name":"id/notary","registration":{"txid":"`+txid+`","vout":0},"owner":"`+notaryOwner+`"}]`,
		`"notaries":[`+strings.Join(notaries, `,`)+`]`, 1)
	tooManyNotaries = strings.Replace(tooManyNotaries, `"notary":"id/notary"`, `"notary":"id/notary00"`, 1)
	trustContractTestRefusal(t, []byte(tooManyNotaries), "CONTRACT_DELEGATE")
	if _, err := ParseRootGrantsTrustContract(valid); err != nil {
		t.Fatalf("valid public delegated neighbor failed: %v", err)
	}
}

func trustContractTestRoot() RootGrantsTrustContract {
	return RootGrantsTrustContract{
		Profile: rootGrantsTrustContractProfile, Network: "regtest", LandlordName: "id/root", AgentName: "id/agent",
		GranteeKey: grantV3TestK, Actions: []string{"instruct"}, Repos: []string{}, SpendBudget: 0,
		NotBefore: 1, NotAfter: 100, ScopeTextSHA256: "", ParentGrantID: "", Ordinal: 0,
		Delegate: RootGrantsTrustDelegate{Depth: 0, Actions: []string{}, Budget: 0, Slots: []RootGrantsTrustDelegateSlot{}, Notaries: []RootGrantsTrustNotary{}, Checkpoint: ""}, Note: "",
	}
}

func trustContractTestDelegated() RootGrantsTrustContract {
	contract := trustContractTestRoot()
	contract.Actions = []string{"instruct", "review"}
	contract.Delegate = RootGrantsTrustDelegate{
		Depth: 1, Actions: []string{"instruct"}, Budget: 0,
		Slots:      []RootGrantsTrustDelegateSlot{{Executor: "id/executor", Grantee: grantV3TestK, Cap: 0, Notary: "id/notary"}},
		Notaries:   []RootGrantsTrustNotary{{Name: "id/notary", Registration: RootGrantsTrustRegistration{TxID: strings.Repeat("a", 64), Vout: 0}, Owner: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}},
		Checkpoint: strings.Repeat("b", 64),
	}
	return contract
}

func trustContractTestCanonical(t *testing.T, c RootGrantsTrustContract) []byte {
	t.Helper()
	raw, err := CanonicalRootGrantsTrustContract(c)
	if err != nil {
		t.Fatalf("synthetic trust contract invalid: %v", err)
	}
	return raw
}

func trustContractTestReplace(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	updated := strings.Replace(string(raw), old, replacement, 1)
	if updated == string(raw) {
		t.Fatalf("fixture token not found: %s", old)
	}
	return []byte(updated)
}

func trustContractTestRefusal(t *testing.T, raw []byte, code string) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := ParseRootGrantsTrustContract(raw)
	if err == nil || !reflect.DeepEqual(got, RootGrantsTrustContract{}) || !bytes.Equal(raw, before) {
		t.Fatalf("refusal returned partial model or modified input: %#v %v", got, err)
	}
	trustContractTestWantError(t, err, code)
}

func trustContractTestWantError(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	trustErr, ok := err.(*RootGrantsTrustError)
	wantRule := map[string]int{
		"CONTRACT_ENCODING": 1, "CONTRACT_PROFILE": 2, "CONTRACT_FIELD": 3,
		"CONTRACT_ACTIONS": 4, "CONTRACT_REPOS": 5, "CONTRACT_BUDGET": 6,
		"CONTRACT_NOTE": 7, "CONTRACT_PARENT": 8, "CONTRACT_DELEGATE": 9,
		"DELEGATE_NO_NOTARY": 9,
	}[code]
	if !ok || trustErr.Code != code || trustErr.Rule != wantRule {
		t.Fatalf("expected %s at Rule %d, got %T %#v", code, wantRule, err, err)
	}
}
