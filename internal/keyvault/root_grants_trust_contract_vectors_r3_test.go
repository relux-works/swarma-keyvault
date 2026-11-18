package keyvault

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/vectors/VECTORS-19-r3.json
var rootGrantsTrustVectorsR3 []byte

//go:embed testdata/vectors/root-grants-sign-request-v2.json
var rootGrantsTrustCountersignRequestV2 []byte

type rootGrantsTrustVectorR3Document struct {
	Schema  string                       `json:"schema"`
	Vectors []rootGrantsTrustVectorR3Row `json:"vectors"`
}

type rootGrantsTrustVectorR3Row struct {
	ID            string `json:"id"`
	Expected      string `json:"expected"`
	ExpectedCheck string `json:"expected_check"`
	Input         struct {
		Kind      string                            `json:"kind"`
		Bytes     string                            `json:"bytes"`
		Fixture   string                            `json:"fixture"`
		Mutations []rootGrantsTrustVectorR3Mutation `json:"mutations"`
	} `json:"input"`
}

type rootGrantsTrustVectorR3Mutation struct {
	Op         string   `json:"op"`
	Path       []string `json:"path"`
	Member     string   `json:"member"`
	Value      string   `json:"value"`
	SourcePath []string `json:"source_path"`
}

type rootGrantsTrustVectorJSONMember struct {
	name  string
	value *rootGrantsTrustVectorJSON
}

type rootGrantsTrustVectorJSON struct {
	kind    byte
	object  []rootGrantsTrustVectorJSONMember
	array   []*rootGrantsTrustVectorJSON
	text    string
	number  string
	boolean bool
}

// Claim: the 18 contract vectors exercise the production contract parser, and the 12 countersign vectors exercise the production helper-request parser with the artifact's ordered mutations; requests continue into the authority binder when preflight accepts them. Each vector reports its own code and phase so earlier failures cannot be mistaken for later guard coverage. This does not invoke signing, an owner operation, or the Darwin executable.
func TestRootGrantsTrustContractVectorsR3(t *testing.T) {
	var document rootGrantsTrustVectorR3Document
	if err := json.Unmarshal(rootGrantsTrustVectorsR3, &document); err != nil {
		t.Fatalf("decode embedded R3 vector metadata: %v", err)
	}
	if document.Schema != "keyvault-root-grants-trust-conformance-vectors/1" {
		t.Fatalf("unexpected R3 vector schema %q", document.Schema)
	}
	if len(document.Vectors) != 30 {
		t.Fatalf("R3 vector count: got %d, want 30", len(document.Vectors))
	}

	fixtureSum := sha256.Sum256(rootGrantsTrustCountersignRequestV2)
	if got := hex.EncodeToString(fixtureSum[:]); got != "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea" {
		t.Fatalf("embedded request fixture SHA-256 changed: %s", got)
	}
	fixtureTree, err := rootGrantsTrustVectorParseJSON(rootGrantsTrustCountersignRequestV2)
	if err != nil {
		t.Fatalf("parse raw request fixture: %v", err)
	}
	fixtureCanonical, err := rootGrantsTrustVectorCanonicalJSON(fixtureTree)
	if err != nil || !bytes.Equal(fixtureCanonical, rootGrantsTrustCountersignRequestV2) {
		t.Fatalf("fixture is not the source-defined ordered canonical JSON (error %v)", err)
	}

	seen := make(map[string]struct{}, len(document.Vectors))
	contractCount, requestCount := 0, 0
	for _, vector := range document.Vectors {
		if vector.ID == "" || vector.Expected == "" {
			t.Errorf("R3 vector has empty id or expected code")
			continue
		}
		if _, exists := seen[vector.ID]; exists {
			t.Errorf("duplicate R3 vector id %q", vector.ID)
			continue
		}
		seen[vector.ID] = struct{}{}

		switch vector.Input.Kind {
		case "contract":
			contractCount++
		case "countersign_request":
			requestCount++
		default:
			t.Errorf("vector %s has unsupported input kind %q", vector.ID, vector.Input.Kind)
			continue
		}
		vector := vector
		t.Run(vector.ID, func(t *testing.T) { rootGrantsTrustVectorRunOne(t, vector) })
	}
	if contractCount != 18 || requestCount != 12 {
		t.Fatalf("R3 vector kinds: got %d contract and %d request, want 18 and 12", contractCount, requestCount)
	}
}

func rootGrantsTrustVectorRunOne(t *testing.T, vector rootGrantsTrustVectorR3Row) {
	t.Helper()
	switch vector.Input.Kind {
	case "contract":
		if vector.Input.Bytes == "" {
			t.Fatal("contract vector has no exact input bytes")
		}
		observed, rule := rootGrantsTrustVectorContractOutcome([]byte(vector.Input.Bytes))
		t.Logf("expected=%s observed=%s rule=%d expected_check=%q", vector.Expected, observed, rule, vector.ExpectedCheck)
		if observed != vector.Expected {
			t.Fatalf("expected code %q, observed %q (rule %d)", vector.Expected, observed, rule)
		}
		if err := rootGrantsTrustVectorContractWitness(vector, rule); err != nil {
			t.Fatalf("expected_check=%q: %v", vector.ExpectedCheck, err)
		}

	case "countersign_request":
		if vector.Input.Fixture != "root-grants-sign-request-v2" {
			t.Fatalf("request vector names unsupported fixture %q", vector.Input.Fixture)
		}
		if vector.ExpectedCheck == "" {
			t.Fatal("request vector has no expected_check witness")
		}
		rawTree, err := rootGrantsTrustVectorParseJSON(rootGrantsTrustCountersignRequestV2)
		if err != nil {
			t.Fatalf("parse fixture: %v", err)
		}
		for _, mutation := range vector.Input.Mutations {
			if err := rootGrantsTrustVectorApplyMutation(rawTree, mutation); err != nil {
				t.Fatalf("apply %s mutation at %s: %v", mutation.Op, strings.Join(mutation.Path, "."), err)
			}
		}
		raw, err := rootGrantsTrustVectorCanonicalJSON(rawTree)
		if err != nil {
			t.Fatalf("serialize mutated raw request: %v", err)
		}
		observed, phase := rootGrantsTrustVectorRequestOutcome(raw)
		wantPhase := rootGrantsTrustVectorRequestPhase(vector.ID)
		t.Logf("expected=%s observed=%s phase=%s expected_phase=%s expected_check=%q",
			vector.Expected, observed, phase, wantPhase, vector.ExpectedCheck)
		if observed != vector.Expected || phase != wantPhase {
			t.Logf("preflight_checks=%s", rootGrantsTrustVectorRequestPreflight(raw))
			t.Fatalf("expected code/phase %q/%q, observed %q/%q; expected_check not established",
				vector.Expected, wantPhase, observed, phase)
		}
		if err := rootGrantsTrustVectorRequestWitness(vector, rawTree); err != nil {
			t.Fatalf("input witness for expected_check=%q: %v", vector.ExpectedCheck, err)
		}
	}
}

func rootGrantsTrustVectorRequestPreflight(raw []byte) string {
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil {
		return "outer=decode_failed"
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(outer.Review, &review) != nil {
		return "review=decode_failed"
	}
	var issuance RootGrantsTrustContractCountersignIssuanceContext
	if DecodeSingleJSON(review.IssuanceContextJSON, &issuance) != nil {
		return "issuance=decode_failed"
	}
	contract, contractErr := rootGrantsTrustContractCountersignDecodeBase64(review.ContractBase64)
	scopeText, scopeErr := rootGrantsTrustContractCountersignDecodeBase64(review.ScopeTextBase64)
	if contractErr != nil || scopeErr != nil {
		return "contract_or_scope_base64=decode_failed"
	}
	defer clear(contract)
	defer clear(scopeText)
	binding, err := BindRootGrantsTrustContract(RootGrantsTrustBindingInput{
		ContractBytes: contract, ScopeTextBytes: scopeText, ScopeTextAvailable: review.ScopeTextSHA256 != "",
	})
	if err != nil {
		return "contract_binding=failed"
	}
	defer clear(binding.ContractBytes)
	defer clear(binding.ScopeTextBytes)
	checks := []string{
		"contract_sha256=" + rootGrantsTrustVectorCheck(review.ContractSHA256 == binding.ContractSHA256),
		"authority_sha256=" + rootGrantsTrustVectorCheck(review.AuthoritySHA256 == rootGrantsHashHex(review.AuthorityJSON)),
		"record_sha256=" + rootGrantsTrustVectorCheck(review.RecordSHA256 == rootGrantsHashHex(review.RecordJSON)),
	}
	checks = append(checks,
		"landlord="+rootGrantsTrustVectorCheck(issuance.LandlordName == binding.Contract.LandlordName),
		"network="+rootGrantsTrustVectorCheck(issuance.Network == binding.Contract.Network),
		"agent_name="+rootGrantsTrustVectorCheck(issuance.AgentName == binding.Contract.AgentName),
		"grantee_key="+rootGrantsTrustVectorCheck(issuance.GranteeKey == binding.Contract.GranteeKey),
		"not_before="+rootGrantsTrustVectorCheck(issuance.NotBefore == binding.Contract.NotBefore),
		"not_after="+rootGrantsTrustVectorCheck(issuance.NotAfter == binding.Contract.NotAfter),
		"actions="+rootGrantsTrustVectorCheck(slices.Equal(issuance.Actions, binding.Contract.Actions)),
		"repos="+rootGrantsTrustVectorCheck(slices.Equal(issuance.Repos, binding.Contract.Repos)),
		"spend_budget="+rootGrantsTrustVectorCheck(issuance.SpendBudget == binding.Contract.SpendBudget),
	)
	return strings.Join(checks, ",")
}

func rootGrantsTrustVectorCheck(ok bool) string {
	if ok {
		return "ok"
	}
	return "mismatch"
}

func rootGrantsTrustVectorContractOutcome(raw []byte) (string, int) {
	_, err := ParseRootGrantsTrustContract(raw)
	if err == nil {
		return "ACCEPT", 0
	}
	var contractErr *RootGrantsTrustError
	if errors.As(err, &contractErr) && contractErr != nil {
		return contractErr.Code, contractErr.Rule
	}
	return "<unclassified-error>", 0
}

func rootGrantsTrustVectorContractWitness(vector rootGrantsTrustVectorR3Row, rule int) error {
	switch vector.ID {
	case "f2-single-label-host":
		if vector.Expected != "CONTRACT_REPOS" || rule != 5 {
			return fmt.Errorf("single-label DNS host did not reach repository rule 5")
		}
	case "f2-two-label-host-positive":
		if vector.Expected != "ACCEPT" || rule != 0 {
			return fmt.Errorf("valid two-label DNS host was not accepted")
		}
	case "review18-finding-2-delegate-duplicate-member":
		if vector.Expected != "CONTRACT_DELEGATE" || rule != 9 {
			return fmt.Errorf("nested delegate duplicate did not reach Rule 9")
		}
	case "review18-finding-2-valid-delegate-positive":
		if vector.Expected != "ACCEPT" || rule != 0 {
			return fmt.Errorf("valid delegate neighbor was not accepted")
		}
	case "review18-finding-3-empty-notaries-malformed-slot":
		if vector.Expected != "DELEGATE_NO_NOTARY" || rule != 9 {
			return fmt.Errorf("empty-notary refusal did not win at Rule 9b")
		}
	case "review18-finding-3-valid-delegate-positive":
		if vector.Expected != "ACCEPT" || rule != 0 {
			return fmt.Errorf("valid notary-backed delegate neighbor was not accepted")
		}
	}
	return nil
}

func rootGrantsTrustVectorRequestOutcome(raw []byte) (string, string) {
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
	if err != nil {
		return rootGrantsTrustVectorFailure(err)
	}
	defer data.clear()
	authority, binding, err := rootGrantsTrustContractCountersignBindHelperAuthority(&data)
	if err != nil {
		return rootGrantsTrustVectorFailure(err)
	}
	clear(authority.approvedContractBytes)
	clear(binding.ContractBytes)
	clear(binding.ScopeTextBytes)
	return "success", ""
}

func rootGrantsTrustVectorFailure(err error) (string, string) {
	var failure *RootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Code, failure.Phase
	}
	var trustFailure *RootGrantsTrustError
	if errors.As(err, &trustFailure) && trustFailure != nil {
		return trustFailure.Code, "contract_parse"
	}
	return "<unclassified-error>", ""
}

func rootGrantsTrustVectorRequestPhase(id string) string {
	switch id {
	case "f4-valid-request-positive":
		return ""
	case "f1-authority-agent-off-curve", "f1-authority-grantee-off-curve",
		"f4-authority-value-mismatch", "f4-record-public-key-value-mismatch",
		"f4-record-wrapping-point-valid-base64-wrong-value",
		"f4-approved-contract-malformed-base64", "f4-approved-contract-valid-base64-wrong-value":
		return "authority"
	default:
		return "review"
	}
}

func rootGrantsTrustVectorRequestWitness(vector rootGrantsTrustVectorR3Row, root *rootGrantsTrustVectorJSON) error {
	review := rootGrantsTrustVectorAt(root, []string{"review"})
	if review == nil || review.kind != '{' {
		return fmt.Errorf("raw request has no review object")
	}
	authority := rootGrantsTrustVectorAt(root, []string{"review", "authority"})
	record := rootGrantsTrustVectorAt(root, []string{"review", "record"})
	authorityHash := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "authority_sha256"}))
	recordHash := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "record_sha256"}))
	authorityDigest, authorityErr := rootGrantsTrustVectorDigest(authority)
	recordDigest, recordErr := rootGrantsTrustVectorDigest(record)
	authorityHashValid := authorityErr == nil && authorityHash == authorityDigest
	recordHashValid := recordErr == nil && recordHash == recordDigest

	expectContains := func(fragment string) error {
		if !strings.Contains(vector.ExpectedCheck, fragment) {
			return fmt.Errorf("expected_check does not name %q", fragment)
		}
		return nil
	}
	switch vector.ID {
	case "f4-valid-request-positive":
		if len(vector.Input.Mutations) != 0 || !authorityHashValid || !recordHashValid {
			return fmt.Errorf("positive request is not the unmutated, hash-valid fixture")
		}
		return expectContains("success return")
	case "f1-authority-agent-off-curve", "f1-authority-grantee-off-curve":
		field := "agent_key"
		if vector.ID == "f1-authority-grantee-off-curve" {
			field = "grantee_key"
		}
		value := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "authority", field}))
		if !authorityHashValid || rootGrantsGrantKey(value) {
			return fmt.Errorf("expected a hash-valid authority with an off-curve %s", field)
		}
		return expectContains("x-only point guard")
	case "f1-authority-agent-off-curve-stale-hash-control":
		if authorityHashValid || rootGrantsGrantKey(rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "authority", "agent_key"}))) {
			return fmt.Errorf("stale-hash control did not retain the stale authority hash and off-curve key")
		}
		return expectContains("checkedHash(review.authority_sha256)")
	case "f4-authority-shape-missing-member":
		if rootGrantsTrustVectorHasMember(authority, "landlord_name") || !authorityHashValid {
			return fmt.Errorf("missing-member authority was not rehashed after removal")
		}
		return expectContains("exact field-set")
	case "f4-authority-value-mismatch":
		landlord := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(authority, []string{"landlord_name"}))
		contextLandlord := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "issuance_context", "landlord_name"}))
		if !authorityHashValid || landlord == "" || landlord == contextLandlord {
			return fmt.Errorf("authority landlord mutation is absent or its hash was not recomputed")
		}
		return expectContains("landlord/context/contract binding")
	case "f4-record-shape-missing-member":
		if rootGrantsTrustVectorHasMember(record, "public_key") || !recordHashValid {
			return fmt.Errorf("missing-member record was not rehashed after removal")
		}
		return expectContains("exact field-set")
	case "f4-record-public-key-value-mismatch":
		publicKey := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(record, []string{"public_key"}))
		issuerKey := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "issuance_context", "issuer_key"}))
		authorityKey := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(authority, []string{"record", "public_key"}))
		if !recordHashValid || !rootGrantsTrustVectorHasMember(record, "public_key") || publicKey == issuerKey ||
			publicKey == authorityKey || rootGrantsGrantKey(publicKey) {
			return fmt.Errorf("record public-key mutation is not a hash-valid present non-key value")
		}
		return expectContains("record public pin checks")
	case "f4-record-wrapping-point-malformed-base64":
		value := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(record, []string{"wrapping_point"}))
		if !recordHashValid {
			return fmt.Errorf("malformed wrapping-point record hash was not recomputed")
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(value); err == nil {
			return fmt.Errorf("wrapping-point mutation is valid Base64")
		}
		return expectContains("Base64 decode")
	case "f4-record-wrapping-point-valid-base64-wrong-value":
		value := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(record, []string{"wrapping_point"}))
		point, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || !recordHashValid || len(point) == 0 {
			return fmt.Errorf("wrong wrapping point is not nonempty valid Base64 with a recomputed record hash")
		}
		fingerprint := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(record, []string{"wrapping_fingerprint"}))
		sum := sha256.Sum256(point)
		if len(point) == 65 && fingerprint == hex.EncodeToString(sum[:]) {
			return fmt.Errorf("wrong wrapping point matches both the accepted size and retained fingerprint")
		}
		return expectContains("fingerprint pin")
	case "f4-approved-contract-malformed-base64":
		value := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(authority, []string{"approved_contract", "contract_bytes_base64"}))
		if !authorityHashValid {
			return fmt.Errorf("malformed approved-contract authority hash was not recomputed")
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(value); err == nil {
			return fmt.Errorf("approved-contract mutation is valid Base64")
		}
		return expectContains("Base64 decode")
	case "f4-approved-contract-valid-base64-wrong-value":
		value := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(authority, []string{"approved_contract", "contract_bytes_base64"}))
		approved, err := base64.StdEncoding.Strict().DecodeString(value)
		contractText := rootGrantsTrustVectorString(rootGrantsTrustVectorAt(root, []string{"review", "contract_bytes_base64"}))
		contract, contractErr := base64.StdEncoding.Strict().DecodeString(contractText)
		if err != nil || contractErr != nil || !authorityHashValid || bytes.Equal(approved, contract) {
			return fmt.Errorf("approved-contract mutation is not valid, independently altered Base64")
		}
		return expectContains("approved contract bytes/hash binding")
	default:
		return fmt.Errorf("no expected_check witness for request vector")
	}
}

func rootGrantsTrustVectorDigest(value *rootGrantsTrustVectorJSON) (string, error) {
	raw, err := rootGrantsTrustVectorCanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func rootGrantsTrustVectorHasMember(value *rootGrantsTrustVectorJSON, name string) bool {
	if value == nil || value.kind != '{' {
		return false
	}
	for _, member := range value.object {
		if member.name == name {
			return true
		}
	}
	return false
}

func rootGrantsTrustVectorString(value *rootGrantsTrustVectorJSON) string {
	if value == nil || value.kind != '"' {
		return ""
	}
	return value.text
}

func rootGrantsTrustVectorParseJSON(raw []byte) (*rootGrantsTrustVectorJSON, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := rootGrantsTrustVectorParseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON token")
		}
		return nil, err
	}
	return value, nil
}

func rootGrantsTrustVectorParseValue(decoder *json.Decoder) (*rootGrantsTrustVectorJSON, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			node := &rootGrantsTrustVectorJSON{kind: '{'}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object member name is not a string")
				}
				memberValue, err := rootGrantsTrustVectorParseValue(decoder)
				if err != nil {
					return nil, err
				}
				node.object = append(node.object, rootGrantsTrustVectorJSONMember{name: key, value: memberValue})
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated object")
			}
			return node, nil
		case '[':
			node := &rootGrantsTrustVectorJSON{kind: '['}
			for decoder.More() {
				item, err := rootGrantsTrustVectorParseValue(decoder)
				if err != nil {
					return nil, err
				}
				node.array = append(node.array, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated array")
			}
			return node, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	case string:
		return &rootGrantsTrustVectorJSON{kind: '"', text: value}, nil
	case json.Number:
		return &rootGrantsTrustVectorJSON{kind: 'n', number: value.String()}, nil
	case bool:
		return &rootGrantsTrustVectorJSON{kind: 'b', boolean: value}, nil
	case nil:
		return &rootGrantsTrustVectorJSON{kind: '0'}, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token %T", token)
	}
}

func rootGrantsTrustVectorCanonicalJSON(value *rootGrantsTrustVectorJSON) ([]byte, error) {
	var output bytes.Buffer
	var appendValue func(*rootGrantsTrustVectorJSON) error
	appendValue = func(node *rootGrantsTrustVectorJSON) error {
		if node == nil {
			return fmt.Errorf("nil JSON node")
		}
		switch node.kind {
		case '{':
			output.WriteByte('{')
			for index, member := range node.object {
				if index != 0 {
					output.WriteByte(',')
				}
				key, err := json.Marshal(member.name)
				if err != nil {
					return err
				}
				output.Write(key)
				output.WriteByte(':')
				if err := appendValue(member.value); err != nil {
					return err
				}
			}
			output.WriteByte('}')
		case '[':
			output.WriteByte('[')
			for index, item := range node.array {
				if index != 0 {
					output.WriteByte(',')
				}
				if err := appendValue(item); err != nil {
					return err
				}
			}
			output.WriteByte(']')
		case '"':
			encoded, err := json.Marshal(node.text)
			if err != nil {
				return err
			}
			output.Write(encoded)
		case 'n':
			value, err := strconv.ParseUint(node.number, 10, 64)
			if err != nil || strconv.FormatUint(value, 10) != node.number {
				return fmt.Errorf("number is not a canonical unsigned decimal")
			}
			output.WriteString(strconv.FormatUint(value, 10))
		case 'b':
			if node.boolean {
				output.WriteString("true")
			} else {
				output.WriteString("false")
			}
		case '0':
			output.WriteString("null")
		default:
			return fmt.Errorf("unknown JSON node kind")
		}
		return nil
	}
	if err := appendValue(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func rootGrantsTrustVectorApplyMutation(root *rootGrantsTrustVectorJSON, mutation rootGrantsTrustVectorR3Mutation) error {
	switch mutation.Op {
	case "replace_string":
		target := rootGrantsTrustVectorAt(root, mutation.Path)
		if target == nil || target.kind != '"' {
			return fmt.Errorf("replace target is not an existing string")
		}
		target.text = mutation.Value
	case "remove_member":
		target := rootGrantsTrustVectorAt(root, mutation.Path)
		if target == nil || target.kind != '{' {
			return fmt.Errorf("remove target is not an object")
		}
		found := -1
		for index, member := range target.object {
			if member.name == mutation.Member {
				if found != -1 {
					return fmt.Errorf("member name occurs more than once")
				}
				found = index
			}
		}
		if found == -1 {
			return fmt.Errorf("member to remove is missing")
		}
		target.object = append(target.object[:found], target.object[found+1:]...)
	case "recompute_sha256":
		source := rootGrantsTrustVectorAt(root, mutation.SourcePath)
		target := rootGrantsTrustVectorAt(root, mutation.Path)
		if source == nil || target == nil || target.kind != '"' {
			return fmt.Errorf("digest source or existing string target is missing")
		}
		canonical, err := rootGrantsTrustVectorCanonicalJSON(source)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(canonical)
		target.text = hex.EncodeToString(sum[:])
	default:
		return fmt.Errorf("unsupported mutation operation %q", mutation.Op)
	}
	return nil
}

func rootGrantsTrustVectorAt(root *rootGrantsTrustVectorJSON, path []string) *rootGrantsTrustVectorJSON {
	current := root
	for _, name := range path {
		if current == nil || current.kind != '{' {
			return nil
		}
		var found *rootGrantsTrustVectorJSON
		for _, member := range current.object {
			if member.name == name {
				if found != nil {
					return nil
				}
				found = member.value
			}
		}
		current = found
	}
	return current
}
