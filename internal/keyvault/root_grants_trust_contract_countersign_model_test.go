package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// This proves a generated software key signs the exact raw contract SHA-256 separately from the prefixed Grant v3 digest; it does not exercise authority, native presence, or actual keys.
func TestRootGrantsTrustContractSignatureUsesRawContractDigest(t *testing.T) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal("could not generate an in-memory synthetic test key")
	}
	issuerKey := hex.EncodeToString(schnorr.SerializePubKey(privateKey.PubKey()))
	contract := []byte(`{"profile":"swarma-trust-contract/2","synthetic":true}`)
	originalContract := bytes.Clone(contract)
	rawDigest := sha256.Sum256(contract)
	rawSignature, err := schnorr.Sign(privateKey, rawDigest[:])
	if err != nil {
		t.Fatal("could not produce the synthetic raw-contract signature")
	}
	rawSigBytes := rawSignature.Serialize()
	if err := rootGrantsTrustContractVerifyRawSignature(contract, issuerKey, rawSigBytes); err != nil {
		t.Fatalf("valid raw-contract signature was rejected: %v", err)
	}
	changedContract := append(bytes.Clone(contract), ' ')
	if err := rootGrantsTrustContractVerifyRawSignature(changedContract, issuerKey, rawSigBytes); err == nil {
		t.Fatal("signature for original contract octets was accepted after a byte change")
	}
	if rootGrantsVerifyGrantV3(contract, issuerKey, rawSigBytes) == nil {
		t.Fatal("raw-contract signature was accepted under the prefixed Grant v3 digest")
	}
	grantDigest, err := rootGrantsGrantV3Digest(contract)
	if err != nil {
		t.Fatal("could not compute synthetic Grant v3 digest")
	}
	grantSignature, err := schnorr.Sign(privateKey, grantDigest[:])
	if err != nil {
		t.Fatal("could not produce the synthetic Grant v3 signature")
	}
	grantSigBytes := grantSignature.Serialize()
	if rootGrantsVerifyGrantV3(contract, issuerKey, grantSigBytes) != nil {
		t.Fatal("valid prefixed Grant v3 signature was rejected")
	}
	if err := rootGrantsTrustContractVerifyRawSignature(contract, issuerKey, grantSigBytes); err == nil {
		t.Fatal("Grant v3 signature was accepted for the raw contract digest")
	}
	if err := rootGrantsTrustContractVerifyRawSignature(contract, "A"+issuerKey[1:], rawSigBytes); err == nil {
		t.Fatal("uppercase issuer key encoding was accepted")
	}
	otherPrivateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal("could not generate a second synthetic test key")
	}
	otherIssuerKey := hex.EncodeToString(schnorr.SerializePubKey(otherPrivateKey.PubKey()))
	if err := rootGrantsTrustContractVerifyRawSignature(contract, otherIssuerKey, rawSigBytes); err == nil {
		t.Fatal("signature verified under a different full issuer key")
	}
	if err := rootGrantsTrustContractVerifyRawSignature(contract, issuerKey, rawSigBytes[:63]); err == nil {
		t.Fatal("short signature was accepted")
	}
	if !bytes.Equal(contract, originalContract) {
		t.Fatal("raw signature verifier mutated caller-owned contract bytes")
	}
}

// This proves the public issuance context preserves its ordered closed JSON shape and rejects generation, issuer, scope, or no-spend binding mismatches; it does not validate installed authority.
func TestRootGrantsTrustContractCountersignIssuanceContextJSON(t *testing.T) {
	c := RootGrantsTrustContractCountersignIssuanceContext{
		RootRecord:      RootGrantsAuthorityRecord{Service: "svc", Version: 1, MetadataSHA256: "meta", PublicKey: "issuer", SealScript: "script"},
		RootGeneration:  1,
		LandlordName:    "landlord",
		Network:         "regtest",
		Genesis:         "genesis",
		IssuerKey:       "issuer",
		AgentName:       "agent",
		AgentKey:        "agent-key",
		GranteeKey:      "grantee-key",
		GranteeName:     "grantee",
		NotBefore:       2,
		NotAfter:        3,
		MaxGrantSeconds: 1,
		MaxBudgetSat:    0,
		Seal:            RootGrantsGrantPoint{TxID: "txid", Vout: 5},
		Actions:         []string{"instruct"},
		Repos:           []string{},
		SpendBudget:     0,
		DerivedV3Scope:  []string{},
	}
	want := []byte(`{"root_record":{"service":"svc","version":1,"metadata_sha256":"meta","public_key":"issuer","seal_script":"script"},"root_generation":1,"landlord_name":"landlord","network":"regtest","genesis":"genesis","issuer_key":"issuer","agent_name":"agent","agent_key":"agent-key","grantee_key":"grantee-key","grantee_name":"grantee","not_before":2,"not_after":3,"max_grant_seconds":1,"max_budget_sat":0,"seal":{"txid":"txid","vout":5},"actions":["instruct"],"repos":[],"spend_budget":0,"derived_v3_scope":[]}`)
	got, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("context did not serialize in the agreed order: %s err=%v", got, err)
	}
	clear(got)
	cases := []RootGrantsTrustContractCountersignIssuanceContext{c, c, c}
	cases[0].Actions = nil
	cases[1].Repos = nil
	cases[2].DerivedV3Scope = nil
	for i, invalid := range cases {
		if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(invalid); err == nil {
			t.Fatalf("nil context array %d was accepted", i)
		}
	}
	c.RootGeneration++
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err == nil {
		t.Fatal("root_generation mismatch was accepted")
	}
	c.RootGeneration--
	c.RootGeneration = int(^uint(0) >> 1)
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err == nil {
		t.Fatal("root_generation beyond the bound record version was accepted")
	}
	c.RootGeneration = int(c.RootRecord.Version)
	c.IssuerKey = "other-issuer"
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err == nil {
		t.Fatal("issuer key differing from the record key was accepted")
	}
	c.IssuerKey = c.RootRecord.PublicKey
	c.Actions = []string{"land"}
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err == nil {
		t.Fatal("caller-selected empty v3 scope for land was accepted")
	}
	c.DerivedV3Scope = []string{"repository.push"}
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err != nil {
		t.Fatalf("R1-derived land scope was rejected: %v", err)
	}
	c.Actions = []string{"review", "instruct"}
	c.DerivedV3Scope = []string{}
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err != nil {
		t.Fatalf("R1-derived empty trust-action scope was rejected: %v", err)
	}
	c.Actions = []string{"spend"}
	c.SpendBudget = 1
	c.DerivedV3Scope = []string{"pay"}
	if _, err := rootGrantsTrustContractCountersignIssuanceContextJSON(c); err == nil {
		t.Fatal("spend action was accepted by the no-spend countersign instance")
	}
}

// This proves R1 derives only repository.push for land and pay for spend, while trust-only actions create no Grant v3 scope.
func TestRootGrantsTrustContractCountersignDerivedV3Scope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actions []string
		want    []string
	}{
		{name: "instruct", actions: []string{"instruct"}, want: []string{}},
		{name: "land", actions: []string{"land"}, want: []string{"repository.push"}},
		{name: "review", actions: []string{"review"}, want: []string{}},
		{name: "mixed trust and land", actions: []string{"instruct", "land", "review"}, want: []string{"repository.push"}},
		{name: "land and spend sort", actions: []string{"land", "spend"}, want: []string{"pay", "repository.push"}},
	} {
		if got := rootGrantsTrustContractCountersignDerivedV3Scope(tc.actions); !slices.Equal(got, tc.want) {
			t.Errorf("derived scope for %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// This proves the request clone owns all mutable byte and slice inputs before parsing or helper use.
func TestRootGrantsTrustContractCountersignRequestCloneOwnsInputs(t *testing.T) {
	q := RootGrantsTrustContractCountersignRequest{
		Contract:  []byte("contract"),
		ScopeText: []byte("scope"),
		IssuanceContext: RootGrantsTrustContractCountersignIssuanceContext{
			Actions:        []string{"instruct"},
			Repos:          []string{"https://example.invalid/repo"},
			DerivedV3Scope: []string{"repository.push"},
		},
	}
	clone := rootGrantsTrustContractCountersignCloneRequest(q)
	q.Contract[0] = 'X'
	q.ScopeText[0] = 'X'
	q.IssuanceContext.Actions[0] = "spend"
	q.IssuanceContext.Repos[0] = "changed"
	q.IssuanceContext.DerivedV3Scope[0] = "changed"
	if string(clone.Contract) != "contract" || string(clone.ScopeText) != "scope" ||
		clone.IssuanceContext.Actions[0] != "instruct" || clone.IssuanceContext.Repos[0] != "https://example.invalid/repo" ||
		clone.IssuanceContext.DerivedV3Scope[0] != "repository.push" {
		t.Fatal("request clone retained caller-owned mutable storage")
	}
}

// This proves the request-size preflight admits a small valid-size control and refuses caller buffers or string arrays whose encoded lower bound already exceeds the existing helper limit.
func TestRootGrantsTrustContractCountersignInputBound(t *testing.T) {
	valid := RootGrantsTrustContractCountersignRequest{Contract: []byte("synthetic contract"), ScopeText: []byte{}}
	if !rootGrantsTrustContractCountersignInputsWithinBound(valid) {
		t.Fatal("small request was rejected by the pre-marshal lower bound")
	}
	tooLargeContract := valid
	tooLargeContract.Contract = make([]byte, 196609)
	if rootGrantsTrustContractCountersignInputsWithinBound(tooLargeContract) {
		t.Fatal("contract whose Base64 alone exceeds the helper limit passed the preflight")
	}
	tooLargeScope := valid
	tooLargeScope.ScopeText = make([]byte, 196609)
	if rootGrantsTrustContractCountersignInputsWithinBound(tooLargeScope) {
		t.Fatal("scope text whose Base64 alone exceeds the helper limit passed the preflight")
	}
	tooManyValues := valid
	tooManyValues.IssuanceContext.Actions = make([]string, 87382)
	if rootGrantsTrustContractCountersignInputsWithinBound(tooManyValues) {
		t.Fatal("string-array JSON lower bound beyond the helper limit passed the preflight")
	}
}

// This proves cloning preserves the absent-versus-empty ScopeText distinction while retaining independent byte storage.
func TestRootGrantsTrustContractCountersignScopeTextClonePreservesPresence(t *testing.T) {
	absent := rootGrantsTrustContractCountersignCloneRequest(RootGrantsTrustContractCountersignRequest{})
	if absent.ScopeText != nil {
		t.Fatal("absent scope text became present during cloning")
	}
	presentEmpty := rootGrantsTrustContractCountersignCloneRequest(RootGrantsTrustContractCountersignRequest{ScopeText: []byte{}})
	if presentEmpty.ScopeText == nil || len(presentEmpty.ScopeText) != 0 {
		t.Fatal("present empty scope text became absent during cloning")
	}
	present := RootGrantsTrustContractCountersignRequest{ScopeText: []byte("scope")}
	clone := rootGrantsTrustContractCountersignCloneRequest(present)
	clone.ScopeText[0] = 'S'
	if string(present.ScopeText) != "scope" || string(clone.ScopeText) != "Scope" {
		t.Fatal("nonempty scope text clone aliases caller-owned bytes")
	}
}

// This proves countersign uses the existing closed outer helper envelope and enforces its full-request bound; it does not parse or validate the purpose-specific inner review.
func TestRootGrantsTrustContractCountersignHelperRequestEnvelope(t *testing.T) {
	got, err := rootGrantsTrustContractCountersignHelperRequest([]byte(`{"review":"ok"}`), []byte(`{"item":"public"}`), []byte{0xab, 0xcd})
	want := []byte(`{"schema":"keyvault-root-grants-sign-request/2","operation":"review-sign-trust-contract-countersign","review":{"review":"ok"},"envelope":{"item":"public"},"pair_metadata":"abcd"}`)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("helper request changed the agreed C1 envelope: %s err=%v", got, err)
	}
	if _, err := rootGrantsTrustContractCountersignHelperRequest(nil, []byte(`{}`), []byte{1}); err == nil {
		t.Fatal("missing review was accepted")
	}
	largeReview := append([]byte(`"`), bytes.Repeat([]byte{'x'}, 262145)...)
	largeReview = append(largeReview, '"')
	_, err = rootGrantsTrustContractCountersignHelperRequest(largeReview, []byte(`{}`), []byte{1})
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure.Code != "limit_exceeded" || failure.Outcome != "not_applied" {
		t.Fatalf("oversized complete request did not fail closed before helper start: %v", err)
	}
}

// This proves only the accepted pre-sign semantic/error classes map to existing statuses; malformed and uncertain outcomes keep the existing UNKNOWN status control.
func TestRootGrantsTrustContractCountersignHelperStatusMap(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int32
	}{
		{code: "invalid_arguments", want: 1},
		{code: "terminal_required", want: 2},
		{code: "invalid_word_number", want: 3},
		{code: "invalid_word_count", want: 4},
		{code: "invalid_mnemonic", want: 5},
		{code: "invalid_checksum", want: 6},
		{code: "invalid_derivation", want: 7},
		{code: "retained_record_mismatch", want: 8},
		{code: "public_pin_mismatch", want: 9},
		{code: "operation_unavailable", want: 10},
		{code: "wrapping_policy_refused", want: 11},
		{code: "invalid_envelope", want: 12},
		{code: "CONTRACT_ACTIONS", want: 13},
		{code: "CONTRACT_PROFILE", want: 13},
		{code: "binding_mismatch", want: 13},
		{code: "scope_text_hash_mismatch", want: 13},
		{code: "canceled", want: 14},
		{code: "timeout", want: 15},
		{code: "private_protocol_error", want: 16},
		{code: "limit_exceeded", want: 17},
		{code: "unsupported_version", want: 18},
		{code: "unsupported_operation", want: 19},
		{code: "input_canceled", want: 20},
		{code: "code_not_admitted", want: 21},
		{code: "acl_refused", want: 22},
		{code: "lock_unavailable", want: 23},
		{code: "inventory_changed", want: 24},
		{code: "unclassified", want: 16},
	} {
		if got := rootGrantsTrustContractCountersignHelperStatusCode(tc.code); got != tc.want {
			t.Errorf("status(%q)=%d, want %d", tc.code, got, tc.want)
		}
	}
	control := rootGrantsTrustContractCountersignControlResponse(&RootGrantsGrantV3Failure{Code: "CONTRACT_ACTIONS"})
	if want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 13)); !bytes.Equal(control, want) {
		t.Fatalf("known semantic refusal control changed wire shape: %x", control)
	}
	parserControl := rootGrantsTrustContractCountersignControlResponse(&RootGrantsTrustError{Code: "CONTRACT_ACTIONS", Rule: 4})
	if want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 13)); !bytes.Equal(parserControl, want) {
		t.Fatalf("accepted A parser code did not coarsen to the existing local-LIP status: %x", parserControl)
	}
	unknown := rootGrantsTrustContractCountersignControlResponse(&RootGrantsGrantV3Failure{Code: "private_protocol_error"})
	if want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 16)); !bytes.Equal(unknown, want) {
		t.Fatalf("uncertain refusal did not stay UNKNOWN: %x", unknown)
	}
	unknownSemantic := rootGrantsTrustContractCountersignControlResponse(&RootGrantsGrantV3Failure{Code: "CONTRACT_ACTIONS", Outcome: "unknown"})
	if want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 16)); !bytes.Equal(unknownSemantic, want) {
		t.Fatalf("uncertain semantic code was incorrectly coarsened to status 13: %x", unknownSemantic)
	}
}

// This proves the exported native classifier preserves only closed existing statuses and coarsens malformed or uncertain semantic failures to UNKNOWN.
func TestRootGrantsTrustContractCountersignExportedHelperStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int32
	}{
		{name: "success", err: nil, want: 0},
		{name: "known binding refusal", err: &RootGrantsGrantV3Failure{Code: "binding_mismatch", Outcome: "not_applied"}, want: 13},
		{name: "malformed carrier", err: &RootGrantsGrantV3Failure{Code: "private_protocol_error", Outcome: "unknown"}, want: 16},
		{name: "uncertain semantic", err: &RootGrantsGrantV3Failure{Code: "CONTRACT_ACTIONS", Outcome: "unknown"}, want: 16},
		{name: "cancel after attempt", err: &RootGrantsGrantV3Failure{Code: "canceled", Outcome: "unknown"}, want: 14},
		{name: "deadline after attempt", err: &RootGrantsGrantV3Failure{Code: "timeout", Outcome: "unknown"}, want: 15},
		{name: "cancel before attempt", err: rootGrantsTrustContractCountersignFailed("canceled", "preflight", false), want: 14},
		{name: "deadline before attempt", err: rootGrantsTrustContractCountersignFailed("timeout", "preflight", false), want: 15},
		{name: "unclassified", err: errors.New("unclassified failure"), want: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RootGrantsTrustContractCountersignHelperStatus(tc.err); got != tc.want {
				t.Fatalf("native status=%d, want %d", got, tc.want)
			}
		})
	}
}

// This proves cancellation and deadline failures remain UNKNOWN even when they happen before helper start.
func TestRootGrantsTrustContractCountersignCancelAndTimeoutAreUnknown(t *testing.T) {
	for _, code := range []string{"canceled", "timeout", "private_protocol_error", "unclassified"} {
		failure, ok := rootGrantsTrustContractCountersignFailed(code, "preflight", false).(*RootGrantsGrantV3Failure)
		if !ok || failure.Outcome != "unknown" {
			t.Fatalf("preflight %s outcome=%v, want unknown", code, failure)
		}
	}
}

// This proves local semantic refusals are not_applied, while malformed, cancellation, timeout, and post-attempt uncertainty stay UNKNOWN.
func TestRootGrantsGrantV3FailureOutcomeByClassAndAttempt(t *testing.T) {
	for _, tc := range []struct {
		code      string
		attempted bool
		want      string
	}{
		{code: "private_protocol_error", attempted: false, want: "unknown"},
		{code: "canceled", attempted: false, want: "unknown"},
		{code: "timeout", attempted: false, want: "unknown"},
		{code: "signature_verification_failed", attempted: true, want: "unknown"},
		{code: "private_protocol_error", attempted: true, want: "unknown"},
		{code: "canceled", attempted: true, want: "unknown"},
		{code: "timeout", attempted: true, want: "unknown"},
	} {
		err := rootGrantsTrustContractCountersignFailed(tc.code, "preflight", tc.attempted)
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Outcome != tc.want {
			t.Errorf("failure(%q, attempted=%v) outcome=%v, want %q", tc.code, tc.attempted, failure, tc.want)
		}
	}
}

// This proves completed native refusals preserve only the existing codes and keep 14–16 uncertain after one attempted child exchange.
func TestRootGrantsTrustContractCountersignCompletedNativeRefusalMap(t *testing.T) {
	for code := uint32(1); code <= 24; code++ {
		err := rootGrantsTrustContractCountersignHelperRefusalFailure(code)
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure == nil {
			t.Fatalf("status %d did not produce a typed refusal", code)
		}
		wantOutcome := "not_applied"
		if code == 14 || code == 15 || code == 16 {
			wantOutcome = "unknown"
		}
		if failure.Outcome != wantOutcome || rootGrantsTrustContractCountersignHelperStatusCode(failure.Code) != int32(code) {
			t.Errorf("status %d became code=%q outcome=%q; want outcome=%q", code, failure.Code, failure.Outcome, wantOutcome)
		}
		control := rootGrantsTrustContractCountersignControlResponse(err)
		want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, code))
		if !bytes.Equal(control, want) {
			t.Errorf("completed refusal %d returned a different parent control frame: %x", code, control)
		}
	}
	unknownSemantic := rootGrantsTrustContractCountersignControlResponse(&RootGrantsGrantV3Failure{
		Code: "binding_mismatch", Phase: "verify", Outcome: "unknown",
	})
	if want := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 16)); !bytes.Equal(unknownSemantic, want) {
		t.Fatalf("uncertain Grant failure was incorrectly downgraded to semantic status 13: %x", unknownSemantic)
	}
}

// Claim: each nested, review, and complete-payload byte predicate accepts its inclusive maximum and rejects exactly one byte above it; these isolated checks do not claim every padded object is semantically valid.
func TestRootGrantsTrustContractCountersignJSONSizeBoundaries(t *testing.T) {
	for _, field := range []string{"issuance", "authority", "record"} {
		for _, tc := range []struct {
			bytes int
			want  bool
		}{{32767, true}, {32768, true}, {32769, false}} {
			sizes := rootGrantsTrustContractCountersignJSONSizes{}
			switch field {
			case "issuance":
				sizes.issuance = tc.bytes
			case "authority":
				sizes.authority = tc.bytes
			case "record":
				sizes.record = tc.bytes
			}
			if got := rootGrantsTrustContractCountersignJSONSizesWithinBound(sizes); got != tc.want {
				t.Errorf("%s size %d accepted=%v, want %v", field, tc.bytes, got, tc.want)
			}
		}
	}
	for _, field := range []string{"review", "payload"} {
		for _, tc := range []struct {
			bytes int
			want  bool
		}{{262143, true}, {262144, true}, {262145, false}} {
			sizes := rootGrantsTrustContractCountersignJSONSizes{}
			if field == "review" {
				sizes.review = tc.bytes
			} else {
				sizes.payload = tc.bytes
			}
			if got := rootGrantsTrustContractCountersignJSONSizesWithinBound(sizes); got != tc.want {
				t.Errorf("%s size %d accepted=%v, want %v", field, tc.bytes, got, tc.want)
			}
		}
	}
	if rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{
		issuance: 32768, authority: 32768, record: 32768, review: 262144, payload: 262145,
	}) {
		t.Fatal("individually bounded nested objects were allowed to exceed the complete payload limit")
	}
}
