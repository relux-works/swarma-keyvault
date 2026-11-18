package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

type trustCountersignOperationHelper struct {
	calls     int
	request   []byte
	signature []byte
	err       error
}

func (h *trustCountersignOperationHelper) ReviewSignTrustContractCountersign(ctx context.Context, request []byte) ([]byte, error) {
	h.calls++
	h.request = bytes.Clone(request)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.err != nil {
		return nil, h.err
	}
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(request)
	if err != nil {
		return nil, err
	}
	defer data.clear()
	digest := sha256.Sum256(data.Contract)
	defer clear(digest[:])
	var secret [32]byte
	secret[31] = 3 // Public synthetic fixture scalar matching the fixture issuer key.
	defer clear(secret[:])
	signature, err := signNostrWithAux(secret[:], digest[:], [32]byte{})
	if err != nil {
		return nil, err
	}
	h.signature = bytes.Clone(signature)
	return signature, nil
}

func rootGrantsTrustCountersignOperationFixture(t *testing.T) (RootGrantsTrustContractCountersignRequest, []byte, RootGrantsSigningSnapshot) {
	t.Helper()
	f := grantV3FullFixture(t)
	contract, contractBytes := rootGrantsTrustContractFixture(t, f, []string{"instruct", "review"})
	defer clear(contractBytes)
	authority := rootGrantsTrustAuthorityV2ForContractFixture(t, f, contract, contractBytes)
	authority.Scope = []string{}
	authority.NotBefore = contract.NotBefore
	authority.NotAfter = contract.NotAfter
	authority.MaxGrantSeconds = contract.NotAfter - contract.NotBefore
	authorityJSON, err := json.Marshal(authority)
	if err != nil {
		t.Fatal("marshal synthetic authority/2", err)
	}
	metadata := rootGrantsRaw13(t, f.r)
	envelope, err := CanonicalRootGrantsEnvelope(rootGrantsEnvelopeFixture13(t, f.r), f.r)
	if err != nil {
		t.Fatal("marshal synthetic sealed envelope", err)
	}
	pairMetadata, _ := rootGrantsTestPair(t, "keyvault-recovery/2")
	issuance := RootGrantsTrustContractCountersignIssuanceContext{
		RootRecord: authority.Record, RootGeneration: int(authority.RootGeneration),
		LandlordName: authority.LandlordName, Network: authority.Network, Genesis: authority.Genesis,
		IssuerKey: authority.Record.PublicKey, AgentName: authority.AgentName, AgentKey: authority.AgentKey,
		GranteeKey: authority.GranteeKey, GranteeName: authority.GranteeName,
		NotBefore: authority.NotBefore, NotAfter: authority.NotAfter, MaxGrantSeconds: authority.MaxGrantSeconds,
		MaxBudgetSat: authority.MaxBudgetSat, Seal: authority.Seal,
		Actions: append([]string{}, contract.Actions...), Repos: append([]string{}, contract.Repos...),
		SpendBudget: contract.SpendBudget, DerivedV3Scope: []string{},
	}
	return RootGrantsTrustContractCountersignRequest{
		Address:        RootGrantsAddress{Service: f.r.Service, Version: f.r.Version},
		OwnerPrincipal: f.p.OwnerPrincipal, Contract: bytes.Clone(contractBytes),
		IssuanceContext: issuance,
	}, authorityJSON, RootGrantsSigningSnapshot{Metadata: metadata, Envelope: envelope, PairMetadata: pairMetadata}
}

func cloneTrustCountersignSnapshot(s RootGrantsSigningSnapshot) RootGrantsSigningSnapshot {
	return RootGrantsSigningSnapshot{Metadata: bytes.Clone(s.Metadata), Envelope: bytes.Clone(s.Envelope), PairMetadata: bytes.Clone(s.PairMetadata)}
}

// Claim: an agreed synthetic authority, exact trust contract, sealed snapshot, and helper signature produce a complete raw-contract receipt once; inputs remain caller-owned. The fixture does not exercise native vault custody or presence.
func TestRootGrantsTrustContractCountersignOperationReceipt(t *testing.T) {
	q, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
	contractBefore := bytes.Clone(q.Contract)
	actionsBefore := append([]string{}, q.IssuanceContext.Actions...)
	vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
	helper := &trustCountersignOperationHelper{}
	loaderCalls := 0
	got, err := rootGrantsTrustContractCountersignWith(context.Background(), q, func(address RootGrantsAddress) ([]byte, error) {
		loaderCalls++
		if address != q.Address {
			t.Fatal("fixed authority loader received another root address")
		}
		return bytes.Clone(authorityJSON), nil
	}, vault, helper)
	if err != nil {
		t.Fatal("eligible synthetic countersign refused", err)
	}
	contractHash := sha256.Sum256(q.Contract)
	if loaderCalls != 1 || vault.calls != 1 || helper.calls != 1 || vault.address != q.Address ||
		vault.digest != q.IssuanceContext.RootRecord.MetadataSHA256 {
		t.Fatal("operation did not load one fixed authority, one pinned snapshot, and one helper attempt")
	}
	if got.Schema != rootGrantsTrustContractCountersignReceiptSchema ||
		got.Operation != rootGrantsTrustContractCountersignOperation || got.ContractProfile != rootGrantsTrustContractProfile ||
		got.ContractSHA256 != hex.EncodeToString(contractHash[:]) || got.RootRecordSHA256 != q.IssuanceContext.RootRecord.MetadataSHA256 ||
		got.RootGeneration != q.IssuanceContext.RootGeneration || got.IssuerKey != q.IssuanceContext.IssuerKey ||
		got.Outcome != "signed" || len(got.LandlordSig) != 128 {
		t.Fatalf("receipt omitted or changed an agreed public binding: %#v", got)
	}
	if err := rootGrantsTrustContractVerifyRawSignature(q.Contract, got.IssuerKey, helper.signature); err != nil ||
		!bytes.Equal(q.Contract, contractBefore) || !equalStrings(q.IssuanceContext.Actions, actionsBefore) {
		t.Fatal("raw contract signature failed or caller-owned inputs changed", err)
	}
}

// Claim: wrong-owner binding and source, record-pin, and retained-pair refusals return an empty receipt before helper use; the adjacent valid fixture is accepted by the positive operation test.
func TestRootGrantsTrustContractCountersignOperationRefusals(t *testing.T) {
	for _, mode := range []string{"wrong-owner", "changed-approved-contract", "unreadable-authority", "changed-record-pin", "retained-record-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			q, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
			if mode == "wrong-owner" {
				q.OwnerPrincipal = "owner:id/other-owner"
			}
			vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
			helper := &trustCountersignOperationHelper{}
			calls := 0
			wantCode := "binding_mismatch"
			load := func(address RootGrantsAddress) ([]byte, error) {
				calls++
				if address != q.Address {
					t.Fatal("authority source was read for a different address")
				}
				switch mode {
				case "changed-approved-contract":
					wantCode = "CONTRACT_ENCODING"
					var authority rootGrantsTrustAuthorityV2
					if err := json.Unmarshal(authorityJSON, &authority); err != nil {
						t.Fatal(err)
					}
					authority.ApprovedContract.ContractBytesBase64 = "eA=="
					authority.ApprovedContract.ContractSHA256 = rootGrantsHashHex([]byte("x"))
					changed, err := json.Marshal(authority)
					if err != nil {
						t.Fatal(err)
					}
					return changed, nil
				case "unreadable-authority":
					wantCode = "operation_unavailable"
					return nil, errors.New("PRIVATE_TEST_DIAGNOSTIC")
				}
				return bytes.Clone(authorityJSON), nil
			}
			switch mode {
			case "changed-record-pin":
				vault.snapshot.Metadata = bytes.Clone(snapshot.Metadata)
				vault.snapshot.Metadata[len(vault.snapshot.Metadata)-2] ^= 1
				wantCode = "public_pin_mismatch"
			case "retained-record-mismatch":
				vault.snapshot.PairMetadata = []byte(`{}`)
				wantCode = "retained_record_mismatch"
			}
			got, err := rootGrantsTrustContractCountersignWith(context.Background(), q, load, vault, helper)
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Code != wantCode || failure.Outcome != "not_applied" ||
				got.Schema != "" || got.LandlordSig != "" || helper.calls != 0 {
				t.Fatalf("expected closed %s refusal without a receipt/helper call: %#v, %v", wantCode, got, err)
			}
			if calls != 1 || mode == "wrong-owner" && vault.calls != 0 ||
				mode == "unreadable-authority" && bytes.Contains([]byte(err.Error()), []byte("PRIVATE_TEST_DIAGNOSTIC")) {
				t.Fatal("refusal escaped the fixed source boundary or exposed source diagnostics")
			}
		})
	}
}

// Claim: canonical trust-contract refusal precedes issuance-context spend policy, and both local refusals occur before authority, vault, or helper effects.
func TestRootGrantsTrustContractCountersignLIPBeforeIssuanceContext(t *testing.T) {
	for _, tc := range []struct {
		name            string
		invalidContract bool
		invalidBudget   bool
		code            string
		phase           string
	}{
		{name: "invalid contract with valid context", invalidContract: true, code: "CONTRACT_ENCODING", phase: "contract_parse"},
		{name: "valid contract with invalid context", invalidBudget: true, code: "spend_not_authorized", phase: "authority"},
		{name: "invalid contract precedes invalid context", invalidContract: true, invalidBudget: true, code: "CONTRACT_ENCODING", phase: "contract_parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
			if tc.invalidContract {
				q.Contract = []byte("x")
			}
			if tc.invalidBudget {
				q.IssuanceContext.MaxBudgetSat = 1
			}
			contractBefore := bytes.Clone(q.Contract)
			contextBefore, err := json.Marshal(q.IssuanceContext)
			if err != nil {
				t.Fatal("could not snapshot synthetic issuance context", err)
			}
			vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
			helper := &trustCountersignOperationHelper{}
			loaderCalls := 0
			got, err := rootGrantsTrustContractCountersignWith(context.Background(), q, func(RootGrantsAddress) ([]byte, error) {
				loaderCalls++
				return bytes.Clone(authorityJSON), nil
			}, vault, helper)
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Code != tc.code || failure.Phase != tc.phase || failure.Outcome != "not_applied" ||
				rootGrantsTrustContractCountersignHelperStatusCode(failure.Code) != 13 ||
				got.Schema != "" || got.LandlordSig != "" || got.Outcome != "" || len(got.Actions) != 0 ||
				loaderCalls != 0 || vault.calls != 0 || helper.calls != 0 {
				t.Fatalf("local refusal=%#v, %v; want %s/%s/not_applied status 13 with no effects", failure, err, tc.code, tc.phase)
			}
			contextAfter, marshalErr := json.Marshal(q.IssuanceContext)
			if marshalErr != nil || !bytes.Equal(q.Contract, contractBefore) || !bytes.Equal(contextAfter, contextBefore) {
				t.Fatal("local refusal mutated caller-owned request bytes or context")
			}
		})
	}
}

func rootTrustCountersignSetContextJSONSize(t *testing.T, q *RootGrantsTrustContractCountersignRequest, want int, escaped bool) {
	t.Helper()
	base, err := json.Marshal(q.IssuanceContext)
	if err != nil {
		t.Fatal("could not encode the synthetic issuance context", err)
	}
	oldName, err := json.Marshal(q.IssuanceContext.AgentName)
	if err != nil {
		t.Fatal("could not encode the synthetic agent name", err)
	}
	bodyBytes := want - len(base) + len(oldName) - 2
	if bodyBytes < 0 {
		t.Fatal("requested context boundary is smaller than the fixed fixture")
	}
	if escaped {
		q.IssuanceContext.AgentName = strings.Repeat("\n", bodyBytes/2) + strings.Repeat("x", bodyBytes%2)
	} else {
		q.IssuanceContext.AgentName = strings.Repeat("x", bodyBytes)
	}
	encoded, err := json.Marshal(q.IssuanceContext)
	if err != nil || len(encoded) != want {
		t.Fatalf("synthetic context has %d bytes, want exactly %d (err=%v)", len(encoded), want, err)
	}
}

// Claim: typed context bounds count canonical JSON octets including escaped control bytes, and an oversized supplied context wins before a malformed LIP contract or any authority, vault, or helper effect.
func TestRootGrantsTrustContractCountersignTypedContextBoundPrecedence(t *testing.T) {
	for _, tc := range []struct {
		bytes   int
		escaped bool
		code    string
		phase   string
		status  int32
	}{
		{bytes: 32767, code: "CONTRACT_ENCODING", phase: "contract_parse", status: 13},
		{bytes: 32768, escaped: true, code: "CONTRACT_ENCODING", phase: "contract_parse", status: 13},
		{bytes: 32769, code: "limit_exceeded", phase: "preflight", status: 17},
	} {
		t.Run(strconv.Itoa(tc.bytes), func(t *testing.T) {
			q, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
			q.Contract = []byte("x")
			rootTrustCountersignSetContextJSONSize(t, &q, tc.bytes, tc.escaped)
			contractBefore := bytes.Clone(q.Contract)
			contextBefore, err := json.Marshal(q.IssuanceContext)
			if err != nil {
				t.Fatal("could not snapshot synthetic issuance context", err)
			}
			vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
			helper := &trustCountersignOperationHelper{}
			loaderCalls := 0
			got, err := rootGrantsTrustContractCountersignWith(context.Background(), q, func(RootGrantsAddress) ([]byte, error) {
				loaderCalls++
				return bytes.Clone(authorityJSON), nil
			}, vault, helper)
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Code != tc.code || failure.Phase != tc.phase || failure.Outcome != "not_applied" ||
				rootGrantsTrustContractCountersignHelperStatusCode(failure.Code) != tc.status ||
				got.Schema != "" || got.LandlordSig != "" || got.Outcome != "" || len(got.Actions) != 0 ||
				loaderCalls != 0 || vault.calls != 0 || helper.calls != 0 {
				t.Fatalf("boundary refusal=%#v, %v; want %s/%s/not_applied status %d with no effects", failure, err, tc.code, tc.phase, tc.status)
			}
			contextAfter, marshalErr := json.Marshal(q.IssuanceContext)
			if marshalErr != nil || !bytes.Equal(q.Contract, contractBefore) || !bytes.Equal(contextAfter, contextBefore) {
				t.Fatal("bounded local refusal mutated caller-owned contract or context")
			}
		})
	}
}

// Claim: exact source and snapshot bytes pass child recheck; changed authority, unreadable source, record pin, envelope, or retained pair refuse before signing.
func TestRootGrantsTrustContractCountersignRecheckRefusals(t *testing.T) {
	q, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
	helper := &trustCountersignOperationHelper{}
	_, err := rootGrantsTrustContractCountersignWith(context.Background(), q, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(authorityJSON), nil
	}, &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}, helper)
	if err != nil {
		t.Fatal("positive request fixture refused", err)
	}
	validVault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
	if err := rootGrantsTrustContractCountersignCheckForHelperWithClock(context.Background(), helper.request, validVault,
		func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authorityJSON), nil }, func() int64 { return 100 }); err != nil || validVault.calls != 1 {
		t.Fatal("unchanged fixed source and snapshot failed the positive recheck", err)
	}
	for _, mode := range []string{"changed-authority", "unreadable-authority", "changed-record-pin", "changed-envelope", "changed-retained-pair"} {
		t.Run(mode, func(t *testing.T) {
			vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
			load := func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authorityJSON), nil }
			wantCodes := []string{"binding_mismatch"}
			switch mode {
			case "changed-authority":
				load = func(RootGrantsAddress) ([]byte, error) { return []byte(`{}`), nil }
			case "unreadable-authority":
				load = func(RootGrantsAddress) ([]byte, error) { return nil, errors.New("PRIVATE_TEST_DIAGNOSTIC") }
				wantCodes = []string{"operation_unavailable"}
			case "changed-record-pin":
				vault.snapshot.Metadata = bytes.Clone(snapshot.Metadata)
				vault.snapshot.Metadata[len(vault.snapshot.Metadata)-2] ^= 1
				wantCodes = []string{"public_pin_mismatch"}
			case "changed-envelope":
				vault.snapshot.Envelope = bytes.Clone(snapshot.Envelope)
				vault.snapshot.Envelope[len(vault.snapshot.Envelope)-2] ^= 1
				wantCodes = []string{"binding_mismatch", "invalid_envelope"}
			case "changed-retained-pair":
				vault.snapshot.PairMetadata = []byte(`{}`)
				wantCodes = []string{"retained_record_mismatch"}
			}
			err := rootGrantsTrustContractCountersignCheckForHelperWithClock(context.Background(), helper.request, vault, load, func() int64 { return 100 })
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Outcome != "not_applied" || !containsString(wantCodes, failure.Code) {
				t.Fatalf("changed fixed-source state reached a valid recheck: %v", err)
			}
			if mode == "unreadable-authority" && bytes.Contains([]byte(err.Error()), []byte("PRIVATE_TEST_DIAGNOSTIC")) {
				t.Fatal("source diagnostic escaped")
			}
		})
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
