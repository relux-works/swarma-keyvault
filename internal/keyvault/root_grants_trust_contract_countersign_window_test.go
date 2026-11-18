package keyvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func trustCountersignWindowFixture(t *testing.T, before, after, max int64) (RootGrantsTrustContractCountersignRequest, []byte, RootGrantsSigningSnapshot) {
	t.Helper()
	q, raw, snapshot := rootGrantsTrustCountersignOperationFixture(t)
	var authority rootGrantsTrustAuthorityV2
	if err := json.Unmarshal(raw, &authority); err != nil {
		t.Fatal(err)
	}
	authority.NotBefore, authority.NotAfter, authority.MaxGrantSeconds = before, after, max
	q.IssuanceContext.NotBefore, q.IssuanceContext.NotAfter, q.IssuanceContext.MaxGrantSeconds = before, after, max
	raw, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	return q, raw, snapshot
}

func trustCountersignWindowRun(t *testing.T, q RootGrantsTrustContractCountersignRequest, raw []byte, snapshot RootGrantsSigningSnapshot) (RootGrantsTrustContractCountersignReceipt, error, int, int, int) {
	t.Helper()
	vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
	helper := &trustCountersignOperationHelper{}
	loads := 0
	got, err := rootGrantsTrustContractCountersignWith(context.Background(), q, func(address RootGrantsAddress) ([]byte, error) {
		loads++
		if address != q.Address {
			t.Fatal("authority loader received a different address")
		}
		return bytes.Clone(raw), nil
	}, vault, helper)
	return got, err, loads, vault.calls, helper.calls
}

// Claim: equal, containing, one-sided touching windows and an exact duration cap
// reach one verified synthetic signature with exactly the signed contract window.
// These fixtures exercise no native custody or owner credentials.
func TestRootGrantsTrustContractCountersignOperationContainedWindow(t *testing.T) {
	for _, tc := range []struct {
		name               string
		before, after, max int64
	}{
		{"equal", 100, 1000, 900},
		{"strictly-containing", 0, 2000, 1000},
		{"touch-start", 100, 2000, 1000},
		{"touch-end", 0, 1000, 1000},
		{"duration-at-cap", 0, 2000, 900},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, raw, snapshot := trustCountersignWindowFixture(t, tc.before, tc.after, tc.max)
			before := bytes.Clone(q.Contract)
			got, err, loads, reads, signs := trustCountersignWindowRun(t, q, raw, snapshot)
			if err != nil || got.Outcome != "signed" || len(got.LandlordSig) != 128 || loads != 1 || reads != 1 || signs != 1 {
				t.Fatalf("contained window: err=%v outcome=%q loads=%d reads=%d signs=%d", err, got.Outcome, loads, reads, signs)
			}
			if got.NotBefore != 100 || got.NotAfter != 1000 {
				t.Fatalf("receipt window = %d..%d; want signed contract 100..1000 (authority %d..%d)", got.NotBefore, got.NotAfter, tc.before, tc.after)
			}
			sig, err := hex.DecodeString(got.LandlordSig)
			if err != nil || rootGrantsTrustContractVerifyRawSignature(q.Contract, got.IssuerKey, sig) != nil || !bytes.Equal(before, q.Contract) {
				t.Fatal("signature or caller-owned contract changed")
			}
		})
	}
}

// Claim: the unchanged normative raw carrier reaches a verified synthetic
// receipt whose window is exactly the signed contract, not the wider authority.
func TestRootGrantsTrustContractCountersignOperationOriginalCarrierWindow(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors/root-grants-sign-request-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if rootGrantsHashHex(raw) != "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea" {
		t.Fatal("normative raw carrier changed")
	}
	var wire struct {
		Review struct {
			Contract  string                                            `json:"contract_bytes_base64"`
			Issuance  RootGrantsTrustContractCountersignIssuanceContext `json:"issuance_context"`
			Authority json.RawMessage                                   `json:"authority"`
			Record    json.RawMessage                                   `json:"record"`
		} `json:"review"`
		Envelope json.RawMessage `json:"envelope"`
		Pair     string          `json:"pair_metadata"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	contract, err := base64.StdEncoding.Strict().DecodeString(wire.Review.Contract)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := hex.DecodeString(wire.Pair)
	if err != nil {
		t.Fatal(err)
	}
	var authority rootGrantsTrustAuthorityV2
	if err := json.Unmarshal(wire.Review.Authority, &authority); err != nil {
		t.Fatal(err)
	}
	q := RootGrantsTrustContractCountersignRequest{
		Address:        RootGrantsAddress{Service: wire.Review.Issuance.RootRecord.Service, Version: wire.Review.Issuance.RootRecord.Version},
		OwnerPrincipal: authority.OwnerPrincipal, Contract: contract, IssuanceContext: wire.Review.Issuance,
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: wire.Review.Record, Envelope: wire.Envelope, PairMetadata: pair}
	got, err, loads, reads, signs := trustCountersignWindowRun(t, q, wire.Review.Authority, snapshot)
	if err != nil || got.Outcome != "signed" || len(got.LandlordSig) != 128 || loads != 1 || reads != 1 || signs != 1 {
		t.Fatalf("original carrier: err=%v outcome=%q loads=%d reads=%d signs=%d", err, got.Outcome, loads, reads, signs)
	}
	if got.NotBefore != 1900000000 || got.NotAfter != 1900000100 {
		t.Fatalf("receipt window = %d..%d; want signed contract 1900000000..1900000100 (authority 1599999980..4102445800)", got.NotBefore, got.NotAfter)
	}
	sig, err := hex.DecodeString(got.LandlordSig)
	if err != nil || rootGrantsTrustContractVerifyRawSignature(contract, got.IssuerKey, sig) != nil {
		t.Fatal("original carrier signature does not verify against the signed contract")
	}
}

// Claim: one-second escapes/duration overflow and mismatched context fields
// still refuse with the exact binding error, zero receipt and no vault/helper
// use. A contained positive control is exercised alongside these neighbors.
func TestRootGrantsTrustContractCountersignOperationWindowRefusals(t *testing.T) {
	for _, mode := range []string{"start-escape", "end-escape", "duration-over-cap", "authority-window", "authority-duration", "landlord", "agent", "grantee", "actions", "repos"} {
		t.Run(mode, func(t *testing.T) {
			q, raw, snapshot := trustCountersignWindowFixture(t, 0, 2000, 1000)
			wantLoads := 0
			switch mode {
			case "start-escape":
				q, raw, snapshot = trustCountersignWindowFixture(t, 101, 2000, 1000)
			case "end-escape":
				q, raw, snapshot = trustCountersignWindowFixture(t, 0, 999, 900)
			case "duration-over-cap":
				q, raw, snapshot = trustCountersignWindowFixture(t, 0, 2000, 899)
			case "authority-window":
				q.IssuanceContext.NotBefore = 1
				wantLoads = 1
			case "authority-duration":
				q.IssuanceContext.MaxGrantSeconds = 999
				wantLoads = 1
			case "landlord":
				q.IssuanceContext.LandlordName = "other-owner"
			case "agent":
				q.IssuanceContext.AgentName = "other-agent"
			case "grantee":
				q.IssuanceContext.GranteeKey = q.IssuanceContext.IssuerKey
			case "actions":
				q.IssuanceContext.Actions = []string{"instruct"}
			case "repos":
				q.IssuanceContext.Repos = []string{"other/repo"}
			}
			got, err, loads, reads, signs := trustCountersignWindowRun(t, q, raw, snapshot)
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Code != "binding_mismatch" || failure.Phase != "authority" || failure.Outcome != "not_applied" ||
				!reflect.DeepEqual(got, RootGrantsTrustContractCountersignReceipt{}) || loads != wantLoads || reads != 0 || signs != 0 {
				t.Fatalf("%s: err=%v loads=%d reads=%d signs=%d receipt=%#v", mode, err, loads, reads, signs, got)
			}
		})
	}
}
