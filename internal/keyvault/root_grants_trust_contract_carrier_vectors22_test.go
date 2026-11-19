package keyvault

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

//go:embed testdata/vectors/SHARED-CARRIER-VECTORS-22.json
var rootTrustCarrierVectors22 []byte

// Claim: the SAME fixed canonical bytes intended for both language parsers
// produce the independently agreed carrier/LIP/pin verdicts (BOTH-SIDES22 rows
// 0-7) through Go's production request parser and authority binder. Per-row
// claims in the artifact distinguish each boundary. This executes no native code.
func TestRootGrantsTrustContractCarrierVectors22(t *testing.T) {
	if rootGrantsHashHex(rootTrustCarrierVectors22) != "1d272bcd9bc5865c3c84923366ec96e1b58f06b8bb110e29b1f1b2af9c36611b" {
		t.Fatal("fixed shared byte artifact changed")
	}
	var doc struct {
		Schema  string `json:"schema"`
		Source  string `json:"source_fixture_sha256"`
		Vectors []struct {
			ID     string `json:"id"`
			Bytes  string `json:"request_base64"`
			SHA256 string `json:"request_sha256"`
			Count  int    `json:"request_bytes"`
			Status int32  `json:"expected_status"`
			Code   string `json:"expected_code"`
			Row    int    `json:"accepted_row"`
			Claim  string `json:"claim"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(rootTrustCarrierVectors22, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "keyvault-root-grants-carrier-byte-vectors/1" || doc.Source != "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea" || len(doc.Vectors) != 17 {
		t.Fatal("unexpected shared artifact schema/source/count")
	}
	seen := map[string]bool{}
	for _, v := range doc.Vectors {
		if seen[v.ID] || v.ID == "" || v.Claim == "" {
			t.Fatal("missing/duplicate vector metadata")
		}
		seen[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			raw, err := base64.StdEncoding.Strict().DecodeString(v.Bytes)
			if err != nil || base64.StdEncoding.EncodeToString(raw) != v.Bytes || len(raw) != v.Count || rootGrantsHashHex(raw) != v.SHA256 {
				t.Fatal("fixed byte seal mismatch")
			}
			before := bytes.Clone(raw)
			data, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
			if err == nil {
				authority, binding, bindErr := rootGrantsTrustContractCountersignBindHelperAuthority(&data)
				err = bindErr
				clear(authority.approvedContractBytes)
				clear(binding.ContractBytes)
				clear(binding.ScopeTextBytes)
				data.clear()
			}
			code := "success"
			outcome := ""
			if err != nil {
				code, _ = rootGrantsTrustVectorFailure(err)
				if f, ok := err.(*RootGrantsGrantV3Failure); ok {
					outcome = f.Outcome
				}
			}
			status := RootGrantsTrustContractCountersignHelperStatus(err)
			if code != v.Code || status != v.Status || !bytes.Equal(raw, before) {
				t.Fatalf("row%d expected=%s/%d got=%s/%d; request unchanged=%v", v.Row, v.Code, v.Status, code, status, bytes.Equal(raw, before))
			}
			if v.Status != 0 {
				want := "not_applied"
				if v.Status == 16 {
					want = "unknown"
				}
				if outcome != want {
					t.Fatalf("outcome=%q want=%q", outcome, want)
				}
			}
			t.Logf("row=%d status=%d code=%s request_sha256=%s", v.Row, status, code, v.SHA256)
		})
	}
}

// Claim: four complete shared requests have fresh contract/approved-contract/authority
// pins before public parsing; exact empty/nonempty scopes bind and wrong empty
// bytes refuse scope_text_hash_mismatch/13/not_applied. No private path is invoked.
func TestRootGrantsTrustContractScopePresenceCompleteRequests(t *testing.T) {
	nativeBytes, err := os.ReadFile("../../cmd/mac-keyvault-enclave/testdata/SHARED-CARRIER-VECTORS-22.json")
	if err != nil || !bytes.Equal(nativeBytes, rootTrustCarrierVectors22) {
		t.Fatal("Go and native complete fixture artifacts differ")
	}
	var doc struct {
		Vectors []struct {
			ID            string `json:"id"`
			RequestBase64 string `json:"request_base64"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(rootTrustCarrierVectors22, &doc); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		text     string
		present  bool
		hashText string
		status   int32
	}{
		"scope-absent-empty":     {},
		"scope-present-empty":    {present: true},
		"scope-present-nonempty": {text: "synthetic scope", present: true, hashText: "synthetic scope"},
		"scope-empty-wrong-hash": {present: true, hashText: "synthetic scope", status: 13},
	}
	seen := map[string]bool{}
	for _, v := range doc.Vectors {
		want, ok := cases[v.ID]
		if !ok {
			continue
		}
		if seen[v.ID] {
			t.Fatalf("duplicate complete scope case %s", v.ID)
		}
		seen[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			raw, err := rootGrantsTrustContractCountersignDecodeBase64(v.RequestBase64)
			if err != nil {
				t.Fatal(err)
			}
			var outer rootGrantsGrantV3HelperRequest
			if err := DecodeSingleJSON(raw, &outer); err != nil {
				t.Fatal(err)
			}
			var review rootGrantsTrustContractCountersignReviewWire
			if err := DecodeSingleJSON(outer.Review, &review); err != nil {
				t.Fatal(err)
			}
			contract, err := rootGrantsTrustContractCountersignDecodeBase64(review.ContractBase64)
			if err != nil {
				t.Fatal(err)
			}
			model, err := ParseRootGrantsTrustContract(contract)
			if err != nil {
				t.Fatal(err)
			}
			scopeHash := ""
			if want.present {
				scopeHash = rootGrantsHashHex([]byte(want.hashText))
			}
			if len(contract) != review.ContractBytes || rootGrantsHashHex(contract) != review.ContractSHA256 ||
				model.ScopeTextSHA256 != scopeHash || review.ScopeTextSHA256 != scopeHash ||
				review.ScopeTextBase64 != base64.StdEncoding.EncodeToString([]byte(want.text)) || review.ScopeTextBytes != len(want.text) {
				t.Fatal("stale contract/scope pins can mask presence verdict")
			}
			authority, err := rootGrantsParseTrustAuthorityV2(review.AuthorityJSON)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(authority.approvedContractBytes)
			if !bytes.Equal(authority.approvedContractBytes, contract) ||
				authority.ApprovedContract.ContractSHA256 != review.ContractSHA256 ||
				rootGrantsHashHex(review.AuthorityJSON) != review.AuthoritySHA256 ||
				rootGrantsHashHex(review.RecordJSON) != review.RecordSHA256 {
				t.Fatal("stale approved-contract/authority/record pins can mask presence verdict")
			}
			original := bytes.Clone(raw)
			parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
			if want.status == 13 {
				var failure *RootGrantsGrantV3Failure
				if !errors.As(err, &failure) || failure.Code != "scope_text_hash_mismatch" ||
					failure.Outcome != "not_applied" || failure.Phase != "contract_parse" ||
					RootGrantsTrustContractCountersignHelperStatus(err) != 13 || len(parsed.Contract) != 0 {
					t.Fatalf("scope must refuse during public parsing, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer parsed.clear()
				if parsed.ScopeTextAvailable != want.present || !bytes.Equal(parsed.ScopeText, []byte(want.text)) {
					t.Fatal("scope presence/bytes changed during parsing")
				}
				boundAuthority, binding, err := rootGrantsTrustContractCountersignBindHelperAuthority(&parsed)
				defer clear(boundAuthority.approvedContractBytes)
				defer clear(binding.ContractBytes)
				defer clear(binding.ScopeTextBytes)
				if err != nil {
					t.Fatal(err)
				}
				state := RootGrantsTrustScopeTextNone
				if want.present {
					state = RootGrantsTrustScopeTextPresent
				}
				if binding.ScopeTextState != state || binding.ScopeTextSHA256 != scopeHash {
					t.Fatal("authority binding lost scope presence")
				}
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("public request was mutated")
			}
		})
	}
	if len(seen) != len(cases) {
		t.Fatal("missing complete scope request control")
	}
}
