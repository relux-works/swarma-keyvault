package keyvault

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"testing"
)

//go:embed testdata/vectors/SHARED-CARRIER-VECTORS-22.json
var rootTrustCarrierVectors22 []byte

// Claim: the SAME fixed canonical bytes intended for both language parsers
// produce the independently agreed carrier/LIP/pin verdicts (BOTH-SIDES22 rows
// 0-7) through Go's production request parser and authority binder. Per-row
// claims in the artifact distinguish each boundary. This executes no native code.
func TestRootGrantsTrustContractCarrierVectors22(t *testing.T) {
	if rootGrantsHashHex(rootTrustCarrierVectors22) != "cb85e9c1520634808a29c8b7c8f3eda0825eef861a3174275f5f9f7d9b4f2758" {
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
	if doc.Schema != "keyvault-root-grants-carrier-byte-vectors/1" || doc.Source != "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea" || len(doc.Vectors) != 13 {
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
