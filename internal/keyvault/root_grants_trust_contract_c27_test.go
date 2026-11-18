package keyvault

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/vectors/CONTRACT-27-CONTROLS.json
var rootGrantsTrustContractC27Controls []byte

type rootGrantsTrustContractC27Document struct {
	Schema            string                               `json:"schema"`
	ContractSHA256    string                               `json:"contract_sha256"`
	BaseRequestSHA256 string                               `json:"base_request_sha256"`
	BaseRequestBytes  int                                  `json:"base_request_bytes"`
	Requests          []rootGrantsTrustContractC27Request  `json:"requests"`
	Contracts         []rootGrantsTrustContractC27Contract `json:"contracts"`
}

type rootGrantsTrustContractC27Request struct {
	ID             string `json:"id"`
	Claim          string `json:"claim"`
	ExpectedStatus int32  `json:"expected_status"`
	RequestBase64  string `json:"request_base64"`
	RequestBytes   int    `json:"request_bytes"`
	RequestSHA256  string `json:"request_sha256"`
	Source         string `json:"source"`
	SourceSHA256   string `json:"source_sha256"`
}

type rootGrantsTrustContractC27Contract struct {
	ID           string `json:"id"`
	Claim        string `json:"claim"`
	Expected     string `json:"expected"`
	ExpectedRule int    `json:"expected_rule"`
	BytesBase64  string `json:"bytes_base64"`
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Source       string `json:"source"`
}

// Claim: all 60 exact request rows exercise the production helper parser and authority binder against the shared C27 status table, including source-pinned witnesses and paired precedence controls. This does not invoke signing, Keychain, or the Darwin executable.
func TestRootGrantsTrustContractC27ExactRequestControls(t *testing.T) {
	document := rootGrantsTrustContractC27Read(t)
	if len(document.Requests) != 64 {
		t.Fatalf("C27 request control count=%d, want 64", len(document.Requests))
	}
	seen := make(map[string]bool, len(document.Requests))
	for _, vector := range document.Requests {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			if vector.ID == "" || vector.Claim == "" || seen[vector.ID] {
				t.Fatalf("request row must have a unique id and claim: %q", vector.ID)
			}
			seen[vector.ID] = true
			raw, err := base64.StdEncoding.Strict().DecodeString(vector.RequestBase64)
			if err != nil || base64.StdEncoding.EncodeToString(raw) != vector.RequestBase64 {
				t.Fatalf("request Base64 is not canonical: %v", err)
			}
			if len(raw) != vector.RequestBytes || rootGrantsTrustContractC27SHA256(raw) != vector.RequestSHA256 {
				t.Fatalf("exact request byte/hash pin changed (claim: %s)", vector.Claim)
			}
			if vector.Source != "" && (vector.SourceSHA256 == "" || vector.RequestSHA256 != vector.SourceSHA256) {
				t.Fatalf("source witness pin mismatch: source=%s request=%s claim=%s",
					vector.Source, vector.RequestSHA256, vector.Claim)
			}

			data, parseErr := rootGrantsTrustContractCountersignParseHelperRequest(raw)
			if parseErr == nil {
				defer data.clear()
				var authority rootGrantsTrustAuthorityV2
				var binding RootGrantsTrustBinding
				authority, binding, parseErr = rootGrantsTrustContractCountersignBindHelperAuthority(&data)
				clear(authority.approvedContractBytes)
				clear(binding.ContractBytes)
				clear(binding.ScopeTextBytes)
			}
			if got := RootGrantsTrustContractCountersignHelperStatus(parseErr); got != vector.ExpectedStatus {
				t.Fatalf("status=%d, want %d (claim: %s; error: %v)", got, vector.ExpectedStatus, vector.Claim, parseErr)
			}
		})
	}
}

// Claim: the exact depth-65 LIP witness reaches Go's existing CONTRACT_DELEGATE rule 9, while the one-field valid-depth neighbor is accepted. This checks parser ownership, not a signing path.
func TestRootGrantsTrustContractC27DepthWitnessAndNeighbor(t *testing.T) {
	document := rootGrantsTrustContractC27Read(t)
	if len(document.Contracts) != 2 {
		t.Fatalf("C27 contract control count=%d, want 2", len(document.Contracts))
	}
	for _, vector := range document.Contracts {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			if vector.ID == "" || vector.Claim == "" {
				t.Fatal("contract row is missing id or claim")
			}
			raw, err := base64.StdEncoding.Strict().DecodeString(vector.BytesBase64)
			if err != nil || len(raw) != vector.Bytes || rootGrantsTrustContractC27SHA256(raw) != vector.SHA256 {
				t.Fatalf("exact contract byte/hash pin changed: %v", err)
			}
			_, parseErr := ParseRootGrantsTrustContract(raw)
			if vector.Expected == "ACCEPT" {
				if parseErr != nil || vector.ExpectedRule != 0 {
					t.Fatalf("neighbor was not accepted at rule 0: %v (claim: %s)", parseErr, vector.Claim)
				}
				return
			}
			var failure *RootGrantsTrustError
			if !errors.As(parseErr, &failure) || failure == nil || failure.Code != vector.Expected || failure.Rule != vector.ExpectedRule {
				t.Fatalf("contract refusal=%v, want %s rule %d (claim: %s)", parseErr, vector.Expected, vector.ExpectedRule, vector.Claim)
			}
		})
	}
}

func rootGrantsTrustContractC27Read(t *testing.T) rootGrantsTrustContractC27Document {
	t.Helper()
	const artifactSHA256 = "34491b440d32838f8a25c30cf64513e5871a6aec7edf39c5fe07b433bb0c2870"
	const contractSHA256 = "d3efe6fad933ee7077c3209b13e3a166ae243fa2cba6a33213be17c1306e7086"
	const baseSHA256 = "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea"
	if got := rootGrantsTrustContractC27SHA256(rootGrantsTrustContractC27Controls); got != artifactSHA256 {
		t.Fatalf("C27 control artifact SHA-256=%s, want %s", got, artifactSHA256)
	}
	var document rootGrantsTrustContractC27Document
	if err := json.Unmarshal(rootGrantsTrustContractC27Controls, &document); err != nil {
		t.Fatalf("decode C27 controls: %v", err)
	}
	if document.Schema != "keyvault-root-grants-contract-27-controls/1" ||
		document.ContractSHA256 != contractSHA256 || document.BaseRequestSHA256 != baseSHA256 || document.BaseRequestBytes != 8465 {
		t.Fatalf("C27 contract/base pins do not match the reviewed inputs: schema=%q contract=%s base=%s/%d",
			document.Schema, document.ContractSHA256, document.BaseRequestSHA256, document.BaseRequestBytes)
	}
	return document
}

func rootGrantsTrustContractC27SHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
