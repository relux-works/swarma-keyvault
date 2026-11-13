package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// RootGrantsGrantV3SignRequest contains public document bytes and an explicit
// existing root address. It carries no caller-selected policy path, digest,
// approval bit, scalar or helper option.
type RootGrantsGrantV3SignRequest struct {
	Address        RootGrantsAddress
	OwnerPrincipal string
	Grant          []byte
	Contract       []byte
}

// RootGrantsGrantV3SigningHelper is the private helper process boundary. The
// only successful output is a raw, verified-length BIP-340 signature.
type RootGrantsGrantV3SigningHelper interface {
	ReviewSignGrantV3(context.Context, []byte) ([]byte, error)
}

// RootGrantsGrantV3SignatureReceipt contains public binding facts and the
// lowercase raw signature. No sealed envelope or private value is included.
type RootGrantsGrantV3SignatureReceipt struct {
	Schema               string `json:"schema"`
	Operation            string `json:"operation"`
	Profile              string `json:"profile"`
	ObservationPolicy    string `json:"observation_policy"`
	OwnerPrincipal       string `json:"owner_principal"`
	RecordService        string `json:"record_service"`
	RecordVersion        int    `json:"record_version"`
	RecordMetadataSHA256 string `json:"record_metadata_sha256"`
	AuthoritySHA256      string `json:"authority_sha256"`
	GrantSHA256          string `json:"grant_sha256"`
	ContractSHA256       string `json:"contract_sha256"`
	MessageSHA256        string `json:"message_sha256"`
	PublicKey            string `json:"public_key"`
	Signature            string `json:"signature"`
	Outcome              string `json:"outcome"`
}

type rootGrantsGrantV3HelperRequest struct {
	Schema       string          `json:"schema"`
	Operation    string          `json:"operation"`
	Review       json.RawMessage `json:"review"`
	Envelope     json.RawMessage `json:"envelope"`
	PairMetadata string          `json:"pair_metadata"`
}

const rootGrantsGrantV3AttemptLimit = 120 * time.Second

type unavailableRootGrantsGrantV3Vault struct{}

func (unavailableRootGrantsGrantV3Vault) ReadRootGrantsForSigning(context.Context, RootGrantsAddress, string) (RootGrantsSigningSnapshot, error) {
	return RootGrantsSigningSnapshot{}, recoveryRefuse("operation_unavailable")
}

type unavailableRootGrantsGrantV3Helper struct{}

func (unavailableRootGrantsGrantV3Helper) ReviewSignGrantV3(context.Context, []byte) ([]byte, error) {
	return nil, recoveryRefuse("operation_unavailable")
}

func newRootGrantsGrantV3SigningVault() RootGrantsGrantV3SigningVault {
	vault, err := newRootGrantsProductionVault()
	if err != nil {
		return unavailableRootGrantsGrantV3Vault{}
	}
	return vault
}

// ReviewRootGrantsGrantV3 loads owner authority from its fixed local address
// and executes the operation. The production adapter reads only the exact,
// policy-admitted sealed item under the existing vault guard.
func ReviewRootGrantsGrantV3(ctx context.Context, q RootGrantsGrantV3SignRequest) (RootGrantsGrantV3SignatureReceipt, error) {
	var empty RootGrantsGrantV3SignatureReceipt
	if q.OwnerPrincipal == "" {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	address, err := q.Address.Account()
	if err != nil {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	_ = address // Account validation is independent of policy and request bytes.
	authority, err := LoadRootGrantsAuthority(q.Address)
	if err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "authority", false)
	}
	defer clear(authority)
	return SignRootGrantsGrantV3With(ctx, q, authority, newRootGrantsGrantV3SigningVault(), newRootGrantsGrantV3SigningHelper())
}

// SignRootGrantsGrantV3With runs public validation and the fakeable read/helper
// seams. Production callers must load authority from LoadRootGrantsAuthority;
// this lower-level entry accepts policy bytes for deterministic package tests.
func SignRootGrantsGrantV3With(ctx context.Context, q RootGrantsGrantV3SignRequest, authority []byte,
	vault RootGrantsGrantV3SigningVault, helper RootGrantsGrantV3SigningHelper) (RootGrantsGrantV3SignatureReceipt, error) {
	var empty RootGrantsGrantV3SignatureReceipt
	if ctx == nil || vault == nil || helper == nil {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	if q.Address.Service == "" || q.Address.Version < 1 || q.Address.Version > 2147483647 {
		return empty, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "preflight", false)
	}
	policy, err := ParseRootGrantsAuthority(authority)
	if err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "preflight", false)
	}
	if policy.OwnerPrincipal != q.OwnerPrincipal || policy.Record.Service != q.Address.Service || policy.Record.Version != q.Address.Version {
		return empty, rootGrantsGrantV3Failed("authority_mismatch", "preflight", false)
	}
	snapshot, record, err := rootGrantsSnapshotForSigning(ctx, vault, q.Address, policy)
	if err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "read", false)
	}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	plan, err := PrepareRootGrantsGrantV3(q.Grant, q.Contract, authority, snapshot.Metadata, q.OwnerPrincipal, time.Now())
	if err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "review", false)
	}
	review, err := plan.ReviewJSON()
	if err != nil {
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "review", false)
	}
	envelope, err := ParseRootGrantsEnvelope(snapshot.Envelope, record)
	if err != nil {
		clear(review)
		return empty, rootGrantsGrantV3Failed("invalid_envelope", "read", false)
	}
	envelopeJSON, err := CanonicalRootGrantsEnvelope(envelope, record)
	if err != nil {
		clear(review)
		return empty, rootGrantsGrantV3Failed("invalid_envelope", "read", false)
	}
	requestBytes, err := json.Marshal(rootGrantsGrantV3HelperRequest{
		Schema: "keyvault-root-grants-sign-request/2", Operation: rootGrantsGrantV3Operation,
		Review: review, Envelope: envelopeJSON, PairMetadata: hex.EncodeToString(snapshot.PairMetadata),
	})
	clear(review)
	clear(envelopeJSON)
	if err != nil || len(requestBytes) == 0 || len(requestBytes) > 262144 {
		clear(requestBytes)
		return empty, rootGrantsGrantV3Failed("limit_exceeded", "review", false)
	}
	defer clear(requestBytes)
	helperInput := bytes.Clone(requestBytes)
	signature, err := helper.ReviewSignGrantV3(ctx, helperInput)
	clear(helperInput)
	if err != nil {
		clear(signature)
		var failure *RootGrantsGrantV3Failure
		if errors.As(err, &failure) && failure != nil {
			return empty, failure
		}
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "sign", false)
	}
	if err := ctx.Err(); err != nil {
		clear(signature)
		return empty, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "sign", true)
	}
	if err := plan.VerifySignature(signature); err != nil {
		clear(signature)
		return empty, rootGrantsGrantV3Failed("signature_verification_failed", "verify", true)
	}
	var reviewHashes struct {
		GrantSHA256    string `json:"grant_sha256"`
		ContractSHA256 string `json:"contract_sha256"`
		MessageSHA256  string `json:"message_sha256"`
	}
	planReview, err := plan.ReviewJSON()
	if err != nil || json.Unmarshal(planReview, &reviewHashes) != nil {
		clear(signature)
		clear(planReview)
		return empty, rootGrantsGrantV3Failed("private_protocol_error", "receipt", true)
	}
	clear(planReview)
	policyDigest := sha256.Sum256(authority)
	receipt := RootGrantsGrantV3SignatureReceipt{
		Schema: "keyvault-root-grants-signature-receipt/1", Operation: rootGrantsGrantV3Operation,
		Profile: rootGrantsProfile, ObservationPolicy: RootGrantsOfflineReview, OwnerPrincipal: policy.OwnerPrincipal,
		RecordService: record.Service, RecordVersion: record.Version, RecordMetadataSHA256: policy.Record.MetadataSHA256,
		AuthoritySHA256: hex.EncodeToString(policyDigest[:]), GrantSHA256: reviewHashes.GrantSHA256,
		ContractSHA256: reviewHashes.ContractSHA256, MessageSHA256: reviewHashes.MessageSHA256,
		PublicKey: record.PublicKey, Signature: hex.EncodeToString(signature), Outcome: "signed",
	}
	clear(signature)
	return receipt, nil
}

func rootGrantsGrantV3ContextCode(err error) string {
	if err == context.DeadlineExceeded {
		return "timeout"
	}
	return "canceled"
}

func rootGrantsGrantV3RefusalCode(err error) string {
	var failure *rootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Code
	}
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal != nil {
		code := refusal.Code
		if len(code) > len("recovery_") && code[:len("recovery_")] == "recovery_" {
			return code[len("recovery_"):]
		}
		return code
	}
	return "operation_unavailable"
}
