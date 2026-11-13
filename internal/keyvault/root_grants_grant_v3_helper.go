package keyvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type rootGrantsGrantV3HelperReview struct {
	Operation         string          `json:"operation"`
	Profile           string          `json:"profile"`
	ObservationPolicy string          `json:"observation_policy"`
	Grant             json.RawMessage `json:"grant"`
	ContractBase64    string          `json:"contract_bytes_base64"`
	Authority         json.RawMessage `json:"authority"`
	Record            json.RawMessage `json:"record"`
	GrantBytes        int             `json:"grant_bytes"`
	ContractBytes     int             `json:"contract_bytes"`
	GrantSHA256       string          `json:"grant_sha256"`
	ContractSHA256    string          `json:"contract_sha256"`
	AuthoritySHA256   string          `json:"authority_sha256"`
	RecordSHA256      string          `json:"record_sha256"`
	MessageSHA256     string          `json:"message_sha256"`
}

func RootGrantsGrantV3HelperStatus(err error) int32 {
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil {
		return 16
	}
	switch failure.Code {
	case "invalid_arguments":
		return 1
	case "retained_record_mismatch":
		return 8
	case "public_pin_mismatch":
		return 9
	case "operation_unavailable", "review_refused":
		return 10
	case "code_not_admitted":
		return 21
	case "acl_refused":
		return 22
	case "lock_unavailable":
		return 23
	case "inventory_changed":
		return 24
	case "invalid_envelope":
		return 12
	case "binding_mismatch", "authority_mismatch", "contract_mismatch", "consent_invalid", "review_changed":
		return 13
	case "canceled", "presence_canceled":
		return 14
	case "timeout":
		return 15
	case "limit_exceeded":
		return 17
	case "unsupported_version":
		return 18
	case "unsupported_operation":
		return 19
	default:
		return 16
	}
}

func rootGrantsGrantV3PlanFromHelperRequest(rawRequest []byte) (*RootGrantsGrantV3Plan, error) {
	var wire rootGrantsGrantV3HelperRequest
	if len(rawRequest) == 0 || len(rawRequest) > 262144 || DecodeSingleJSON(rawRequest, &wire) != nil ||
		wire.Schema != "keyvault-root-grants-sign-request/2" || wire.Operation != rootGrantsGrantV3Operation ||
		len(wire.Review) == 0 || len(wire.Envelope) == 0 || wire.PairMetadata == "" {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "preflight", false)
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, rawRequest) {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "preflight", false)
	}
	var review rootGrantsGrantV3HelperReview
	if DecodeSingleJSON(wire.Review, &review) != nil || review.Operation != rootGrantsGrantV3Operation ||
		review.Profile != rootGrantsProfile || review.ObservationPolicy != RootGrantsOfflineReview {
		return nil, rootGrantsGrantV3Failed("private_protocol_error", "review", false)
	}
	var authority RootGrantsAuthority
	if DecodeSingleJSON(review.Authority, &authority) != nil {
		return nil, rootGrantsGrantV3Failed("authority_mismatch", "review", false)
	}
	contract, err := rootGrantsContractBytes(review.ContractBase64)
	if err != nil {
		return nil, rootGrantsGrantV3Failed("contract_mismatch", "review", false)
	}
	defer clear(contract)
	plan, err := PrepareRootGrantsGrantV3(review.Grant, contract, review.Authority, review.Record,
		authority.OwnerPrincipal, time.Now())
	if err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "review", false)
	}
	expectedReview, err := plan.ReviewJSON()
	if err != nil || !bytes.Equal(expectedReview, wire.Review) {
		clear(expectedReview)
		return nil, rootGrantsGrantV3Failed("review_changed", "review", false)
	}
	clear(expectedReview)
	policy, err := ParseRootGrantsAuthority(review.Authority)
	if err != nil {
		return nil, rootGrantsGrantV3Failed("authority_mismatch", "review", false)
	}
	pairMetadata, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || hex.EncodeToString(pairMetadata) != wire.PairMetadata {
		clear(pairMetadata)
		return nil, rootGrantsGrantV3Failed("retained_record_mismatch", "review", false)
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: bytes.Clone(review.Record), Envelope: bytes.Clone(wire.Envelope), PairMetadata: pairMetadata}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	if _, err := rootGrantsValidateSigningSnapshot(snapshot, policy); err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "read", false)
	}
	return plan, nil
}

// rootGrantsGrantV3CheckForHelperWithContext runs in the admitted parent vault
// process. The private helper requests a fixed checkpoint; it never opens the
// Keychain or selects a vault guard itself.
func rootGrantsGrantV3CheckForHelperWithContext(ctx context.Context, rawRequest []byte, vault RootGrantsGrantV3SigningVault,
	loadAuthority func(RootGrantsAddress) ([]byte, error)) error {
	if ctx == nil {
		return rootGrantsGrantV3Failed("invalid_arguments", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "recheck", false)
	}
	if _, err := rootGrantsGrantV3PlanFromHelperRequest(rawRequest); err != nil {
		return err
	}
	var wire rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(rawRequest, &wire) != nil {
		return rootGrantsGrantV3Failed("private_protocol_error", "recheck", false)
	}
	var review rootGrantsGrantV3HelperReview
	if DecodeSingleJSON(wire.Review, &review) != nil {
		return rootGrantsGrantV3Failed("private_protocol_error", "recheck", false)
	}
	policy, err := ParseRootGrantsAuthority(review.Authority)
	if err != nil || vault == nil || loadAuthority == nil {
		return rootGrantsGrantV3Failed("operation_unavailable", "recheck", false)
	}
	address := RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}
	currentAuthority, err := loadAuthority(address)
	if contextErr := ctx.Err(); contextErr != nil {
		clear(currentAuthority)
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(contextErr), "recheck", false)
	}
	if err != nil || !bytes.Equal(currentAuthority, review.Authority) {
		clear(currentAuthority)
		return rootGrantsGrantV3Failed("review_changed", "recheck", false)
	}
	clear(currentAuthority)
	pairMetadata, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || hex.EncodeToString(pairMetadata) != wire.PairMetadata {
		clear(pairMetadata)
		return rootGrantsGrantV3Failed("retained_record_mismatch", "recheck", false)
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: bytes.Clone(review.Record), Envelope: bytes.Clone(wire.Envelope), PairMetadata: pairMetadata}
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	if _, err := rootGrantsValidateSigningSnapshot(snapshot, policy); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "recheck", false)
	}
	current, _, err := rootGrantsSnapshotForSigning(ctx, vault, address, policy)
	if err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "recheck", false)
	}
	defer clear(current.Metadata)
	defer clear(current.Envelope)
	defer clear(current.PairMetadata)
	if !rootGrantsSigningSnapshotsEqual(snapshot, current) {
		return rootGrantsGrantV3Failed("review_changed", "recheck", false)
	}
	if err := ctx.Err(); err != nil {
		return rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "recheck", false)
	}
	return nil
}

// RootGrantsGrantV3SignFromHelper is the linked helper's context-bound signing
// entry. Vault reads are completed by the admitted parent over its private
// control channel before this call; this process receives no vault capability.
func RootGrantsGrantV3SignFromHelper(ctx context.Context, rawRequest, ownedPlaintext []byte) ([]byte, error) {
	defer clear(ownedPlaintext)
	if ctx == nil {
		return nil, rootGrantsGrantV3Failed("invalid_arguments", "sign", false)
	}
	plan, err := rootGrantsGrantV3PlanFromHelperRequest(rawRequest)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, rootGrantsGrantV3Failed(rootGrantsGrantV3ContextCode(err), "sign", false)
	}
	attempt, err := newRootGrantsGrantV3Attempt(ctx, plan)
	if err != nil {
		return nil, err
	}
	return attempt.sign(ownedPlaintext)
}

func rootGrantsContractBytes(encoded string) ([]byte, error) {
	contract, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || encoded == "" || base64.StdEncoding.EncodeToString(contract) != encoded || len(contract) == 0 || len(contract) > 65536 {
		clear(contract)
		return nil, recoveryRefuse("contract_mismatch")
	}
	return contract, nil
}
