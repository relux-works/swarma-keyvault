package keyvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Claim: newly surfaced production-read refusals cross the helper ABI only as
// existing closed statuses. Limit: this maps Go refusal types; it does not run
// the archive or helper process.
func TestRootGrantsGrantV3ReadRefusalsUseClosedHelperStatuses(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int32
	}{{"code_not_admitted", 21}, {"acl_refused", 22}, {"lock_unavailable", 23}, {"inventory_changed", 24}} {
		if got := RootGrantsGrantV3HelperStatus(rootGrantsGrantV3Failed(tc.code, "read", false)); got != tc.want {
			t.Errorf("%s helper status = %d, want %d", tc.code, got, tc.want)
		}
	}
}

type grantV3OperationVault struct {
	snapshot RootGrantsSigningSnapshot
	calls    int
	address  RootGrantsAddress
	digest   string
	err      error
	mutate   func(*RootGrantsSigningSnapshot)
}

func (v *grantV3OperationVault) ReadRootGrantsForSigning(ctx context.Context, address RootGrantsAddress, digest string) (RootGrantsSigningSnapshot, error) {
	v.calls++
	v.address, v.digest = address, digest
	if v.mutate != nil {
		v.mutate(&v.snapshot)
	}
	if err := ctx.Err(); err != nil {
		return RootGrantsSigningSnapshot{}, err
	}
	return v.snapshot, v.err
}

type grantV3OperationHelper struct {
	calls int
	err   error
}

func (h *grantV3OperationHelper) ReviewSignGrantV3(ctx context.Context, request []byte) ([]byte, error) {
	h.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.err != nil {
		return nil, h.err
	}
	var wire struct {
		Schema       string          `json:"schema"`
		Operation    string          `json:"operation"`
		Review       json.RawMessage `json:"review"`
		Envelope     json.RawMessage `json:"envelope"`
		PairMetadata string          `json:"pair_metadata"`
	}
	if json.Unmarshal(request, &wire) != nil || wire.Schema != "keyvault-root-grants-sign-request/1" ||
		wire.Operation != rootGrantsGrantV3Operation || len(wire.Review) == 0 || len(wire.Envelope) == 0 || wire.PairMetadata == "" {
		return nil, errors.New("invalid test request")
	}
	var review struct {
		MessageSHA256 string `json:"message_sha256"`
	}
	if json.Unmarshal(wire.Review, &review) != nil || len(review.MessageSHA256) != 64 {
		return nil, errors.New("invalid test review")
	}
	message, err := hex.DecodeString(review.MessageSHA256)
	if err != nil || len(message) != 32 {
		return nil, errors.New("invalid test message")
	}
	var digest, secret, aux [32]byte
	copy(digest[:], message)
	secret[31] = 3
	signature, err := signNostrWithAux(secret[:], digest[:], aux)
	clear(secret[:])
	if err != nil {
		return nil, errors.New("test signature failed")
	}
	return signature, nil
}

func liveGrantV3OperationFixture(t *testing.T) (RootGrantsGrantV3SignRequest, []byte, RootGrantsSigningSnapshot) {
	t.Helper()
	f := grantV3FullFixture(t)
	pairMetadata, _ := rootGrantsTestPair(t, "keyvault-recovery/2")
	now := time.Now().Unix()
	f.c.NotBefore, f.c.NotAfter = now-1, now+600
	contract, err := rootGrantsEventBytes(f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.g.NotBefore, f.g.NotAfter, f.g.ContractSHA256 = f.c.NotBefore, f.c.NotAfter, rootGrantsHashHex(contract)
	f.g.Consent.ConsentEvent.CreatedAt = now - 2
	f.g.Consent.ConsentEvent.Tags[1][1] = f.g.ContractSHA256
	grantV3TestConsent(t, &f.g)
	f.p.NotBefore, f.p.NotAfter = now-20, now+1000
	metadata, err := CanonicalRootGrantsRecord(f.r)
	if err != nil {
		t.Fatal(err)
	}
	f.p.Record.MetadataSHA256 = rootGrantsHashHex(metadata)
	policy, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := CanonicalRootGrantsEnvelope(rootGrantsEnvelopeFixture13(t, f.r), f.r)
	if err != nil {
		t.Fatal(err)
	}
	return RootGrantsGrantV3SignRequest{
		Address: RootGrantsAddress{Service: f.r.Service, Version: f.r.Version}, OwnerPrincipal: f.p.OwnerPrincipal,
		Grant: rootGrantsRaw13(t, f.g), Contract: contract,
	}, policy, RootGrantsSigningSnapshot{Metadata: metadata, Envelope: envelope, PairMetadata: pairMetadata}
}

// Claim: the CLI-facing operation reads exactly one explicit sealed snapshot,
// constructs the complete immutable review, and emits only a verified public
// receipt. The fake proves interface wiring and binding, not native custody.
func TestRootGrantsGrantV3OperationReceiptFromVaultDouble(t *testing.T) {
	q, policy, snapshot := liveGrantV3OperationFixture(t)
	vault := &grantV3OperationVault{snapshot: snapshot}
	helper := &grantV3OperationHelper{}
	got, err := SignRootGrantsGrantV3With(context.Background(), q, policy, vault, helper)
	if err != nil {
		t.Fatal("eligible fake-backed operation refused", err)
	}
	if vault.calls != 1 || vault.address != q.Address || vault.digest == "" || helper.calls != 1 {
		t.Fatal("signing operation did not use the injected read/helper seams exactly once")
	}
	if got.Schema != "keyvault-root-grants-signature-receipt/1" || got.Operation != rootGrantsGrantV3Operation ||
		got.ObservationPolicy != RootGrantsOfflineReview || got.OwnerPrincipal != q.OwnerPrincipal || got.Outcome != "signed" ||
		got.RecordService != q.Address.Service || got.RecordVersion != q.Address.Version || len(got.Signature) != 128 ||
		got.AuthoritySHA256 == "" || got.GrantSHA256 == "" || got.ContractSHA256 == "" || got.MessageSHA256 == "" {
		t.Fatal("receipt omitted a public operation binding")
	}
}

// Claim: every pre-sign refusal stops before the helper, and a failed vault
// read is mapped to a closed result without exposing its diagnostic.
func TestRootGrantsGrantV3OperationRefusalsStopBeforeHelper(t *testing.T) {
	for _, mode := range []string{"wrong-owner", "bad-pair", "vault-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			q, policy, snapshot := liveGrantV3OperationFixture(t)
			ctx := context.Background()
			vault := &grantV3OperationVault{snapshot: snapshot}
			helper := &grantV3OperationHelper{}
			wantCode := "authority_mismatch"
			switch mode {
			case "wrong-owner":
				q.OwnerPrincipal = "owner:id/other-owner"
			case "bad-pair":
				vault.snapshot.PairMetadata = []byte("{}")
				wantCode = "retained_record_mismatch"
			case "vault-error":
				vault.err = errors.New("PRIVATE_TEST_DIAGNOSTIC")
				wantCode = "operation_unavailable"
			case "canceled":
				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = canceled
				wantCode = "canceled"
			}
			_, err := SignRootGrantsGrantV3With(ctx, q, policy, vault, helper)
			var refusal *rootGrantsGrantV3Failure
			if !errors.As(err, &refusal) || refusal.Code != wantCode || refusal.Outcome != "not_applied" {
				t.Fatalf("expected closed %s refusal, got %v", wantCode, err)
			}
			if helper.calls != 0 {
				t.Fatal("pre-sign refusal reached helper")
			}
			if strings.Contains(err.Error(), "PRIVATE_TEST_DIAGNOSTIC") {
				t.Fatal("vault diagnostic escaped")
			}
		})
	}
}

// Claim: immediately before private signing the helper reloads both the fixed
// authority document and sealed snapshot through the read-only vault interface. A changed
// read refuses, and every attempt clears its KVG1 buffer.
func TestRootGrantsGrantV3HelperRechecksVaultAndPolicy(t *testing.T) {
	q, authority, snapshot := liveGrantV3OperationFixture(t)
	plan, err := PrepareRootGrantsGrantV3(q.Grant, q.Contract, authority, snapshot.Metadata, q.OwnerPrincipal, time.Now())
	if err != nil {
		t.Fatal("test plan refused", err)
	}
	review, err := plan.ReviewJSON()
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseRootGrantsRecord(snapshot.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ParseRootGrantsEnvelope(snapshot.Envelope, record)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := CanonicalRootGrantsEnvelope(envelope, record)
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(rootGrantsGrantV3HelperRequest{Schema: "keyvault-root-grants-sign-request/1",
		Operation: rootGrantsGrantV3Operation, Review: review, Envelope: envelopeBytes, PairMetadata: hex.EncodeToString(snapshot.PairMetadata)})
	if err != nil {
		t.Fatal(err)
	}
	clear(review)
	clear(envelopeBytes)
	preUnwrapVault := &grantV3OperationVault{snapshot: snapshot}
	if err := rootGrantsGrantV3CheckForHelperWith(request, preUnwrapVault, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(authority), nil
	}); err != nil || preUnwrapVault.calls != 1 {
		t.Fatal("fresh policy/snapshot was not checked before unwrapping", err)
	}
	binding, err := rootGrantsPlaintextBinding(record)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 68)
	copy(plain[:4], "KVG1")
	copy(plain[4:36], binding[:])
	plain[67] = 3
	vault := &grantV3OperationVault{snapshot: snapshot}
	sig, err := rootGrantsGrantV3SignFromHelperWith(request, plain, vault, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(authority), nil
	})
	if err != nil || len(sig) != 64 || plan.VerifySignature(sig) != nil || vault.calls != 1 || !bytes.Equal(plain, make([]byte, 68)) {
		t.Fatal("fresh policy/snapshot did not produce one verified, cleared signature", err)
	}
	clear(sig)

	plain = make([]byte, 68)
	copy(plain[:4], "KVG1")
	copy(plain[4:36], binding[:])
	plain[67] = 3
	changed := &grantV3OperationVault{snapshot: snapshot}
	changed.mutate = func(s *RootGrantsSigningSnapshot) {
		var envelope RootGrantsEnvelope
		if json.Unmarshal(s.Envelope, &envelope) != nil {
			panic("test envelope decode")
		}
		envelope.EnclaveBlob[0] ^= 1
		s.Envelope, _ = json.Marshal(envelope)
	}
	_, err = rootGrantsGrantV3SignFromHelperWith(request, plain, changed, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(authority), nil
	})
	var refusal *rootGrantsGrantV3Failure
	if !errors.As(err, &refusal) || refusal.Code != "review_changed" || !bytes.Equal(plain, make([]byte, 68)) {
		t.Fatal("changed live vault snapshot was accepted or retained private input", err)
	}

	plain = make([]byte, 68)
	copy(plain[:4], "KVG1")
	copy(plain[4:36], binding[:])
	plain[67] = 3
	changedPolicy, err := ParseRootGrantsAuthority(authority)
	if err != nil {
		t.Fatal("test authority invalid", err)
	}
	changedPolicy.LandlordName = "id/other-landlord"
	changedPolicyBytes, err := json.Marshal(changedPolicy)
	if err != nil {
		t.Fatal("changed test authority could not be encoded", err)
	}
	policyChangeVault := &grantV3OperationVault{snapshot: snapshot}
	_, err = rootGrantsGrantV3SignFromHelperWith(request, plain, policyChangeVault, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(changedPolicyBytes), nil
	})
	if !errors.As(err, &refusal) || refusal.Code != "review_changed" || policyChangeVault.calls != 0 || !bytes.Equal(plain, make([]byte, 68)) {
		t.Fatal("changed live authority reached the vault or retained private input", err)
	}
	clear(changedPolicyBytes)
}
