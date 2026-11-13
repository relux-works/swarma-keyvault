package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	calls     int
	err       error
	request   []byte
	signature []byte
}

func (h *grantV3OperationHelper) ReviewSignGrantV3(ctx context.Context, request []byte) ([]byte, error) {
	h.calls++
	h.request = bytes.Clone(request)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.err != nil {
		return nil, h.err
	}
	if h.signature != nil {
		return bytes.Clone(h.signature), nil
	}
	var wire struct {
		Schema       string          `json:"schema"`
		Operation    string          `json:"operation"`
		Review       json.RawMessage `json:"review"`
		Envelope     json.RawMessage `json:"envelope"`
		PairMetadata string          `json:"pair_metadata"`
	}
	if json.Unmarshal(request, &wire) != nil || wire.Schema != "keyvault-root-grants-sign-request/2" ||
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
	// Keep the request fixture reproducible and valid for both the Go operation
	// and the checked-in Swift decoder fixture. These are public synthetic dates.
	const now int64 = 1600000000
	const notAfter int64 = 4102444800 // 2100-01-01 UTC.
	f.c.NotBefore, f.c.NotAfter = now-1, notAfter
	f.c.TemplateID = "example<&>"
	contract, err := rootGrantsEventBytes(f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.g.NotBefore, f.g.NotAfter, f.g.ContractSHA256 = f.c.NotBefore, f.c.NotAfter, rootGrantsHashHex(contract)
	f.g.Consent.ConsentEvent.CreatedAt = now - 2
	f.g.Consent.ConsentEvent.Tags[1][1] = f.g.ContractSHA256
	grantV3TestConsent(t, &f.g)
	f.p.NotBefore, f.p.NotAfter = now-20, notAfter+1000
	f.p.MaxGrantSeconds = f.p.NotAfter - f.p.NotBefore
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

// Claim: the public operation emits the real production helper request shape,
// retains the full recovery-record bytes, and transports the exact accepted
// contract bytes separately from JSON escaping. It does not prove Swift UI or
// a live vault read; the captured file is also consumed by the Swift decoder.
func TestRootGrantsGrantV3ProductionHelperRequestFixture(t *testing.T) {
	q, policy, snapshot := liveGrantV3OperationFixture(t)
	vault := &grantV3OperationVault{snapshot: snapshot}
	helper := &grantV3OperationHelper{}
	receipt, err := SignRootGrantsGrantV3With(context.Background(), q, policy, vault, helper)
	if err != nil {
		t.Fatal("production-shaped request refused by operation", err)
	}
	var wire rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(helper.request, &wire) != nil || wire.Schema != "keyvault-root-grants-sign-request/2" {
		t.Fatal("operation did not produce the fixed helper request")
	}
	var review rootGrantsGrantV3HelperReview
	if DecodeSingleJSON(wire.Review, &review) != nil {
		t.Fatal("operation request did not contain the complete review")
	}
	contract, err := rootGrantsContractBytes(review.ContractBase64)
	if err != nil || !bytes.Equal(contract, q.Contract) || !bytes.Contains(contract, []byte("example<&>")) ||
		bytes.Contains(contract, []byte("\\u003c")) {
		t.Fatal("accepted contract bytes changed in the production request")
	}
	contractDigest := sha256.Sum256(q.Contract)
	messageDigest, digestErr := rootGrantsGrantV3Digest(q.Grant)
	if digestErr != nil || review.ContractBytes != len(q.Contract) || review.ContractSHA256 != hex.EncodeToString(contractDigest[:]) ||
		review.MessageSHA256 != hex.EncodeToString(messageDigest[:]) {
		t.Fatal("exact contract bytes were not bound into the review and grant-v3 signing message")
	}
	grant, err := ParseRootGrantsGrantV3(q.Grant, time.Now())
	if err != nil || grant.ContractSHA256 != review.ContractSHA256 || receipt.ContractSHA256 != review.ContractSHA256 ||
		receipt.MessageSHA256 != review.MessageSHA256 || receipt.Outcome != "signed" {
		t.Fatal("signed grant did not retain the exact contract digest binding")
	}
	clear(contract)
	retained, err := hex.DecodeString(wire.PairMetadata)
	if err != nil || len(retained) <= 628 || !bytes.Equal(retained, snapshot.PairMetadata) {
		t.Fatal("production request did not retain the full recovery record")
	}
	if target := os.Getenv("ROOT_GRANTS_SWIFT_FIXTURE_OUT"); target != "" {
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, helper.request, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Claim: a helper cannot turn an invalid 64-byte result into a public success
// receipt. The valid adjacent operation test proves the positive path.
func TestRootGrantsGrantV3OperationRejectsInvalidHelperSignature(t *testing.T) {
	q, policy, snapshot := liveGrantV3OperationFixture(t)
	helper := &grantV3OperationHelper{signature: make([]byte, 64)}
	receipt, err := SignRootGrantsGrantV3With(context.Background(), q, policy,
		&grantV3OperationVault{snapshot: snapshot}, helper)
	var failure *RootGrantsGrantV3Failure
	if receipt != (RootGrantsGrantV3SignatureReceipt{}) || !errors.As(err, &failure) ||
		failure.Code != "signature_verification_failed" || failure.Phase != "verify" || failure.Outcome != "unknown" || helper.calls != 1 {
		t.Fatalf("invalid helper signature reached a successful receipt: %#v, %v", receipt, err)
	}
}

// Claim: the linked helper engine honors the context opened for the signing
// attempt instead of replacing it with a background budget. A valid owned
// plaintext is cleared and cannot produce a signature after cancellation or
// deadline expiry; the normal helper exchange test covers the live context.
func TestRootGrantsGrantV3HelperSigningHonorsOriginalContext(t *testing.T) {
	q, authority, snapshot := liveGrantV3OperationFixture(t)
	plan, err := PrepareRootGrantsGrantV3(q.Grant, q.Contract, authority, snapshot.Metadata, q.OwnerPrincipal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	review, err := plan.ReviewJSON()
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(rootGrantsGrantV3HelperRequest{
		Schema: "keyvault-root-grants-sign-request/2", Operation: rootGrantsGrantV3Operation,
		Review: review, Envelope: snapshot.Envelope, PairMetadata: hex.EncodeToString(snapshot.PairMetadata),
	})
	clear(review)
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseRootGrantsRecord(snapshot.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := rootGrantsPlaintextBinding(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"canceled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			if mode == "canceled" {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			}
			defer cancel()
			plaintext := make([]byte, 68)
			copy(plaintext[:4], "KVG1")
			copy(plaintext[4:36], binding[:])
			plaintext[67] = 3
			signature, signErr := RootGrantsGrantV3SignFromHelper(ctx, request, plaintext)
			want := "canceled"
			if mode == "deadline" {
				want = "timeout"
			}
			var failure *RootGrantsGrantV3Failure
			if signature != nil || !errors.As(signErr, &failure) || failure.Code != want || failure.Outcome != "not_applied" ||
				!bytes.Equal(plaintext, make([]byte, 68)) {
				t.Fatalf("helper signed or retained valid plaintext after %s: signature=%x err=%v", mode, signature, signErr)
			}
		})
	}
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
func TestRootGrantsGrantV3ParentRechecksVaultAndPolicy(t *testing.T) {
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
	request, err := json.Marshal(rootGrantsGrantV3HelperRequest{Schema: "keyvault-root-grants-sign-request/2",
		Operation: rootGrantsGrantV3Operation, Review: review, Envelope: envelopeBytes, PairMetadata: hex.EncodeToString(snapshot.PairMetadata)})
	if err != nil {
		t.Fatal(err)
	}
	clear(review)
	clear(envelopeBytes)
	preUnwrapVault := &grantV3OperationVault{snapshot: snapshot}
	if err := rootGrantsGrantV3CheckForHelperWithContext(context.Background(), request, preUnwrapVault, func(RootGrantsAddress) ([]byte, error) {
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
	sig, err := rootGrantsGrantV3SignFromHelperWithAuthorityLoader(context.Background(), request, plain,
		func(address RootGrantsAddress) ([]byte, error) {
			if address != (RootGrantsAddress{Service: record.Service, Version: record.Version}) {
				return nil, recoveryRefuse("operation_unavailable")
			}
			return bytes.Clone(authority), nil
		}, bytes.NewReader(make([]byte, 32)), nil, nil)
	if err != nil || len(sig) != 64 || plan.VerifySignature(sig) != nil || !bytes.Equal(plain, make([]byte, 68)) {
		t.Fatal("context-bound helper engine did not produce one verified, cleared signature", err)
	}
	clear(sig)

	changed := &grantV3OperationVault{snapshot: snapshot}
	changed.mutate = func(s *RootGrantsSigningSnapshot) {
		var envelope RootGrantsEnvelope
		if json.Unmarshal(s.Envelope, &envelope) != nil {
			panic("test envelope decode")
		}
		envelope.EnclaveBlob[0] ^= 1
		s.Envelope, _ = json.Marshal(envelope)
	}
	err = rootGrantsGrantV3CheckForHelperWithContext(context.Background(), request, changed, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(authority), nil
	})
	var refusal *rootGrantsGrantV3Failure
	if !errors.As(err, &refusal) || refusal.Code != "review_changed" {
		t.Fatal("changed live vault snapshot was accepted", err)
	}

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
	err = rootGrantsGrantV3CheckForHelperWithContext(context.Background(), request, policyChangeVault, func(RootGrantsAddress) ([]byte, error) {
		return bytes.Clone(changedPolicyBytes), nil
	})
	if !errors.As(err, &refusal) || refusal.Code != "review_changed" || policyChangeVault.calls != 0 {
		t.Fatal("changed live authority reached the vault or retained private input", err)
	}
	clear(changedPolicyBytes)
}
