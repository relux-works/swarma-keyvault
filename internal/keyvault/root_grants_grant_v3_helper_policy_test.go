package keyvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func grantV3HelperPolicyFixture(t *testing.T) (request, authority, plaintext []byte, plan *RootGrantsGrantV3Plan) {
	t.Helper()
	q, authority, snapshot := liveGrantV3OperationFixture(t)
	plan, err := PrepareRootGrantsGrantV3(q.Grant, q.Contract, authority, snapshot.Metadata, q.OwnerPrincipal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	review, err := plan.ReviewJSON()
	if err != nil {
		t.Fatal(err)
	}
	request, err = json.Marshal(rootGrantsGrantV3HelperRequest{
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
	plaintext = make([]byte, 68)
	copy(plaintext[:4], "KVG1")
	copy(plaintext[4:36], binding[:])
	plaintext[67] = 3 // Public synthetic scalar fixture; no stored or hardware key.
	return request, authority, plaintext, plan
}

func grantV3ChangedPolicy(t *testing.T, raw []byte) []byte {
	t.Helper()
	var policy RootGrantsAuthority
	if DecodeSingleJSON(raw, &policy) != nil {
		t.Fatal("invalid synthetic policy fixture")
	}
	policy.MaxBudgetSat++
	changed, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRootGrantsAuthority(changed); err != nil {
		t.Fatal("changed neighbor is not a valid installed policy", err)
	}
	return changed
}

// Claim: the helper independently loads the fixed account/address policy at
// pre-unwrap and pre-sign boundaries. Missing, unreadable and changed sources
// refuse; an exact installed-policy neighbor reaches actual BIP-340 math.
// Limits: the loader is an injected synthetic public-file source, not a read of
// an installed policy or proof of OS account database behavior.
func TestRootGrantsGrantV3HelperIndependentPolicyBoundaries(t *testing.T) {
	request, authority, plaintext, plan := grantV3HelperPolicyFixture(t)
	defer clear(plaintext)
	changed := grantV3ChangedPolicy(t, authority)
	record, err := ParseRootGrantsRecord(plan.record)
	if err != nil {
		t.Fatal("test plan record is invalid", err)
	}
	address := RootGrantsAddress{Service: record.Service, Version: record.Version}
	for _, mode := range []string{"missing", "unreadable", "changed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			loader := func(got RootGrantsAddress) ([]byte, error) {
				calls++
				if got != address {
					t.Fatalf("policy loader selected caller-unrelated address: %+v", got)
				}
				switch mode {
				case "missing", "unreadable":
					return nil, recoveryRefuse("operation_unavailable")
				default:
					return bytes.Clone(changed), nil
				}
			}
			if err := rootGrantsGrantV3CheckInstalledAuthorityFromHelper(context.Background(), request, loader); err == nil {
				t.Fatal("pre-unwrap helper gate accepted absent/unreadable/changed authority")
			}
			if calls != 1 {
				t.Fatalf("pre-unwrap policy loader calls=%d, want 1", calls)
			}
			input := bytes.Clone(plaintext)
			signature, err := rootGrantsGrantV3SignFromHelperWithAuthorityLoader(context.Background(), request, input,
				loader, bytes.NewReader(make([]byte, 32)), nil, nil)
			var failure *RootGrantsGrantV3Failure
			if signature != nil || !errors.As(err, &failure) || failure.Outcome != "not_applied" ||
				failure.Code != "operation_unavailable" && mode != "changed" ||
				failure.Code != "review_changed" && mode == "changed" || !bytes.Equal(input, make([]byte, len(input))) {
				t.Fatalf("helper accepted invalid installed authority: signature=%v failure=%+v", signature, failure)
			}
		})
	}

	var calls int
	loader := func(got RootGrantsAddress) ([]byte, error) {
		calls++
		if got != address {
			t.Fatalf("policy loader selected wrong fixed address: %+v", got)
		}
		return bytes.Clone(authority), nil
	}
	if err := rootGrantsGrantV3CheckInstalledAuthorityFromHelper(context.Background(), request, loader); err != nil {
		t.Fatal("valid installed-policy neighbor refused before unwrap", err)
	}
	input := bytes.Clone(plaintext)
	signature, err := rootGrantsGrantV3SignFromHelperWithAuthorityLoader(context.Background(), request, input,
		loader, bytes.NewReader(make([]byte, 32)), nil, nil)
	if err != nil || plan.VerifySignature(signature) != nil || calls != 2 || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatalf("valid installed-policy neighbor did not sign after two independent checks: calls=%d err=%v", calls, err)
	}
	clear(signature)

	// A policy changed after the pre-unwrap check must be caught by the second
	// helper load after public revalidation and before private signing.
	calls = 0
	loader = func(RootGrantsAddress) ([]byte, error) {
		calls++
		if calls == 1 {
			return bytes.Clone(authority), nil
		}
		return bytes.Clone(changed), nil
	}
	if err := rootGrantsGrantV3CheckInstalledAuthorityFromHelper(context.Background(), request, loader); err != nil {
		t.Fatal("initial valid policy was refused", err)
	}
	input = bytes.Clone(plaintext)
	signature, err = rootGrantsGrantV3SignFromHelperWithAuthorityLoader(context.Background(), request, input,
		loader, bytes.NewReader(make([]byte, 32)), nil, nil)
	var failure *RootGrantsGrantV3Failure
	if signature != nil || !errors.As(err, &failure) || failure.Code != "review_changed" || failure.Outcome != "not_applied" ||
		calls != 2 || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatalf("changed installed policy reached private math: calls=%d failure=%+v", calls, failure)
	}
}

// Claim: cancellation after final public revalidation is checked at the actual
// helper-engine math boundary. The hook schedules cancellation only after
// revalidation returns; the math witness must remain untouched and plaintext
// must be cleared. This is software engine evidence, not hardware signing.
func TestRootGrantsGrantV3CancelDuringFinalRevalidationStopsBeforeMath(t *testing.T) {
	grantV3FinalRevalidationContextControl(t, false)
}

// Claim: expiry during the final validation-to-math window has the same
// not-applied outcome as cancellation, using the attempt's original deadline.
func TestRootGrantsGrantV3DeadlineDuringFinalRevalidationStopsBeforeMath(t *testing.T) {
	grantV3FinalRevalidationContextControl(t, true)
}

func grantV3FinalRevalidationContextControl(t *testing.T, deadline bool) {
	t.Helper()
	request, authority, plaintext, _ := grantV3HelperPolicyFixture(t)
	defer clear(plaintext)
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline {
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	loader := func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authority), nil }
	input := bytes.Clone(plaintext)
	mathStarted := false
	enteredBoundary := false
	signature, err := rootGrantsGrantV3SignFromHelperWithAuthorityLoader(ctx, request, input,
		loader, bytes.NewReader(make([]byte, 32)), func() {
			enteredBoundary = true
			if ctx.Err() != nil {
				t.Error("context ended before final public revalidation returned")
				return
			}
			if deadline {
				<-ctx.Done()
			} else {
				cancel()
			}
		}, func() { mathStarted = true })
	want := "canceled"
	if deadline {
		want = "timeout"
	}
	var failure *RootGrantsGrantV3Failure
	if signature != nil || !errors.As(err, &failure) || failure.Code != want || failure.Outcome != "not_applied" ||
		!enteredBoundary || mathStarted || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatalf("private math began after final-validation %s: entered=%v math=%v failure=%+v", want, enteredBoundary, mathStarted, failure)
	}
}
