package keyvault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func grantV3LiveTestPlan(t *testing.T) (*RootGrantsGrantV3Plan, []byte) {
	t.Helper()
	f := grantV3FullFixture(t)
	now := time.Now().Unix()
	f.c.NotBefore, f.c.NotAfter = now-1, now+899
	contract, _ := rootGrantsEventBytes(f.c)
	f.g.NotBefore, f.g.NotAfter, f.g.ContractSHA256 = f.c.NotBefore, f.c.NotAfter, rootGrantsHashHex(contract)
	f.g.Consent.ConsentEvent.CreatedAt = now - 2
	f.g.Consent.ConsentEvent.Tags[1][1] = f.g.ContractSHA256
	grantV3TestConsent(t, &f.g)
	f.p.NotBefore, f.p.NotAfter = now-20, now+1200
	plan, err := PrepareRootGrantsGrantV3(rootGrantsRaw13(t, f.g), contract, rootGrantsRaw13(t, f.p), rootGrantsRaw13(t, f.r), f.p.OwnerPrincipal, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := rootGrantsPlaintextBinding(f.r)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 68)
	copy(plain[:4], "KVG1")
	copy(plain[4:36], binding[:])
	plain[67] = 3 // Published BIP-340 scalar, synthetic helper-local fixture.
	return plan, plain
}

func grantV3SignRefusal(t *testing.T, err error, code, outcome string) {
	t.Helper()
	var refusal *rootGrantsGrantV3Failure
	if !errors.As(err, &refusal) || refusal.Code != code || refusal.Outcome != outcome || refusal.Phase != "sign" {
		t.Fatalf("expected %s/%s sign refusal, got %v", code, outcome, err)
	}
}

// The actual private engine signs one exact plan from helper-local KVG1 bytes,
// verifies its own result and wipes its owned input. Every second use refuses.
// This is software math, not proof of a native display or fresh Touch ID.
func TestRootGrantsGrantV3OneShotEngine(t *testing.T) {
	plan, plain := grantV3LiveTestPlan(t)
	a, err := newRootGrantsGrantV3Attempt(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(plain)
	sig, err := a.signWithRandom(plain, bytes.NewReader(make([]byte, 32)))
	if err != nil || plan.VerifySignature(sig) != nil || !bytes.Equal(plain, make([]byte, 68)) {
		t.Fatal("one-shot engine failed or retained plaintext", err)
	}
	again, err := a.sign(saved)
	grantV3SignRefusal(t, err, "operation_unavailable", "not_applied")
	if again != nil || !bytes.Equal(saved, make([]byte, 68)) {
		t.Fatal("consumed review reused or retained plaintext")
	}
}

// Each broken KVG1 component, wrong scalar, truncated input and entropy failure
// consumes the attempt before private use and wipes caller-owned plaintext.
func TestRootGrantsGrantV3EngineRefusals(t *testing.T) {
	for _, mode := range []string{"magic", "metadata-binding", "wrong-key", "zero-key", "short", "random-failure", "canceled", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			plan, plain := grantV3LiveTestPlan(t)
			ctx := context.Background()
			code := "binding_mismatch"
			var random io.Reader = bytes.NewReader(make([]byte, 32))
			switch mode {
			case "magic":
				plain[0] ^= 1
			case "metadata-binding":
				plain[4] ^= 1
			case "wrong-key":
				plain[67] = 1
			case "zero-key":
				plain[67] = 0
			case "short":
				plain = plain[:67]
				code = "invalid_envelope"
			case "random-failure":
				random = bytes.NewReader(nil)
				code = "operation_unavailable"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				code = "canceled"
			case "timeout":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				code = "timeout"
			}
			a, err := newRootGrantsGrantV3Attempt(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := a.signWithRandom(plain, random)
			grantV3SignRefusal(t, err, code, "not_applied")
			if sig != nil || !bytes.Equal(plain, make([]byte, len(plain))) {
				t.Fatal("refusal returned a signature or kept plaintext")
			}
			_, err = a.sign(nil)
			grantV3SignRefusal(t, err, "operation_unavailable", "not_applied")
		})
	}
}

// Concurrent callers cannot both consume one review. Both supplied KVG1 inputs
// are cleared, and exactly one valid signature is returned; no native calls run.
func TestRootGrantsGrantV3ConcurrentConsumption(t *testing.T) {
	plan, plain := grantV3LiveTestPlan(t)
	a, err := newRootGrantsGrantV3Attempt(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	var wg sync.WaitGroup
	type result struct {
		sig []byte
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		wg.Add(1)
		go func(input []byte) {
			defer wg.Done()
			sig, err := a.sign(input)
			if !bytes.Equal(input, make([]byte, 68)) {
				t.Error("concurrent input not cleared")
			}
			results <- result{sig, err}
		}(bytes.Clone(plain))
	}
	wg.Wait()
	close(results)
	clear(plain)
	accepted, refused := 0, 0
	for r := range results {
		if r.err == nil && plan.VerifySignature(r.sig) == nil {
			accepted++
		} else {
			grantV3SignRefusal(t, r.err, "operation_unavailable", "not_applied")
			refused++
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatalf("concurrent consumption: accepted=%d refused=%d", accepted, refused)
	}
}
