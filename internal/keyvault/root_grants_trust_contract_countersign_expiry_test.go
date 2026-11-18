package keyvault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
)

type trustCountersignExpiryHelper struct {
	t               *testing.T
	now             int64
	at              string
	target          int64
	authority       []byte
	snapshot        RootGrantsSigningSnapshot
	signs, rechecks int
	cancel          context.CancelFunc
}

func (h *trustCountersignExpiryHelper) ReviewSignTrustContractCountersign(ctx context.Context, raw []byte) ([]byte, error) {
	clock := func() int64 { return h.now }
	load := func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(h.authority), nil }
	for _, stage := range []string{"first-wait", "second-wait"} {
		if h.at == stage {
			h.now = h.target
		}
		if h.at == stage+"-cancel" {
			h.now = h.target
			h.cancel()
		}
		vault := &trustCountersignExpiryVault{snapshot: h.snapshot, after: func() {
			if h.at == stage+"-read" {
				h.now = h.target
			}
			if h.at == stage+"-read-cancel" {
				h.now = h.target
				h.cancel()
			}
		}}
		h.rechecks++
		if err := rootGrantsTrustContractCountersignCheckForHelperWithClock(ctx, raw, vault, load, clock); err != nil {
			return nil, err
		}
	}
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
	if err != nil {
		return nil, err
	}
	defer data.clear()
	plaintext := rootTrustCountersignNativePlaintextFixture(h.t, data.Review.RecordJSON, 3)
	entropy := trustCountersignExpiryReader{after: func() {
		if h.at == "entropy" {
			h.now = h.target
		}
		if h.at == "entropy-cancel" {
			h.now = h.target
			h.cancel()
		}
	}}
	if h.at == "installed-authority" {
		load = func(RootGrantsAddress) ([]byte, error) { h.now = h.target; return bytes.Clone(h.authority), nil }
	}
	signature, err := rootGrantsTrustContractCountersignSignFromHelperWithRuntime(ctx, raw, plaintext, load, entropy, clock,
		func(key, digest []byte, aux [32]byte) ([]byte, error) {
			h.signs++
			return signNostrWithAux(key, digest, aux)
		})
	if !bytes.Equal(plaintext, make([]byte, len(plaintext))) {
		h.t.Fatal("owned plaintext not cleared")
	}
	return signature, err
}

type trustCountersignExpiryReader struct {
	after func()
	err   error
}

func (r trustCountersignExpiryReader) Read(p []byte) (int, error) {
	r.after()
	if r.err != nil {
		return 0, r.err
	}
	clear(p)
	return len(p), nil
}

type trustCountersignExpiryVault struct {
	snapshot RootGrantsSigningSnapshot
	after    func()
}

func (v *trustCountersignExpiryVault) ReadRootGrantsForSigning(context.Context, RootGrantsAddress, string) (RootGrantsSigningSnapshot, error) {
	v.after()
	return cloneTrustCountersignSnapshot(v.snapshot), nil
}

// Claim: production operation, both parent rechecks and independent helper signing
// refuse clock expiry across synthetic waits, snapshot reads, authority reads and
// entropy, with status 13, no signer call and a zero receipt. Interactions are
// synthetic; this does not execute native presence or its transport.
func TestRootGrantsTrustContractCountersignExpiryOrchestration(t *testing.T) {
	for _, window := range []string{"contract-end", "authority-end"} {
		for _, stage := range []string{"first-wait", "second-wait", "first-wait-read", "second-wait-read", "installed-authority", "entropy"} {
			t.Run(window+"/"+stage, func(t *testing.T) {
				before, after, max := int64(0), int64(2000), int64(1000)
				end := int64(1000)
				if window == "authority-end" {
					after = 1000
					max = 900
				}
				q, raw, snapshot := trustCountersignWindowFixture(t, before, after, max)
				h := &trustCountersignExpiryHelper{t: t, now: 999, at: stage, target: end + 1, authority: raw, snapshot: snapshot}
				got, err := rootGrantsTrustContractCountersignWith(context.Background(), q,
					func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(raw), nil },
					&grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}, h)
				phase := "recheck"
				if stage == "entropy" || stage == "installed-authority" {
					phase = "sign"
				}
				rootTrustCountersignWantHelperFailure(t, err, "binding_mismatch", phase, "not_applied", 13)
				wantRechecks := 2
				if stage == "first-wait" || stage == "first-wait-read" {
					wantRechecks = 1
				}
				if h.signs != 0 || h.rechecks != wantRechecks || !reflect.DeepEqual(got, RootGrantsTrustContractCountersignReceipt{}) {
					t.Fatalf("forbidden signature/receipt or missing recheck: signs=%d rechecks=%d receipt=%#v", h.signs, h.rechecks, got)
				}
			})
		}
	}
}

// Claim: inclusive authority start/end, contract end, still-valid and explicitly
// allowed pre-contract-start times produce one verified raw-contract signature;
// receipt timestamps remain the signed contract's 100..1000 window.
func TestRootGrantsTrustContractCountersignExpiryPositiveControls(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		before, after, max, now int64
	}{
		{"authority-start", 50, 2000, 1000, 50}, {"pre-contract-start", 0, 2000, 1000, 99},
		{"still-valid", 0, 2000, 1000, 999}, {"contract-end-inclusive", 0, 2000, 1000, 1000},
		{"authority-end-inclusive", 0, 1000, 900, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, raw, snapshot := trustCountersignWindowFixture(t, tc.before, tc.after, tc.max)
			h := &trustCountersignExpiryHelper{t: t, now: tc.now, authority: raw, snapshot: snapshot}
			got, err := rootGrantsTrustContractCountersignWith(context.Background(), q,
				func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(raw), nil },
				&grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}, h)
			if err != nil || h.signs != 1 || h.rechecks != 2 || got.Outcome != "signed" || got.NotBefore != 100 || got.NotAfter != 1000 {
				t.Fatalf("valid boundary refused or receipt widened: err=%v signs=%d rechecks=%d receipt=%#v", err, h.signs, h.rechecks, got)
			}
		})
	}
}

// Claim: cancellation during either wait/read or entropy retains its typed
// pre-effect precedence over expiry, with no signer call and a zero receipt.
func TestRootGrantsTrustContractCountersignExpiryCancellation(t *testing.T) {
	for _, stage := range []string{"first-wait-cancel", "second-wait-cancel", "first-wait-read-cancel", "second-wait-read-cancel", "entropy-cancel"} {
		t.Run(stage, func(t *testing.T) {
			q, raw, snapshot := trustCountersignWindowFixture(t, 0, 2000, 1000)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &trustCountersignExpiryHelper{t: t, now: 999, at: stage, target: 1001, authority: raw, snapshot: snapshot, cancel: cancel}
			got, err := rootGrantsTrustContractCountersignWith(ctx, q,
				func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(raw), nil },
				&grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}, h)
			phase := "recheck"
			if stage == "entropy-cancel" {
				phase = "sign"
			}
			rootTrustCountersignWantHelperFailure(t, err, "canceled", phase, "unknown", 14)
			if h.signs != 0 || !reflect.DeepEqual(got, RootGrantsTrustContractCountersignReceipt{}) {
				t.Fatal("cancellation permitted private effect/receipt")
			}
		})
	}
}

// Claim: the independently callable signing path rejects negative, below-start,
// immediately expired and int64-extreme clocks without a signature, clears owned
// plaintext, and preserves entropy/output refusal precedence. No clock cast occurs.
func TestRootGrantsTrustContractCountersignExpiryIndependentHelper(t *testing.T) {
	raw, authority := rootTrustCountersignNativeRequestFixture(t)
	data, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer data.clear()
	for _, now := range []int64{-1, math.MinInt64, 99, 1001, math.MaxInt64} {
		t.Run(strconv.FormatInt(now, 10), func(t *testing.T) {
			signs := 0
			plain := rootTrustCountersignNativePlaintextFixture(t, data.Review.RecordJSON, 3)
			sig, err := rootGrantsTrustContractCountersignSignFromHelperWithRuntime(context.Background(), raw, plain,
				func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authority), nil }, bytes.NewReader(make([]byte, 32)), func() int64 { return now },
				func(key, digest []byte, aux [32]byte) ([]byte, error) {
					signs++
					return signNostrWithAux(key, digest, aux)
				})
			rootTrustCountersignWantHelperFailure(t, err, "binding_mismatch", "sign", "not_applied", 13)
			if signs != 0 || len(sig) != 0 || !bytes.Equal(plain, make([]byte, len(plain))) {
				t.Fatal("invalid time permitted signing or retained plaintext")
			}
		})
	}
	// A failing entropy source keeps its established refusal even when time expired.
	plain := rootTrustCountersignNativePlaintextFixture(t, data.Review.RecordJSON, 3)
	sig, err := rootGrantsTrustContractCountersignSignFromHelperWithRuntime(context.Background(), raw, plain,
		func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authority), nil }, trustCountersignExpiryReader{after: func() {}, err: io.ErrUnexpectedEOF}, func() int64 { return 1001 },
		func([]byte, []byte, [32]byte) ([]byte, error) {
			t.Fatal("entropy failure reached signer")
			return nil, errors.New("unreachable")
		})
	rootTrustCountersignWantHelperFailure(t, err, "operation_unavailable", "sign", "not_applied", 10)
	if len(sig) != 0 || !bytes.Equal(plain, make([]byte, len(plain))) {
		t.Fatal("entropy refusal leaked output/plaintext")
	}
}
