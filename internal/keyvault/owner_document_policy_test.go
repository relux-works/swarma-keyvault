package keyvault

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// This synthetic peer stops at dispatch: no signature, native UI, presence,
// owner key or cryptographic private operation is involved.
type documentPolicyPeer struct {
	point        []byte
	duringReview func()
	reviews      int
	dispatches   int
}

var errDocumentPolicyBoundary = errors.New("synthetic peer stopped at private dispatch")

func (p *documentPolicyPeer) Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error) {
	if req.Op != "create" {
		return EnclaveResponse{}, errors.New("unexpected generic helper route")
	}
	yes := true
	return EnclaveResponse{Blob: []byte("synthetic-public-blob"), Point: p.point, PresenceEnforced: &yes}, nil
}

func (p *documentPolicyPeer) CallDocument(ctx context.Context, req EnclaveRequest, check func(DocumentBinding) error) (EnclaveResponse, error) {
	p.reviews++
	p.duringReview()
	if err := check(*req.Document); err != nil {
		return EnclaveResponse{}, err
	}
	p.dispatches++
	return EnclaveResponse{}, errDocumentPolicyBoundary
}

func TestOwnerDocumentFinalPolicy(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		before       time.Duration
		review       time.Duration
		final        time.Duration
		noExpiry     bool
		cancelFinal  bool
		cancelPolicy bool
		sourceRefuse bool
		wantReviews  int
		wantFinal    int
		wantDispatch int
		wantExpired  bool
	}{
		{name: "already-expired", before: time.Second, wantExpired: true},
		{name: "before-expiry", review: -time.Nanosecond, wantReviews: 1, wantFinal: 1, wantDispatch: 1},
		{name: "at-expiry", wantReviews: 1, wantFinal: 1, wantExpired: true},
		{name: "expires-during-review", review: time.Second, wantReviews: 1, wantFinal: 1, wantExpired: true},
		{name: "no-expiry-neighbor", review: time.Second, noExpiry: true, wantReviews: 1, wantFinal: 1, wantDispatch: 1},
		{name: "expires-during-source-check", review: -time.Second, final: time.Second, wantReviews: 1, wantFinal: 1, wantExpired: true},
		{name: "cancel-during-source-check", review: -time.Second, cancelFinal: true, wantReviews: 1, wantFinal: 1},
		{name: "cancel-during-policy-check", review: -time.Second, cancelPolicy: true, wantReviews: 1, wantFinal: 1},
		{name: "source-refusal", review: -time.Second, sourceRefuse: true, wantReviews: 1, wantFinal: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixed := Address{Kind: KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1}
			start := time.Unix(1800000000, 0)
			expiry := NewTime(start.Add(time.Minute))
			now := start
			if scenario.before != 0 {
				now = expiry.Add(scenario.before)
			}
			x, y := elliptic.P256().ScalarBaseMult([]byte{7})
			peer := &documentPolicyPeer{point: elliptic.Marshal(elliptic.P256(), x, y)}
			store := NewEnclaveStore(filepath.Join(t.TempDir(), "synthetic-custody"), peer)
			record := testRecord(fixed.Label())
			record.Store, record.UserPresence = StoreEnclave, true
			if !scenario.noExpiry {
				record.Validity.NotAfter = &expiry
			}
			tag, err := EncodeRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Create(CreateOptions{Label: fixed.Label(), Tag: tag, Store: StoreEnclave, UserPresence: true}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := NewOwnerDocumentManager(store)
			manager.SetClock(func() time.Time {
				if scenario.cancelPolicy && peer.reviews != 0 {
					cancel()
				}
				return now
			})
			peer.duringReview = func() { now = expiry.Add(scenario.review) }
			finals := 0
			sourceErr := errors.New("synthetic source changed")
			document := []byte("Exact synthetic document")
			digest := sha256.Sum256(document)
			result, err := manager.SignOwnerDocument(ctx, fixed, digest[:], document,
				func(ResolvedSigningKey) error { return nil }, func() error {
					finals++
					now = now.Add(scenario.final)
					if scenario.cancelFinal {
						cancel()
					}
					if scenario.sourceRefuse {
						return sourceErr
					}
					return nil
				})
			t.Logf("review=%d final=%d dispatch=%d clock=%s expiry=%s result=%v", peer.reviews, finals, peer.dispatches, now.Format(time.RFC3339Nano), expiry.Format(time.RFC3339Nano), err)
			if err == nil || result.Signature.R != nil || result.Signature.S != nil {
				t.Fatal("synthetic boundary released a signature", result, err)
			}
			if peer.reviews != scenario.wantReviews || finals != scenario.wantFinal || peer.dispatches != scenario.wantDispatch {
				t.Fatalf("review/final/dispatch = %d/%d/%d; want %d/%d/%d", peer.reviews, finals, peer.dispatches, scenario.wantReviews, scenario.wantFinal, scenario.wantDispatch)
			}
			if scenario.wantExpired {
				var refusal *Refusal
				if !errors.As(err, &refusal) || refusal.Code != CodeExpired {
					t.Fatal("lost expiry refusal", err)
				}
			} else if scenario.cancelFinal || scenario.cancelPolicy {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("lost cancellation", err)
				}
			} else if scenario.sourceRefuse {
				if !errors.Is(err, sourceErr) {
					t.Fatal("lost source refusal", err)
				}
			} else if !errors.Is(err, errDocumentPolicyBoundary) {
				t.Fatal("unexpired control did not reach synthetic boundary", err)
			}
		})
	}
}
