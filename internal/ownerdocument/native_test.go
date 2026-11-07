package ownerdocument

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// A public toy signer exercises the actual native dispatch composition. It has
// no UI, Keychain, owner secret or presence authentication. A passing fixture
// proves the source boundary/order, never native visibility or human consent.
type nativeFixture struct {
	t            *testing.T
	events       []string
	calls        int
	mode         string
	duringReview func()
	afterSign    func()
	last         keyvault.EnclaveRequest
}

func (f *nativeFixture) Call(req keyvault.EnclaveRequest, interactive bool) (keyvault.EnclaveResponse, error) {
	if req.Op != "create" {
		f.t.Fatal("generic helper/sign fallback", req.Op)
	}
	_, pub, err := keyvault.ParseSPKI(fixturePublic(f.t))
	if err != nil {
		f.t.Fatal(err)
	}
	yes := true
	return keyvault.EnclaveResponse{Blob: []byte("public-synthetic-blob"), Point: elliptic.Marshal(elliptic.P256(), pub.X, pub.Y), PresenceEnforced: &yes}, nil
}
func (f *nativeFixture) CallDocument(ctx context.Context, req keyvault.EnclaveRequest, check func(keyvault.DocumentBinding) error) (keyvault.EnclaveResponse, error) {
	f.calls++
	f.last = req
	if req.Op != "review-document" || req.Presence != "required" || req.Document == nil || req.Interaction != "" {
		f.t.Fatal("wrong native dispatch")
	}
	f.events = append(f.events, "full-render", "explicit-confirm")
	if f.duringReview != nil {
		f.duringReview()
	}
	binding := *req.Document
	binding.Document = bytes.Clone(binding.Document)
	binding.Digest = bytes.Clone(binding.Digest)
	binding.Point = bytes.Clone(binding.Point)
	binding.SPKI = bytes.Clone(binding.SPKI)
	switch f.mode {
	case "truncated":
		binding.Document = binding.Document[:len(binding.Document)-1]
	case "changed-text":
		binding.Document[0] ^= 1
	case "changed-digest":
		binding.Digest[0] ^= 1
	case "changed-spki":
		binding.SPKI[0] ^= 1
	case "changed-key":
		binding.Point[1] ^= 1
	case "changed-label":
		binding.Label += "x"
	case "changed-reason":
		binding.Reason += "x"
	case "cancel":
		return keyvault.EnclaveResponse{}, context.Canceled
	}
	if f.mode == "skip-final" {
		return keyvault.EnclaveResponse{DER: fixtureSignature(f.t, req.Document.Digest), Point: binding.Point}, nil
	}
	if err := check(binding); err != nil {
		return keyvault.EnclaveResponse{}, err
	}
	if f.mode == "duplicate-final" {
		_ = check(binding)
	}
	f.events = append(f.events, "private-call")
	if f.mode == "backend-failure" {
		return keyvault.EnclaveResponse{}, errors.New("synthetic native failure")
	}
	der := fixtureSignature(f.t, req.Document.Digest)
	if f.mode == "invalid-signature" {
		der = fixtureSignature(f.t, bytes.Repeat([]byte{0x42}, 32))
	}
	if f.afterSign != nil {
		f.afterSign()
	}
	return keyvault.EnclaveResponse{DER: der, Point: binding.Point}, nil
}

func nativeManagerFixture(t *testing.T) (*keyvault.Manager, *keyvault.EnclaveStore, *nativeFixture) {
	t.Helper()
	f := &nativeFixture{t: t}
	store := keyvault.NewEnclaveStore(filepath.Join(t.TempDir(), "enclave"), f)
	m := keyvault.NewOwnerDocumentManager(store)
	record := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1, Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: true, Extraction: keyvault.ExtractionNone, Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS}, Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "synthetic", Host: "synthetic", Tool: "synthetic", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	tag, err := keyvault.EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(keyvault.CreateOptions{Label: record.Label(), Tag: tag, Store: keyvault.StoreEnclave, UserPresence: true})
	if err != nil {
		t.Fatal(err)
	}
	return m, store, f
}

func TestNativeTypedDispatchExactBytesOrder(t *testing.T) {
	for _, text := range []string{"Exact without terminal LF", strings.Repeat("Русский полный текст.\n", 60)} {
		t.Run(fmt.Sprint(len(text)), func(t *testing.T) {
			p := prepared(t, text)
			m, _, f := nativeManagerFixture(t)
			checks := 0
			der, err := p.signNative(context.Background(), m, func() error { checks++; return nil })
			if err != nil || p.Verify(der) != nil {
				t.Fatal("typed native fixture failed", err)
			}
			f.events = append(f.events, "public-verify")
			if strings.Join(f.events, ",") != "full-render,explicit-confirm,private-call,public-verify" || f.calls != 1 || checks != 4 {
				t.Fatal(f.events, f.calls, checks)
			}
			if !bytes.Equal(f.last.Document.Document, []byte(text)) || len(f.last.Document.Reason) > 200 || !strings.Contains(f.last.Document.Reason, fmt.Sprintf("%x", p.digest)) || !strings.HasSuffix(f.last.Document.Reason, " with alexis/grants-owner-v1 v1") {
				t.Fatal("bytes/full digest/actual key reason drift")
			}
		})
	}
}

func TestNativeTypedDispatchTamperAndRefusal(t *testing.T) {
	for _, mode := range []string{"truncated", "changed-text", "changed-digest", "changed-key", "changed-spki", "changed-label", "changed-reason", "cancel", "source-changed", "context-canceled", "custody-changed", "backend-failure", "invalid-signature", "after-sign-change", "after-sign-cancel", "skip-final", "duplicate-final"} {
		t.Run(mode, func(t *testing.T) {
			p := prepared(t, "Complete exact text\n")
			m, store, f := nativeManagerFixture(t)
			f.mode = mode
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			current := bytes.Clone(p.document)
			switch mode {
			case "source-changed":
				f.duringReview = func() { current[0] ^= 1 }
			case "context-canceled":
				f.duringReview = cancel
			case "custody-changed":
				f.duringReview = func() {
					if err := os.Remove(filepath.Join(store.Dir, ownerAddress.Label()+".json")); err != nil {
						t.Fatal(err)
					}
				}
			case "after-sign-change":
				f.afterSign = func() { current[0] ^= 1 }
			case "after-sign-cancel":
				f.afterSign = cancel
			}
			der, err := p.signNative(ctx, m, func() error {
				if e := ctx.Err(); e != nil {
					return e
				}
				return p.CheckSource(current)
			})
			if err == nil || len(der) != 0 || f.calls != 1 || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("refusal released/retried or lost uncertainty", err, len(der), f.calls)
			}
			signed := strings.Contains(strings.Join(f.events, ","), "private-call")
			want := mode == "backend-failure" || mode == "invalid-signature" || mode == "after-sign-change" || mode == "after-sign-cancel" || mode == "duplicate-final"
			if signed != want {
				t.Fatal("wrong private boundary", f.events)
			}
		})
	}
}

func TestNativeTypedDispatchWrongPinRefusesBeforeReview(t *testing.T) {
	p := prepared(t, "Exact")
	m, _, f := nativeManagerFixture(t)
	x, y := elliptic.P256().ScalarBaseMult([]byte{9})
	p.public, _ = x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	der, err := p.signNative(context.Background(), m, func() error { return nil })
	if !errors.Is(err, ErrPublic) || len(der) != 0 || f.calls != 0 {
		t.Fatal(err, f.calls)
	}
}
