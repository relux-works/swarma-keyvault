package ownerdocument

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

// Public, deterministic synthetic scalar 7 and nonce 11. Never an owner key,
// native helper, presence result or signing-service credential.
var ownerAddress = keyvault.Address{Kind: keyvault.KindKey, Service: "synthetic-owner", Purpose: ownerkey.GrantPurpose, Version: 1}

func fixturePublic(t *testing.T) []byte {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{7})
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func fixtureSignature(t *testing.T, digest []byte) []byte {
	t.Helper()
	n := elliptic.P256().Params().N
	x, _ := elliptic.P256().ScalarBaseMult([]byte{11})
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, big.NewInt(7))
	s.Add(s, new(big.Int).SetBytes(digest))
	s.Mul(s, new(big.Int).ModInverse(big.NewInt(11), n)).Mod(s, n)
	der, err := (keyvault.Signature{R: r, S: s}).LowS().Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func prepared(t *testing.T, document string) *Prepared {
	t.Helper()
	p, err := Prepare(ownerAddress, []byte(document), fixturePublic(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExactBytesAndOwnership(t *testing.T) {
	for _, document := range []string{"Exact English.\nТочный русский.", "Exact English.\n\nТочный русский.\n", "No terminal newline"} {
		t.Run(document, func(t *testing.T) {
			raw, pin := []byte(document), fixturePublic(t)
			p, err := Prepare(ownerAddress, raw, pin)
			if err != nil {
				t.Fatal(err)
			}
			raw[0] ^= 1
			pin[0] ^= 1
			want := sha256.Sum256([]byte(document))
			if p.Digest() != want || p.CheckSource([]byte(document)) != nil {
				t.Fatal("ingress bytes aliased")
			}
			if p.CheckSource(raw) != ErrChanged {
				t.Fatal("changed source accepted")
			}
			der := fixtureSignature(t, want[:])
			if err := p.Verify(der, []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))); err != nil {
				t.Fatal(err)
			}
			changed := prepared(t, document+"!")
			if changed.Verify(der, []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))) != ErrSignature {
				t.Fatal("tampered document verified")
			}
			if p.Prompt(want[:]) == "" {
				t.Fatal("bound prompt missing")
			}
			other := want
			other[31] ^= 1
			if p.Prompt(other[:]) != "" {
				t.Fatal("prompt bound only to prefix")
			}
			full := "mac-keyvault: " + p.Prompt(want[:]) + " with synthetic-owner/grants-owner-v1 v1"
			if utf8.RuneCountInString(full) > 200 || strings.ContainsAny(full, "\r\n\t") {
				t.Fatal("d154 final reason overflows/changes")
			}
		})
	}
}

func TestFullRenderNoTruncation(t *testing.T) {
	// A far-tail sentinel must be present even beyond typical prompt capacity.
	document := strings.Repeat(strings.Repeat("Ж", 70)+"\n", 70) + "TAIL EXACT END"
	p := prepared(t, document)
	var output bytes.Buffer
	if err := p.Render(&output); err != nil {
		t.Fatal(err)
	}
	headerEnd := strings.Index(output.String(), "BEGIN DOCUMENT (next ")
	start := headerEnd + strings.Index(output.String()[headerEnd:], "\n") + 1
	if !bytes.Equal(output.Bytes()[start:start+len(document)], []byte(document)) {
		t.Fatal("document normalized, escaped or truncated")
	}
	if !strings.Contains(output.String(), "terminal LF absent") || !strings.Contains(output.String(), "TAIL EXACT END") {
		t.Fatal("full rendering/LF state missing")
	}
	lf := prepared(t, "Text\n")
	output.Reset()
	_ = lf.Render(&output)
	if !strings.Contains(output.String(), "terminal LF present") || !strings.Contains(output.String(), "Text\n\nEND DOCUMENT") {
		t.Fatal("terminal LF collapsed")
	}
}

type failingWriter struct {
	calls, failAt int
	short         bool
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestRenderFailureAtEveryStage(t *testing.T) {
	p := prepared(t, "Complete text")
	for at := 1; at <= 3; at++ {
		for _, short := range []bool{false, true} {
			w := &failingWriter{failAt: at, short: short}
			if p.Render(w) == nil || w.calls != at {
				t.Fatal("render failure/short write ignored", at, short)
			}
		}
	}
}

func TestAdmissionRefusalsAndBounds(t *testing.T) {
	negative := [][]byte{nil, {0xff}, []byte("\n\n"), []byte("END DOCUMENT"), []byte("BEGIN DOCUMENT"), []byte("x\r\ny"), []byte("x\ty"), []byte("x\x00y"), []byte("\x1b[2Jtext"), []byte("a\u202eb"), []byte("a\u200bb"), []byte("a\u00a0b"), []byte("e\u0301"), []byte("a\u3164b"), []byte(" leading"), []byte("trailing "), []byte("double  space"), []byte("line \nnext"), []byte(strings.Repeat("a", MaxLineScalars+1)), []byte(strings.Repeat("\n", MaxLines)), []byte(strings.Repeat("a", MaxDocumentBytes+1))}
	for i, raw := range negative {
		if _, err := Prepare(ownerAddress, raw, fixturePublic(t)); err == nil {
			t.Fatal("invalid/ambiguous/bounded input admitted", i)
		}
	}
	for _, raw := range []string{strings.Repeat("a", MaxLineScalars), "a" + strings.Repeat("\n", MaxLines-1), "Алексис — подпись.\n\nIvan: exact bytes."} {
		if _, err := Prepare(ownerAddress, []byte(raw), fixturePublic(t)); err != nil {
			t.Fatal("valid neighbor refused", err)
		}
	}
	// Exact byte cap with each physical line within its independent bound.
	raw := strings.Repeat(strings.Repeat("a", 159)+"\n", 102) + strings.Repeat("b", 64)
	if len(raw) != MaxDocumentBytes {
		t.Fatal("bad limit fixture", len(raw))
	}
	if _, err := Prepare(ownerAddress, []byte(raw), fixturePublic(t)); err != nil {
		t.Fatal("exact byte bound refused", err)
	}
	if _, err := Prepare(ownerAddress, []byte(raw+"c"), fixturePublic(t)); err == nil {
		t.Fatal("byte overflow admitted")
	}
}

func TestStrictPublicAndSignature(t *testing.T) {
	p := prepared(t, "Exact")
	for _, pin := range [][]byte{nil, {1, 2, 3}, append(fixturePublic(t), 0), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixturePublic(t)})} {
		if _, err := Prepare(ownerAddress, []byte("Exact"), pin); err != ErrPublic {
			t.Fatal("non-exact DER accepted", err)
		}
	}
	der := fixtureSignature(t, p.digest[:])
	sig, _ := keyvault.ParseSignature(der, keyvault.FormatSignatureDERLowS)
	high, _ := asn1.Marshal(struct{ R, S *big.Int }{sig.R, new(big.Int).Sub(elliptic.P256().Params().N, sig.S)})
	for _, invalid := range [][]byte{nil, {1, 2, 3}, append(bytes.Clone(der), 0), high, bytes.Repeat([]byte{0}, 64)} {
		if p.Verify(invalid, []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))) != ErrSignature {
			t.Fatal("malformed/high-S/non-DER signature verified")
		}
	}
	if p.Verify(der, []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))) != nil {
		t.Fatal("positive neighbor refused")
	}
}

// A detached signature under one public key remains the same signed bytes,
// while a different configured address fails its trusted out-of-band pin.
func TestVerifyConfiguredAddressAssociation(t *testing.T) {
	p := prepared(t, "Exact")
	pin := []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))
	signature := fixtureSignature(t, p.digest[:])
	if err := p.Verify(signature, pin); err != nil {
		t.Fatal("trusted original address failed", err)
	}
	other := ownerAddress
	other.Service = "second-owner"
	p.address = other
	if err := p.Verify(signature, pin); err != ErrOwnerPin {
		t.Fatal("configured address silently changed under a trusted pin", err)
	}
	secondPin := []byte(ownerkey.PublicPin(other, fixturePublic(t)))
	if err := p.Verify(signature, secondPin); err != nil {
		t.Fatal("explicitly enrolled second address failed", err)
	}
}

type reviewFunc func(context.Context, []byte) ([]byte, error)

func (f reviewFunc) ReviewAndConfirm(ctx context.Context, raw []byte) ([]byte, error) {
	return f(ctx, raw)
}

type syntheticStore struct {
	t         *testing.T
	item      keyvault.Item
	signs     int
	events    *[]string
	afterSign func()
	deny      bool
}

func (s *syntheticStore) Serves(keyvault.StoreKind) bool                       { return true }
func (s *syntheticStore) List() ([]keyvault.Item, error)                       { return []keyvault.Item{s.item}, nil }
func (s *syntheticStore) Create(keyvault.CreateOptions) (keyvault.Item, error) { panic("no create") }
func (s *syntheticStore) Delete(string) error                                  { panic("no delete") }
func (s *syntheticStore) UpdateTag(string, []byte) error                       { panic("no rewrite") }
func (s *syntheticStore) Sign(label string, digest []byte) ([]byte, error) {
	if label != ownerAddress.Label() {
		s.t.Fatal("wrong owner key selected")
	}
	s.signs++
	*s.events = append(*s.events, "private-call")
	if s.deny {
		return nil, errors.New("synthetic presence refused")
	}
	der := fixtureSignature(s.t, digest)
	if s.afterSign != nil {
		s.afterSign()
	}
	return der, nil
}

func fixtureManager(t *testing.T, events *[]string, mutate func(*keyvault.Record)) (*keyvault.Manager, *syntheticStore) {
	t.Helper()
	record := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: ownerAddress.Service, Purpose: ownerAddress.Purpose, Version: ownerAddress.Version, Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: true, Extraction: keyvault.ExtractionNone, Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS}, Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "synthetic", Host: "synthetic", Tool: "synthetic", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	if mutate != nil {
		mutate(&record)
	}
	tag, err := keyvault.EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	s := &syntheticStore{t: t, item: keyvault.Item{Label: record.Label(), Tag: tag, SPKI: fixturePublic(t)}, events: events}
	return keyvault.NewManager(s, nil, keyvault.Origin{}), s
}

func TestSyntheticReviewConfirmSignVerifyOrder(t *testing.T) {
	p := prepared(t, "English exact.\nРусский точно.\n")
	var events []string
	m, s := fixtureManager(t, &events, nil)
	r := reviewFunc(func(ctx context.Context, raw []byte) ([]byte, error) {
		// This is an actual full render into a synthetic in-memory sink, not
		// evidence that a native window displayed it or a human consented.
		var rendered bytes.Buffer
		if err := p.Render(&rendered); err != nil || !bytes.Contains(rendered.Bytes(), raw) {
			t.Fatal("synthetic full render failed", err)
		}
		events = append(events, "full-render")
		if !bytes.Equal(raw, p.document) || s.signs != 0 {
			t.Fatal("full exact text not before private call")
		}
		events = append(events, "explicit-confirm")
		return raw, nil
	})
	der, err := p.signWithReview(context.Background(), m, r, func() ([]byte, error) { return bytes.Clone(p.document), nil })
	if err != nil || p.Verify(der, []byte(ownerkey.PublicPin(ownerAddress, fixturePublic(t)))) != nil {
		t.Fatal("synthetic signature failed", err)
	}
	events = append(events, "public-verify")
	if strings.Join(events, ",") != "full-render,explicit-confirm,private-call,public-verify" || s.signs != 1 {
		t.Fatal(events)
	}
}

func TestSyntheticRefusalHasNoPrivateCall(t *testing.T) {
	for _, scenario := range []string{"changed-before", "changed-during-review", "short-confirmed", "modified-confirmed", "review-error", "cancel-review", "cancel-final-source", "source-error", "wrong-generation", "wrong-store", "no-presence", "extractable", "wrong-pin"} {
		t.Run(scenario, func(t *testing.T) {
			p := prepared(t, "Complete exact text")
			current := bytes.Clone(p.document)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var events []string
			m, s := fixtureManager(t, &events, func(r *keyvault.Record) {
				switch scenario {
				case "wrong-generation":
					r.Version = 2
				case "wrong-store":
					r.Store = keyvault.StoreKeychain
				case "no-presence":
					r.UserPresence = false
				case "extractable":
					r.Extraction = keyvault.ExtractionHuman
				}
			})
			if scenario == "wrong-pin" {
				s.item.SPKI = nil
			}
			if scenario == "changed-before" {
				current[0] ^= 1
			}
			reviews := 0
			r := reviewFunc(func(ctx context.Context, raw []byte) ([]byte, error) {
				reviews++
				switch scenario {
				case "changed-during-review":
					current[0] ^= 1
				case "short-confirmed":
					return raw[:len(raw)-1], nil
				case "modified-confirmed":
					raw[0] ^= 1
				case "review-error":
					return nil, io.ErrShortWrite
				case "cancel-review":
					cancel()
				}
				return raw, nil
			})
			reads := 0
			der, err := p.signWithReview(ctx, m, r, func() ([]byte, error) {
				reads++
				if scenario == "cancel-final-source" && reads == 3 {
					cancel()
				}
				if scenario == "source-error" {
					return nil, io.ErrUnexpectedEOF
				}
				return current, nil
			})
			if err == nil || len(der) != 0 || s.signs != 0 {
				t.Fatal("refusal signed/released", err, s.signs)
			}
			wantReviews := 0
			switch scenario {
			case "changed-during-review", "short-confirmed", "modified-confirmed", "review-error", "cancel-review", "cancel-final-source":
				wantReviews = 1
			}
			if reviews != wantReviews {
				t.Fatal("refusal reached the wrong stage", reviews, wantReviews, err)
			}
			if !bytes.Equal(p.document, []byte("Complete exact text")) {
				t.Fatal("review mutated owned plan")
			}
		})
	}
}

func TestAfterDispatchChangeOrCancellationReleasesNothing(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		p := prepared(t, "Exact")
		ctx, cancel := context.WithCancel(context.Background())
		var events []string
		m, s := fixtureManager(t, &events, nil)
		current := bytes.Clone(p.document)
		s.afterSign = func() {
			if cancellation {
				cancel()
			} else {
				current[0] ^= 1
			}
		}
		der, err := p.signWithReview(ctx, m, reviewFunc(func(_ context.Context, raw []byte) ([]byte, error) { return raw, nil }), func() ([]byte, error) { return current, nil })
		cancel()
		if !errors.Is(err, ErrOutcomeUnknown) || len(der) != 0 || s.signs != 1 {
			t.Fatal("post-dispatch change released signature or retried/lost uncertainty", err, s.signs)
		}
	}
}

func TestSyntheticPrivateRefusalDoesNotRetry(t *testing.T) {
	p := prepared(t, "Exact")
	var events []string
	m, s := fixtureManager(t, &events, nil)
	s.deny = true
	der, err := p.signWithReview(context.Background(), m, reviewFunc(func(_ context.Context, raw []byte) ([]byte, error) { return raw, nil }), func() ([]byte, error) { return bytes.Clone(p.document), nil })
	if !errors.Is(err, ErrOutcomeUnknown) || len(der) != 0 || s.signs != 1 {
		t.Fatal("private refusal retried/released or lost uncertainty", err, s.signs)
	}
}

func TestNonDarwinRouteRefusesWithoutCustody(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("non-Darwin refusal only; native route is exercised with synthetic custody separately")
	}
	file := filepath.Join(t.TempDir(), "document.txt")
	if err := os.WriteFile(file, []byte("Exact"), 0600); err != nil {
		t.Fatal(err)
	}
	p := prepared(t, "Exact")
	der, err := p.SignFile(context.Background(), file)
	if err != ErrNativeUnavailable || len(der) != 0 {
		t.Fatal("native gap bypassed", err)
	}
	if err := os.WriteFile(file, []byte("Changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SignFile(context.Background(), file); err != ErrChanged {
		t.Fatal("changed bytes not refused", err)
	}
}

func TestBoundedRegularInput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "document")
	if err := os.WriteFile(file, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadFile(file, 5); err != nil || string(raw) != "12345" {
		t.Fatal(raw, err)
	}
	if _, err := ReadFile(file, 4); err == nil {
		t.Fatal("oversize read")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, filepath.Join(dir, "missing")} {
		if _, err := ReadFile(path, 5); err == nil {
			t.Fatal("nonregular/missing input admitted")
		}
	}
}
