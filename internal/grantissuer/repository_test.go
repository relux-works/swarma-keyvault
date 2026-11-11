package grantissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// All keys here are ephemeral software fixtures in this process, never vault
// records or actual owner credentials. The fake counts every private attempt.
type fixtureStore struct {
	item   keyvault.Item
	key    *ecdsa.PrivateKey
	calls  int
	denied error
	bad    bool
}

func (s *fixtureStore) Serves(keyvault.StoreKind) bool { return true }
func (s *fixtureStore) Create(keyvault.CreateOptions) (keyvault.Item, error) {
	panic("issuer tried to create a key")
}
func (s *fixtureStore) List() ([]keyvault.Item, error) { return []keyvault.Item{s.item}, nil }
func (s *fixtureStore) Delete(string) error            { panic("issuer tried to delete a key") }
func (s *fixtureStore) UpdateTag(string, []byte) error {
	panic("issuer tried to rewrite a key")
}
func (s *fixtureStore) Sign(label string, digest []byte) ([]byte, error) {
	s.calls++
	if label != s.item.Label {
		panic("wrong fixture label")
	}
	if s.denied != nil {
		return nil, s.denied
	}
	if s.bad {
		return []byte("not a signature"), nil
	}
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

func issuerFixture(t *testing.T) (*Prepared, *fixtureStore, *keyvault.Manager, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	draft := []byte(`{"audience":{"deployment_id":"fixture","executor_id":"fixture"},"certificate_id":"fixture","cycles":[{"channel":"encrypted-dm","cycle_id":"codex-dm","runtime":"codex"}],"expires_at":"2026-11-04T03:00:00Z","name":"matrix-grants-poc-261031","not_before":"2026-11-04T02:00:00Z","organization":"relux-works","subject":{"account_mxid":"@fixture:example.invalid","device_ed25519":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","device_id":"FIXTURE"}}`)
	unsigned, err := grants.PrepareRepositoryCertificate(draft, OwnerMXID, public)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(fixtureOwnerConfig(t), unsigned.Payload, public)
	if err != nil {
		t.Fatal(err)
	}
	record := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: "fixture-owner", Purpose: "grants-owner-v1", Version: 1,
		Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: true, Extraction: keyvault.ExtractionNone,
		Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "fixture", Host: "fixture", Tool: "fixture", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	tag, err := keyvault.EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	store := &fixtureStore{key: key, item: keyvault.Item{Label: record.Label(), Tag: tag, SPKI: public}}
	manager := keyvault.NewManager(store, nil, keyvault.Origin{})
	return prepared, store, manager, unsigned.Payload, public
}

// The complete typed path signs exactly the original domain+payload once,
// renders all fields and the local-association limit first, and verifies its
// emitted envelope independently using the fixture public key.
func TestTypedRepositoryIssuance(t *testing.T) {
	p, store, manager, payload, _ := issuerFixture(t)
	var review bytes.Buffer
	envelope, err := p.Sign(manager, &review)
	if err != nil || store.calls != 1 {
		t.Fatalf("typed sign: %v calls%d", err, store.calls)
	}
	var outer map[string]string
	if err := json.Unmarshal(envelope, &outer); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(outer["payload"])
	sig, _ := base64.RawURLEncoding.Strict().DecodeString(outer["signature"])
	digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), payload...))
	if outer["type"] != "grants-signed-certificate-1" || !bytes.Equal(raw, payload) || !ecdsa.VerifyASN1(&store.key.PublicKey, digest[:], sig) {
		t.Fatal("envelope/signature differs from exact typed payload")
	}
	parts := strings.SplitN(review.String(), "\n", 6)
	if len(parts) != 6 || !strings.HasPrefix(parts[0], "Owner key pin: key/") || !strings.Contains(parts[1], Organization+"/"+Repository) || !strings.Contains(parts[1], "удаление не выполняется") || !strings.Contains(parts[2], "не подтверждает Matrix identity") {
		t.Fatal("review scope/association limit missing")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(parts[5])); err != nil || !bytes.Equal(compact.Bytes(), payload) {
		t.Fatal("full review differs from signed bytes", err)
	}
	if p.Prompt(digest[:]) == "" || p.Prompt(make([]byte, 32)) != "" {
		t.Fatal("presence prompt not bound to exact digest")
	}
}

// Valid metadata with wrong store/presence/extraction/public pin must stop at
// the actual resolved-key gate with no signature or private attempt. A different
// generation alone cannot satisfy the explicitly selected generation 1.
func TestTypedIssuerKeyRefusals(t *testing.T) {
	for _, mode := range []string{"store", "presence", "extraction", "pin", "generation"} {
		t.Run(mode, func(t *testing.T) {
			p, store, manager, _, _ := issuerFixture(t)
			record, problem := keyvault.DecodeRecord(store.item.Tag)
			if problem != "" {
				t.Fatal(problem)
			}
			switch mode {
			case "store":
				record.Store, record.UserPresence = keyvault.StoreKeychain, false
			case "presence":
				record.UserPresence = false
			case "extraction":
				record.Extraction = keyvault.ExtractionHuman
			case "pin":
				_, _, _, _, public := issuerFixture(t)
				store.item.SPKI = public
			case "generation":
				record.Version = 2
				store.item.Label = record.Label()
			}
			store.item.Tag, _ = keyvault.EncodeRecord(record)
			var review bytes.Buffer
			out, err := p.Sign(manager, &review)
			if mode == "generation" {
				if !errors.Is(err, keyvault.ErrNotFound) {
					t.Fatal("generation 1 unexpectedly available", err)
				}
			} else if mode == "extraction" {
				var refusal *keyvault.Refusal
				if !errors.As(err, &refusal) || refusal.Code != keyvault.CodeMetadataUnknown || !strings.Contains(refusal.Message, keyvault.CodeInvalidExtraction) {
					t.Fatal("invalid enclave extraction policy not refused", err)
				}
			} else if !errors.Is(err, ErrOwnerKeyMismatch) {
				t.Fatal("wrong key policy did not reach intended refusal", err)
			}
			if out != nil || store.calls != 0 || review.Len() != 0 {
				t.Fatal("refusal produced output/review/private call")
			}
		})
	}
}

type badReview struct{ short bool }

func (w badReview) Write(p []byte) (int, error) {
	if w.short {
		return len(p) / 2, nil
	}
	return 0, io.ErrClosedPipe
}

// A failed/short review cannot sign. Backend denial or malformed returned
// signature makes one attempt, emits no envelope and is never retried.
func TestTypedIssuerFailures(t *testing.T) {
	for _, mode := range []string{"review-failed", "review-short", "backend-denied", "bad-signature", "wrong-signing-key"} {
		t.Run(mode, func(t *testing.T) {
			p, store, manager, _, _ := issuerFixture(t)
			var review io.Writer = io.Discard
			want := 0
			switch mode {
			case "review-failed":
				review = badReview{}
			case "review-short":
				review = badReview{short: true}
			case "backend-denied":
				store.denied, want = errors.New("fixture denied"), 1
			case "bad-signature":
				store.bad, want = true, 1
			case "wrong-signing-key":
				_, other, _, _, _ := issuerFixture(t)
				store.key, want = other.key, 1
			}
			out, err := p.Sign(manager, review)
			if err == nil || out != nil || store.calls != want {
				t.Fatalf("failure leaked/retried: %v calls%d", err, store.calls)
			}
			switch mode {
			case "review-failed":
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("wrong review refusal", err)
				}
			case "review-short":
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatal("wrong short-review refusal", err)
				}
			case "backend-denied":
				if !errors.Is(err, store.denied) {
					t.Fatal("wrong backend refusal", err)
				}
			case "bad-signature", "wrong-signing-key":
				var refusal *keyvault.Refusal
				if !errors.As(err, &refusal) || refusal.Code != keyvault.CodeSecurity {
					t.Fatal("wrong malformed backend signature refusal", err)
				}
			}
		})
	}
}

// Mutating the caller's payload and public-pin buffers after preparation cannot
// substitute the bytes reviewed/signed or the expected owner-key pin.
func TestTypedIssuerOwnsInputs(t *testing.T) {
	_, store, manager, payload, public := issuerFixture(t)
	raw, pin := bytes.Clone(payload), bytes.Clone(public)
	p, err := Prepare(fixtureOwnerConfig(t), raw, pin)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	for i := range pin {
		pin[i] = 0
	}
	out, err := p.Sign(manager, io.Discard)
	if err != nil || store.calls != 1 {
		t.Fatal("input aliases changed typed signing", err)
	}
	var outer map[string]string
	if err := json.Unmarshal(out, &outer); err != nil {
		t.Fatal(err)
	}
	got, _ := base64.RawURLEncoding.DecodeString(outer["payload"])
	if !bytes.Equal(got, payload) {
		t.Fatal("caller mutated exact signing bytes")
	}
}

// Payload/schema/issuer/scope changes refuse during preparation, before any
// manager exists. This pairs each forbidden variant with a complete valid plan.
func TestTypedIssuerPreparationRefusals(t *testing.T) {
	_, _, _, payload, public := issuerFixture(t)
	for _, mode := range []string{"time", "owner", "purpose", "target", "second-cycle", "supersedes", "newline", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := Prepare(fixtureOwnerConfig(t), payload, public); err != nil {
				t.Fatal("valid neighbor", err)
			}
			var object map[string]any
			if err := json.Unmarshal(payload, &object); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "time":
				delete(object, "expires_at")
			case "owner":
				object["issuer"].(map[string]any)["owner_mxid"] = "@other:example.invalid"
			case "purpose":
				object["issuer"].(map[string]any)["purpose"] = "git-signing"
			case "target":
				for _, e := range object["entries"].([]any) {
					e.(map[string]any)["target"].(map[string]any)["name"] = "other"
				}
			case "second-cycle":
				object["cycles"] = append(object["cycles"].([]any), map[string]any{"channel": "encrypted-group", "cycle_id": "second", "runtime": "codex"})
				for _, e := range object["entries"].([]any) {
					v := e.(map[string]any)
					v["uses"] = append(v["uses"].([]any), map[string]any{"cycle_id": "second", "operation_use_id": "second/use"})
				}
			case "supersedes":
				object["supersedes"] = []string{"previous"}
			}
			bad, _ := json.Marshal(object)
			pin := public
			if mode == "newline" {
				bad = append(bad, '\n')
			}
			if mode == "wrong-pin" {
				_, _, _, _, pin = issuerFixture(t)
			}
			want := map[string]string{"time": "bad-schema", "owner": "issuer-untrusted", "purpose": "bad-schema", "target": "resource-mismatch", "second-cycle": "schedule-mismatch", "supersedes": "schedule-mismatch", "newline": "bad-encoding", "wrong-pin": "issuer-untrusted"}[mode]
			if got, err := Prepare(fixtureOwnerConfig(t), bad, pin); got != nil || err == nil || err.Error() != want {
				t.Fatalf("invalid typed plan: got %v want %s", err, want)
			}
		})
	}
}
