package main

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// This backend never opens a vault or helper. Its software fixture is neither
// an owner credential nor hardware-presence evidence.
type cliIssueStore struct {
	key              *ecdsa.PrivateKey
	item             keyvault.Item
	signs, factories int
	deny             bool
}

func (s *cliIssueStore) Serves(keyvault.StoreKind) bool { return true }
func (s *cliIssueStore) Create(keyvault.CreateOptions) (keyvault.Item, error) {
	panic("unexpected create")
}
func (s *cliIssueStore) List() ([]keyvault.Item, error) { return []keyvault.Item{s.item}, nil }
func (s *cliIssueStore) Delete(string) error            { panic("unexpected delete") }
func (s *cliIssueStore) UpdateTag(string, []byte) error { panic("unexpected rewrite") }
func (s *cliIssueStore) Sign(_ string, digest []byte) ([]byte, error) {
	s.signs++
	if s.deny {
		return nil, errors.New("fixture denied")
	}
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

func issueCLIFixture(t *testing.T) ([]string, []byte, *cliIssueStore) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, draft, _ := prepareCLIFixture(t)
	var plan map[string]any
	if err := json.Unmarshal(draft, &plan); err != nil {
		t.Fatal(err)
	}
	plan["organization"], plan["name"] = grantissuer.Organization, grantissuer.Repository
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := grants.PrepareRepositoryCertificate(raw, fixtureOwnerPrincipal, public)
	if err != nil {
		t.Fatal(err)
	}
	rec := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: "fixture-owner", Purpose: "grants-owner-v1", Version: 1,
		Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: true, Extraction: keyvault.ExtractionNone,
		Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "fixture", Host: "fixture", Tool: "fixture", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	tag, err := keyvault.EncodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	store := &cliIssueStore{key: key, item: keyvault.Item{Label: rec.Label(), Tag: tag, SPKI: public}}
	previous := newIssueManager
	t.Cleanup(func() { newIssueManager = previous })
	newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
		store.factories++
		digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), unsigned.Payload...))
		if !strings.Contains(prompt(digest[:]), grantissuer.Repository) || prompt(make([]byte, 32)) != "" {
			t.Fatal("unbound prompt factory")
		}
		return keyvault.NewManager(store, nil, keyvault.Origin{})
	}
	pin := filepath.Join(t.TempDir(), "owner-public.der")
	if err := os.WriteFile(pin, public, 0600); err != nil {
		t.Fatal(err)
	}
	return withFixtureOwnerArgs([]string{"grants", "issue", "--payload", "-", "--owner-spki-der", pin}), unsigned.Payload, store
}

// The actual CLI dispatch reads the complete payload, signs once through a
// fake manager, and emits the existing signed envelope with exact original bytes.
func TestIssueCLI(t *testing.T) {
	for _, mode := range []string{"stdin", "file"} {
		t.Run(mode, func(t *testing.T) {
			args, payload, store := issueCLIFixture(t)
			if mode == "file" {
				args[3] = filepath.Join(t.TempDir(), "payload.json")
				if err := os.WriteFile(args[3], payload, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var out, review bytes.Buffer
			if code := run(args, bytes.NewReader(payload), &out, &review); code != 0 || store.signs != 1 || store.factories != 1 {
				t.Fatalf("issue code%d signs%d %s", code, store.signs, review.String())
			}
			var outer map[string]string
			if err := json.Unmarshal(out.Bytes(), &outer); err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.Strict().DecodeString(outer["payload"])
			sig, _ := base64.RawURLEncoding.Strict().DecodeString(outer["signature"])
			digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), payload...))
			if outer["type"] != "grants-signed-certificate-1" || !bytes.Equal(raw, payload) || !ecdsa.VerifyASN1(&store.key.PublicKey, digest[:], sig) {
				t.Fatal("CLI substituted signing bytes")
			}
			if !strings.Contains(review.String(), "удаление не выполняется") || !strings.Contains(review.String(), "не подтверждает Matrix identity") {
				t.Fatal("owner scope/limit absent")
			}
		})
	}
}

// Invalid arguments refuse before reading, and invalid exact payload/pin input
// refuses before the production manager can even be constructed.
func TestIssueCLIRefusalsBeforeManager(t *testing.T) {
	args, payload, store := issueCLIFixture(t)
	for _, bad := range [][]string{
		{"grants", "issue"},
		append(append([]string{}, args...), "--payload=-"),
		append(append([]string{}, args...), "--key=other/purpose"),
		{"grants", "issue", "--payload=-", "--owner-spki-der=-"},
	} {
		var out, review bytes.Buffer
		if code := run(bad, mustNotRead{}, &out, &review); code != 2 || out.Len() != 0 || store.factories != 0 {
			t.Fatal("invalid arguments selected issuer")
		}
	}
	for _, bad := range [][]byte{[]byte(`{}`), append(bytes.Clone(payload), '\n'), bytes.Repeat([]byte{'x'}, 65537)} {
		var out, review bytes.Buffer
		if code := run(args, bytes.NewReader(bad), &out, &review); code != 1 || out.Len() != 0 || store.factories != 0 {
			t.Fatal("invalid payload selected issuer")
		}
	}
}

// Review failure makes no private attempt; a denied backend or failed output
// makes only one attempt and reports failure with no automatic retry/fallback.
func TestIssueCLIFailures(t *testing.T) {
	for _, mode := range []string{"review-error", "review-short", "backend-denied", "output-error", "output-short"} {
		t.Run(mode, func(t *testing.T) {
			args, payload, store := issueCLIFixture(t)
			var out bytes.Buffer
			var writer io.Writer = &out
			var review io.Writer = io.Discard
			want := 1
			switch mode {
			case "review-error":
				review = failingOutput{}
				want = 0
			case "review-short":
				review = failingOutput{short: true}
				want = 0
			case "backend-denied":
				store.deny = true
			case "output-error":
				writer = failingOutput{}
			case "output-short":
				writer = failingOutput{short: true}
			}
			if code := run(args, bytes.NewReader(payload), writer, review); code != 1 || store.signs != want || out.Len() != 0 {
				t.Fatalf("failure: code%d signs%d out%d", code, store.signs, out.Len())
			}
		})
	}
}
