package grants_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/grantissuer"
	"github.com/relux-works/swarma-keyvault/internal/grantrequester"
	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/owneridentity"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

// These software keys exist only in memory. The backend refuses all mutation;
// signing counts are not evidence of hardware presence or actual credentials.
type dockingStore struct {
	key   *ecdsa.PrivateKey
	item  keyvault.Item
	calls int
}

func (s *dockingStore) Serves(keyvault.StoreKind) bool { return true }
func (s *dockingStore) Create(keyvault.CreateOptions) (keyvault.Item, error) {
	panic("unexpected create")
}
func (s *dockingStore) List() ([]keyvault.Item, error) { return []keyvault.Item{s.item}, nil }
func (s *dockingStore) Delete(string) error            { panic("unexpected delete") }
func (s *dockingStore) UpdateTag(string, []byte) error { panic("unexpected metadata write") }
func (s *dockingStore) Sign(label string, digest []byte) ([]byte, error) {
	if label != s.item.Label {
		panic("wrong key")
	}
	s.calls++
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}
func dockingKey(t *testing.T, service, purpose string, presence bool) *dockingStore {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: service, Purpose: purpose, Version: 1, Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: presence, Extraction: keyvault.ExtractionNone, Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS}, Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "fixture", Host: "fixture", Tool: "fixture", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	tag, err := keyvault.EncodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return &dockingStore{key: key, item: keyvault.Item{Label: r.Label(), Tag: tag, SPKI: public}}
}
func dockingJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Dock the public authoring -> typed owner signing -> typed requester signing
// -> real mediator/journal/subprocess interfaces, with in-memory keys and a Go
// subprocess fixture only. Success and ambiguous provider failure each hold
// the use across a fresh mediator, including a newly signed request id.
func TestLocalDocking(t *testing.T) {
	for _, mode := range []string{"success", "invalid", "failure"} {
		t.Run(mode, func(t *testing.T) {
			const ownerService = "fixture-owner"
			owner := dockingKey(t, ownerService, ownerkey.GrantPurpose, true)
			requester := dockingKey(t, "swarma-grants", "requester-local-v1", false)
			start := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
			end := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
			subject := map[string]any{"account_mxid": "@fixture:example.invalid", "device_id": "FIXTURE"}
			audience := map[string]any{"deployment_id": "fixture", "executor_id": "fixture"}
			cycle := map[string]any{"cycle_id": "codex-dm", "runtime": "codex", "channel": "encrypted-dm"}
			draft := map[string]any{"audience": audience, "subject": subject, "certificate_id": "docking", "cycles": []any{cycle}, "not_before": start, "expires_at": end, "organization": grants.LocalOrganization, "name": grants.LocalRepository}
			unsigned, err := grants.PrepareLocalRepositoryCertificate(dockingJSON(t, draft), dockingOwnerPrincipal, owner.item.SPKI, requester.item.SPKI)
			if err != nil {
				t.Fatal(err)
			}
			ownerConfig, err := owneridentity.New(dockingOwnerPrincipal, ownerService, ownerkey.GrantPurpose, 1)
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := grantissuer.PrepareLocal(ownerConfig, unsigned.Payload, owner.item.SPKI, requester.item.SPKI)
			if err != nil {
				t.Fatal(err)
			}
			var review bytes.Buffer
			certificate, err := issuer.Sign(keyvault.NewManager(owner, nil, keyvault.Origin{}), &review)
			if err != nil || owner.calls != 1 || !bytes.Contains(review.Bytes(), []byte("docking")) || !bytes.Contains(review.Bytes(), []byte(grants.LocalRepository)) {
				t.Fatal("typed issuance docking", err, owner.calls)
			}
			var payload map[string]any
			if err := json.Unmarshal(unsigned.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			entry := payload["entries"].([]any)[0].(map[string]any)
			use := entry["uses"].([]any)[0].(map[string]any)
			request := map[string]any{"type": "grants-local-operation-1", "request_id": "docking-request", "certificate_id": payload["certificate_id"], "entry_id": entry["entry_id"], "cycle_id": use["cycle_id"], "operation_use_id": use["operation_use_id"], "subject": subject, "audience": audience, "action": entry["action"], "target": entry["target"], "expires_at": end}
			signRequest := func() []byte {
				t.Helper()
				p, err := grantrequester.Prepare(dockingJSON(t, request), requester.item.SPKI)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := p.Sign(keyvault.NewManager(requester, nil, keyvault.Origin{}))
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			attestation := signRequest()
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"type": "grants-local-enrollment-2", "owner_mxid": dockingOwnerPrincipal, "owner_spki": base64.RawURLEncoding.EncodeToString(owner.item.SPKI), "requester_spki": base64.RawURLEncoding.EncodeToString(requester.item.SPKI), "subject": subject, "audience": audience, "cycle": cycle, "organization": grants.LocalOrganization, "name": grants.LocalRepository, "state_dir": root, "gh_path": exe}
			path := filepath.Join(root, "enrollment.json")
			if err := os.WriteFile(path, dockingJSON(t, config), 0600); err != nil {
				t.Fatal(err)
			}
			enrolled, err := grants.LoadLocalEnrollment(path)
			if err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(t.TempDir(), "calls")
			t.Setenv("KEYVAULT_LOCAL_GH_FIXTURE", mode)
			t.Setenv("KEYVAULT_LOCAL_GH_CALLS", calls)
			outcome, err := grants.NewLocalMediator(enrolled).Execute(context.Background(), certificate, attestation)
			if mode == "success" {
				if err != nil || outcome == nil || outcome.State != "succeeded" || outcome.RepositoryID != "42" || outcome.FullName != grants.LocalOrganization+"/"+grants.LocalRepository {
					t.Fatal("successful docking", outcome, err)
				}
			} else if !errors.Is(err, grants.ErrLocalUnknown) || outcome == nil || outcome.State != "unknown" {
				t.Fatal("ambiguous docking", outcome, err)
			}
			before, err := os.ReadFile(filepath.Join(root, "local.journal"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := grants.NewLocalMediator(enrolled).Execute(context.Background(), certificate, attestation); !errors.Is(err, grants.ErrLocalUseHeld) {
				t.Fatal("replay resent", err)
			}
			request["request_id"] = "new-request-id"
			attestation = signRequest()
			if _, err := grants.NewLocalMediator(enrolled).Execute(context.Background(), certificate, attestation); !errors.Is(err, grants.ErrLocalUseHeld) {
				t.Fatal("new id replenished use", err)
			}
			after, err := os.ReadFile(filepath.Join(root, "local.journal"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal modified journal", err)
			}
			actual, err := os.ReadFile(calls)
			if err != nil || string(actual) != "create\n" || owner.calls != 1 || requester.calls != 2 {
				t.Fatal("effect count", err, string(actual), owner.calls, requester.calls)
			}
		})
	}
}
