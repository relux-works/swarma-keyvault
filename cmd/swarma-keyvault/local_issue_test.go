package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func localIssueCLIFixture(t *testing.T) ([]string, []byte, *cliIssueStore, []byte) {
	t.Helper()
	args, raw, store := issueCLIFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["type"] = "grants-local-certificate-1"
	payload["requester_spki_sha256"] = hex.EncodeToString(pin[:])
	delete(payload["subject"].(map[string]any), "device_ed25519")
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "requester.der")
	if err := os.WriteFile(path, der, 0600); err != nil {
		t.Fatal(err)
	}
	// The shared fixture restores the original factory during cleanup. Bind its
	// replacement to this local payload, independently of the production digest.
	digest := sha256.Sum256(append([]byte("swarma-grants/local-certificate/1\n"), raw...))
	newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
		store.factories++
		text := prompt(digest[:])
		if !bytes.Contains([]byte(text), []byte("grant local repository.create")) ||
			!bytes.Contains([]byte(text), []byte("relux-works/matrix-grants-poc-261031")) || prompt(make([]byte, 32)) != "" {
			t.Fatal("unbound local prompt factory")
		}
		return keyvault.NewManager(store, nil, keyvault.Origin{})
	}
	return withFixtureOwnerArgs([]string{"grants", "local-issue", "--payload", "-", "--owner-spki-der", args[5], "--requester-spki-der", path}), raw, store, der
}

// Explicit local authoring and issuance retain exact signed fields, render the
// local disclosure/full requester hash and make one fake private call only.
func TestLocalPrepareIssueCLI(t *testing.T) {
	args, payload, store, requester := localIssueCLIFixture(t)
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	draft := map[string]any{"certificate_id": value["certificate_id"], "subject": value["subject"], "audience": value["audience"], "cycles": value["cycles"], "not_before": value["not_before"], "expires_at": value["expires_at"], "organization": "relux-works", "name": "matrix-grants-poc-261031"}
	raw, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	var out, review bytes.Buffer
	prepare := []string{"grants", "local-prepare", "--plan", "-", "--owner-mxid", fixtureOwnerPrincipal, "--issuer-spki-der", args[5], "--requester-spki-der", args[7]}
	if code := run(prepare, bytes.NewReader(raw), &out, &review); code != 0 || !bytes.Equal(out.Bytes(), payload) || store.signs != 0 || store.factories != 0 {
		t.Fatal("local prepare", code, review.String())
	}
	out.Reset()
	review.Reset()
	if code := run(args, bytes.NewReader(payload), &out, &review); code != 0 || store.signs != 1 || store.factories != 1 {
		t.Fatal("local issue", code, review.String())
	}
	hash := sha256.Sum256(requester)
	if !bytes.Contains(review.Bytes(), []byte("Ни одно устройство Matrix не аутентифицировано.")) || !bytes.Contains(review.Bytes(), []byte(hex.EncodeToString(hash[:]))) {
		t.Fatal("local disclosure missing")
	}
}

// Missing, duplicate, malformed and mismatching requester inputs and Matrix
// payload confusion all refuse before constructing the fake signing manager.
func TestLocalIssueCLIRefusesBeforeFactory(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "wrong-pin", "bad-der", "Matrix"} {
		t.Run(mode, func(t *testing.T) {
			args, payload, store, _ := localIssueCLIFixture(t)
			switch mode {
			case "missing":
				args = args[:6]
			case "duplicate":
				args = append(args, "--requester-spki-der", args[7])
			case "wrong-pin":
				args[7] = args[5]
			case "bad-der":
				if err := os.WriteFile(args[7], []byte("invalid DER"), 0600); err != nil {
					t.Fatal(err)
				}
			case "Matrix":
				payload = bytes.Replace(payload, []byte("grants-local-certificate-1"), []byte("grants-certificate-1"), 1)
			}
			var out, review bytes.Buffer
			if code := run(args, bytes.NewReader(payload), &out, &review); code == 0 || out.Len() != 0 || store.signs != 0 || store.factories != 0 {
				t.Fatal("preprivate refusal", code, store.signs, store.factories)
			}
		})
	}
}
