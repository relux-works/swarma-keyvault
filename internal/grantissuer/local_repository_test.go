package grantissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

func localIssuerFixture(t *testing.T) (*Prepared, *fixtureStore, *keyvault.Manager, []byte, []byte, []byte) {
	t.Helper()
	_, store, manager, raw, owner := issuerFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["type"] = "grants-local-certificate-1"
	delete(payload["subject"].(map[string]any), "device_ed25519")
	hash := sha256.Sum256(requester)
	payload["requester_spki_sha256"] = hex.EncodeToString(hash[:])
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PrepareLocal(fixtureOwnerConfig(t), raw, owner, requester)
	if err != nil {
		t.Fatal(err)
	}
	return p, store, manager, raw, owner, requester
}

// The local typed path signs exact local-domain bytes once and discloses the
// entire payload/full signed requester pin before the sole fake private call.
func TestLocalTypedIssuance(t *testing.T) {
	p, store, manager, raw, owner, requester := localIssuerFixture(t)
	var review bytes.Buffer
	envelope, err := p.Sign(manager, &review)
	if err != nil || store.calls != 1 {
		t.Fatal(err, store.calls)
	}
	var outer map[string]string
	if err := json.Unmarshal(envelope, &outer); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(outer["payload"])
	sig, _ := base64.RawURLEncoding.DecodeString(outer["signature"])
	digest := sha256.Sum256(append([]byte("swarma-grants/local-certificate/1\n"), raw...))
	if outer["type"] != "grants-signed-local-certificate-1" || !bytes.Equal(payload, raw) || !ecdsa.VerifyASN1(&store.key.PublicKey, digest[:], sig) {
		t.Fatal("local envelope/domain")
	}
	const disclosure = "Ни одно устройство Matrix не аутентифицировано. encrypted-dm — только заявленная метка; этот локальный путь ничего не шифрует и не доставляет через Matrix."
	hash := sha256.Sum256(requester)
	if !strings.Contains(review.String(), disclosure+"\n") || !strings.Contains(review.String(), "Requester SPKI SHA256: "+hex.EncodeToString(hash[:])+"\n") || !strings.HasPrefix(p.Prompt(digest[:]), "grant local repository.create ") {
		t.Fatal("local honesty/pin/presence prompt")
	}
	if _, err := Prepare(fixtureOwnerConfig(t), raw, owner); err == nil {
		t.Fatal("Matrix issuer accepted local payload")
	}
	if _, err := PrepareLocal(fixtureOwnerConfig(t), raw, owner, owner); err == nil {
		t.Fatal("wrong independent requester accepted")
	}
	_, _, _, _, _, other := localIssuerFixture(t)
	if _, err := PrepareLocal(fixtureOwnerConfig(t), raw, owner, other); err == nil {
		t.Fatal("different valid independent requester accepted")
	}
}

// Both failed and short review sinks refuse before the private attempt, with
// a successful review neighbor proving the local issuer does not reject all.
func TestLocalTypedReviewRefusal(t *testing.T) {
	for _, w := range []io.Writer{badReview{}, badReview{short: true}} {
		p, store, manager, _, _, _ := localIssuerFixture(t)
		if got, err := p.Sign(manager, w); err == nil || got != nil || store.calls != 0 {
			t.Fatal("review refusal", err, store.calls)
		}
	}
}
