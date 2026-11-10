package grantissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/owneridentity"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

const OwnerMXID = "@fixture-owner:example.invalid"

func fixtureOwnerConfig(t testing.TB) owneridentity.Config {
	t.Helper()
	c, err := owneridentity.New(OwnerMXID, "fixture-owner", ownerkey.GrantPurpose, 1)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Separately generated software keys issue for two explicit principals and
// addresses. Missing/wrong principal refuses preparation, and another root
// cannot reach private sign. This does not qualify any native key or policy.
func TestConfiguredOwnerIssuanceIsolation(t *testing.T) {
	var previous []byte
	for _, who := range []struct {
		principal, service string
		version            int
	}{{OwnerMXID, "fixture-owner", 1}, {"@second:example.invalid", "south", 3}} {
		_, store, _, payload, public := issuerFixture(t)
		if previous != nil && bytes.Equal(previous, public) {
			t.Fatal("owner fixtures reused one key")
		}
		previous = bytes.Clone(public)
		payload = bytes.ReplaceAll(payload, []byte(OwnerMXID), []byte(who.principal))
		cfg, err := owneridentity.New(who.principal, who.service, ownerkey.GrantPurpose, who.version)
		if err != nil {
			t.Fatal(err)
		}
		var record keyvault.Record
		if json.Unmarshal(store.item.Tag, &record) != nil {
			t.Fatal("fixture record decode")
		}
		record.Service, record.Version = who.service, who.version
		store.item.Tag, err = keyvault.EncodeRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		store.item.Label = record.Label()
		manager := keyvault.NewManager(store, nil, keyvault.Origin{})
		if p, err := Prepare(owneridentity.Config{}, payload, public); p != nil || err != owneridentity.ErrConfig {
			t.Fatal("missing owner defaulted")
		}
		wrong := cfg
		wrong.Principal = "@wrong:example.invalid"
		if p, err := Prepare(wrong, payload, public); p != nil || err == nil || store.calls != 0 {
			t.Fatal("other principal accepted")
		}
		wrong = cfg
		wrong.Address.Service = "other-root"
		p, err := Prepare(wrong, payload, public)
		if err != nil {
			t.Fatal("wrong-root fixture setup", err)
		}
		if _, err := p.Sign(manager, io.Discard); err == nil || store.calls != 0 {
			t.Fatal("wrong root reached private operation")
		}
		p, err = Prepare(cfg, payload, public)
		if err != nil {
			t.Fatal("configured owner refused", err)
		}
		envelope, err := p.Sign(manager, io.Discard)
		if err != nil || store.calls != 1 {
			t.Fatal("configured owner did not sign once", err)
		}
		var outer map[string]string
		if json.Unmarshal(envelope, &outer) != nil {
			t.Fatal("envelope decode")
		}
		raw, _ := base64.RawURLEncoding.Strict().DecodeString(outer["payload"])
		sig, _ := base64.RawURLEncoding.Strict().DecodeString(outer["signature"])
		digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), payload...))
		if !bytes.Equal(raw, payload) || !ecdsa.VerifyASN1(&store.key.PublicKey, digest[:], sig) {
			t.Fatal("configured envelope changed signed bytes/key")
		}
	}
}
