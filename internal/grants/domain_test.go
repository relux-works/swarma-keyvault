package grants

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/domain_vectors.json
var domainVectors []byte

// Fixed byte/digest pairs check the four domains and exact input preservation.
// Invalid encodings are intentionally hashable here; this calculation does not
// validate their encoding/schema, authenticate an issuer or authorize an effect.
func TestDomainDigestFixedBytes(t *testing.T) {
	var fixtures []struct {
		Name      string `json:"name"`
		Domain    string `json:"domain"`
		RawBase64 string `json:"raw_base64"`
		Digest    string `json:"digest"`
	}
	if err := json.Unmarshal(domainVectors, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 8 {
		t.Fatalf("fixture count: %d, want 8", len(fixtures))
	}
	domains := map[string]digestDomain{
		"swarma-grants/certificate/1": certificateDomain,
		"swarma-grants/revocation/1":  revocationDomain,
		"swarma-grants/request/1":     requestDomain,
		"swarma-grants/result/1":      resultDomain,
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			domain, ok := domains[fixture.Domain]
			if !ok {
				t.Fatalf("unknown fixture domain %q", fixture.Domain)
			}
			raw, err := base64.StdEncoding.DecodeString(fixture.RawBase64)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(raw)
			got, err := domainDigest(domain, raw)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got[:]) != fixture.Digest {
				t.Fatalf("digest %x, want %s", got, fixture.Digest)
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("digest calculation changed received bytes")
			}
		})
	}
}

// Every domain for the same input has its own independently fixed digest.
// A wrong-domain calculation must not match the intended request digest.
func TestDomainDigestSeparatesKinds(t *testing.T) {
	input := []byte(`{"a":"x","b":true}`)
	tests := []struct {
		domain digestDomain
		want   string
	}{
		{certificateDomain, "26b95b7394ce8f9457aa17560d5fcec6bd6380d434dd9bfcdd84b1f7fb6f93fd"},
		{revocationDomain, "57ffb4b298bb431b5b125941273c0425de66f31f9df3df854bea1569e1fd394e"},
		{requestDomain, "b139b8d0e9c6efb4093b3996b1229b8104a8861ab02b8b5553d43423c080a448"},
		{resultDomain, "47b8fe284bed96dd78beb1694ce873eb872099281f0db62d1b9e5e09bc5d9ee9"},
	}
	seen := map[[32]byte]bool{}
	for _, test := range tests {
		got, err := domainDigest(test.domain, input)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != test.want {
			t.Errorf("domain %d: got %x, want %s", test.domain, got, test.want)
		}
		if seen[got] {
			t.Errorf("domain %d reused another domain's digest", test.domain)
		}
		seen[got] = true
	}
}

// Unknown/zero kind refuses with no digest; a nearby valid request kind works.
func TestDomainDigestRejectsUnknownKind(t *testing.T) {
	raw := []byte(`{"a":"x","b":true}`)
	for _, domain := range []digestDomain{0, 10, 255} {
		before := bytes.Clone(raw)
		got, err := domainDigest(domain, raw)
		if !errors.Is(err, errUnknownDigestDomain) || got != ([32]byte{}) {
			t.Errorf("domain %d: digest %x, error %v", domain, got, err)
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("refusal changed received bytes")
		}
	}
	if _, err := domainDigest(requestDomain, raw); err != nil {
		t.Fatalf("valid control: %v", err)
	}
}

// Fixed independent SHA256 vectors distinguish the application-request and
// owner-certificate domains; appending a final LF changes the signed digest.
func TestA2ADomainFixedVectors(t *testing.T) {
	raw := []byte(`{"a":"x","b":true}`)
	for _, tc := range []struct {
		domain digestDomain
		want   string
	}{
		{a2aCertificateDomain, "8c2430fd885cd7acad82a963e1a1f7113c3f1a890814fa291d1f213bfb32aaa6"},
		{a2aRequestDomain, "5460e7862f02be0f5a2ca3320a12f46df047350bf2cf2bacad31108e17d4c6bd"},
	} {
		got, err := domainDigest(tc.domain, raw)
		if err != nil || hex.EncodeToString(got[:]) != tc.want {
			t.Fatal("fixed vector", tc.domain, got, err)
		}
		changed, err := domainDigest(tc.domain, append(bytes.Clone(raw), '\n'))
		if err != nil || changed == got {
			t.Fatal("terminal LF not bound", err)
		}
	}
}
