package mugrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// testKeys maps test key ids to their software stand-in private keys.
var testKeys sync.Map

func testPrivate(t *testing.T, id string) *ecdsa.PrivateKey {
	t.Helper()
	k, ok := testKeys.Load(id)
	if !ok {
		t.Fatal("no test key for", id)
	}
	return k.(*ecdsa.PrivateKey)
}

func spkiOf(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func signWire(t *testing.T, k *ecdsa.PrivateKey, p *Plan) []byte {
	t.Helper()
	w, err := AssembleNative(p, signDER(t, k, p.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func agentAttestation(t *testing.T, root, subject, mxid string, nb, ex time.Time) []byte {
	t.Helper()
	p, _, err := BuildMacAgentAttestation(root, spkiOf(t, testPrivate(t, subject)), mxid, 1, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	return signWire(t, testPrivate(t, root), p)
}

func publisherAttestation(t *testing.T, root, publisher string, nb, ex time.Time) []byte {
	t.Helper()
	p, _, err := BuildPublisherAttestation(root, spkiOf(t, testPrivate(t, publisher)), nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	return signWire(t, testPrivate(t, root), p)
}

// attestSpec signs, under the spec issuer, a Mac agent attestation of the
// subject with the spec MXID and a fresh publisher attestation, both with a
// 366-day window from the grant start.
func attestSpec(t *testing.T, s *GrantSpec) {
	t.Helper()
	nb, ex := s.NotBefore.UTC(), s.NotBefore.UTC().Add(MaxAttestationWindow)
	s.SubjectAttestation = agentAttestation(t, s.Issuer, s.Subject, s.SubjectMXID, nb, ex)
	_, publisher := testKey(t)
	s.PublisherAttestation = publisherAttestation(t, s.Issuer, publisher, nb, ex)
}

// Claim (B1 c, r5 constraint 6): a grant builds only when the subject key has
// a Mac agent attestation and the domain a publisher attestation, both
// byte-exact, signed by the grant issuer and covering the whole interval; the
// grantee MXID is the attested one and a different expected MXID refuses. The
// rendering shows the attested MXID and generation and the SPKI SHA-256 of the
// grantee and publisher keys, computed here independently from the keys.
func TestGrantAttestationBinding(t *testing.T) {
	s := metaSpec(t)
	g, err := BuildGrant(s)
	if err != nil {
		t.Fatal("valid control refused", err)
	}
	agent, _ := VerifyMacAgentAttestation(s.SubjectAttestation, s.Issuer)
	publisher, err := VerifyPublisherAttestation(s.PublisherAttestation, s.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	// Expected fingerprints come from the mac-keyvault encoder itself.
	grantee := signerclient.Fingerprint(spkiOf(t, testPrivate(t, s.Subject)))
	pub := signerclient.Fingerprint(spkiOf(t, testPrivate(t, publisher.Key)))
	r := g.Rendering()
	for _, want := range []string{
		fmt.Sprintf("grantee: %s (generation 1, from attestation %s)", agentMXID, agent.ContentID),
		"grantee key fingerprint (as mac-keyvault prints it): " + grantee,
		fmt.Sprintf("revocation publisher key: %s (attestation %s)", publisher.Key, publisher.ContentID),
		"revocation publisher key fingerprint (as mac-keyvault prints it): " + pub,
	} {
		if !strings.Contains(r, want) {
			t.Fatal("rendering misses", want, r)
		}
	}
	nb, ex := s.NotBefore, s.NotBefore.Add(MaxAttestationWindow)
	_, otherRoot := testKey(t)
	_, otherKey := testKey(t)
	cases := map[string]func(*GrantSpec){
		"mxid-mismatch":       func(s *GrantSpec) { s.SubjectMXID = "@fixture-principal-8:example.invalid" },
		"agent-for-other-key": func(s *GrantSpec) { s.SubjectAttestation = agentAttestation(t, s.Issuer, otherKey, agentMXID, nb, ex) },
		"agent-by-other-root": func(s *GrantSpec) {
			s.SubjectAttestation = agentAttestation(t, otherRoot, s.Subject, agentMXID, nb, ex)
		},
		"publisher-by-other-root": func(s *GrantSpec) { s.PublisherAttestation = publisherAttestation(t, otherRoot, otherKey, nb, ex) },
		"agent-window-short": func(s *GrantSpec) {
			s.SubjectAttestation = agentAttestation(t, s.Issuer, s.Subject, agentMXID, nb, s.Expires.Add(-time.Second))
		},
		"agent-window-late": func(s *GrantSpec) {
			s.SubjectAttestation = agentAttestation(t, s.Issuer, s.Subject, agentMXID, nb.Add(time.Second), ex)
		},
		"publisher-window-short": func(s *GrantSpec) {
			s.PublisherAttestation = publisherAttestation(t, s.Issuer, otherKey, nb, s.Expires.Add(-time.Second))
		},
		"publisher-is-subject": func(s *GrantSpec) { s.PublisherAttestation = publisherAttestation(t, s.Issuer, s.Subject, nb, ex) },
		"no-agent":             func(s *GrantSpec) { s.SubjectAttestation = nil },
		"no-publisher":         func(s *GrantSpec) { s.PublisherAttestation = nil },
		"swapped": func(s *GrantSpec) {
			s.SubjectAttestation, s.PublisherAttestation = s.PublisherAttestation, s.SubjectAttestation
		},
		"agent-tampered": func(s *GrantSpec) {
			s.SubjectAttestation = reidentified(t, s.SubjectAttestation, agentMXID, "@fixture-principal-8:example.invalid")
			s.SubjectMXID = "@fixture-principal-8:example.invalid"
		},
	}
	for name, mutate := range cases {
		c := metaSpec(t)
		mutate(&c)
		if _, err := BuildGrant(c); !errors.Is(err, ErrGrantSpec) {
			t.Error("unbound grant admitted", name, err)
		}
	}
}

// reidentified replaces text inside the signed body and recomputes the
// content id, keeping the original signature: only the signature check can
// refuse it.
func reidentified(t *testing.T, wire []byte, old, new string) []byte {
	t.Helper()
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		t.Fatal(err)
	}
	e := parsed.(map[string]any)
	body := e["body"].(map[string]any)
	binding := body["binding"].(map[string]any)
	if binding["mxid"] != old {
		t.Fatal("fixture mxid")
	}
	binding["mxid"] = new
	if e["id"], err = record.ContentID("attestation/1", body); err != nil {
		t.Fatal(err)
	}
	out, err := record.Canonical(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Claim: the attestation verifier admits exactly what the builder signs and
// refuses a foreign envelope member, a second signature, a non-author role
// and malformed input, beside the valid record.
func TestVerifyAttestationShape(t *testing.T) {
	_, root := testKey(t)
	_, subject := testKey(t)
	nb := time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC)
	wire := agentAttestation(t, root, subject, agentMXID, nb, nb.Add(time.Hour))
	if a, err := VerifyMacAgentAttestation(wire, root); err != nil || a.Key != subject || a.MXID != agentMXID || a.Generation != 1 {
		t.Fatal("valid attestation refused", err)
	}
	if _, err := VerifyPublisherAttestation(wire, root); !errors.Is(err, ErrAttestation) {
		t.Error("agent attestation admitted as publisher")
	}
	edit := func(f func(map[string]any)) []byte {
		parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
		if err != nil {
			t.Fatal(err)
		}
		e := parsed.(map[string]any)
		f(e)
		out, err := record.Canonical(e)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for name, raw := range map[string][]byte{
		"extra-member":     edit(func(e map[string]any) { e["note"] = "x" }),
		"second-signature": edit(func(e map[string]any) { e["signatures"] = append(e["signatures"].([]any), e["signatures"].([]any)[0]) }),
		"role-not-author":  edit(func(e map[string]any) { e["signatures"].([]any)[0].(map[string]any)["role"] = "witness" }),
		"other-version":    edit(func(e map[string]any) { e["version"] = "swarm-envelope/1" }),
		"truncated":        wire[:len(wire)/2],
		"empty":            nil,
	} {
		if _, err := VerifyMacAgentAttestation(raw, root); !errors.Is(err, ErrAttestation) {
			t.Error("malformed attestation admitted", name)
		}
	}
	// Signed by the root, but the body carries a member the builder never
	// emits: only the exact-body comparison can refuse it.
	parsed, err := record.Parse(wire, MaxEnvelopeBytes, 16)
	if err != nil {
		t.Fatal(err)
	}
	body := parsed.(map[string]any)["body"].(map[string]any)
	body["note"] = "extra"
	extra, err := record.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare("attestation/1", root, extra)
	if err != nil {
		t.Fatal(err)
	}
	// Root-signed foreign body carrying the legitimate record's id.
	foreign, err := record.Parse(signWire(t, testPrivate(t, root), p), MaxEnvelopeBytes, 16)
	if err != nil {
		t.Fatal(err)
	}
	foreign.(map[string]any)["id"] = parsed.(map[string]any)["id"]
	relabelled, err := record.Canonical(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMacAgentAttestation(relabelled, root); !errors.Is(err, ErrAttestation) {
		t.Error("root-signed foreign body admitted")
	}
	// A re-identified binding with the original signature: only the
	// signature check refuses it.
	if _, err := VerifyMacAgentAttestation(reidentified(t, wire, agentMXID, "@fixture-principal-8:example.invalid"), root); !errors.Is(err, ErrAttestation) {
		t.Error("re-identified attestation admitted")
	}
	if _, err := VerifyMacAgentAttestation(bytes.Clone(wire), subject); !errors.Is(err, ErrAttestation) {
		t.Error("attestation admitted under another root")
	}
}
