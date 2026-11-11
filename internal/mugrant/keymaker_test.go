package mugrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

type edTestKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func newEdKey(t *testing.T) edTestKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Ed25519KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return edTestKey{priv, pub, id}
}

func (k edTestKey) sign(t *testing.T, p *Plan) []byte {
	t.Helper()
	w, err := AssembleEd25519(p, ed25519.Sign(k.priv, p.Preimage()))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

var testBinding = KeymakerBinding{UID: 1000, Generation: "generation-1", RegistrationNumber: 7, MasterEpoch: "epoch-1", Owner: "owner:fixture-primary", Path: "agents/linux"}

const linuxTestMXID = "@linux-agent:interop.invalid"

type linuxFixture struct {
	service, agent edTestKey
	spec           GrantSpec
}

// linuxSpec builds a valid grant spec to an Ed25519 grantee: a Keymaker
// attestation current at issuance and the matching registry identity.
func linuxSpec(t *testing.T, mutate func(*KeymakerBinding, *time.Time, *time.Time)) linuxFixture {
	t.Helper()
	f := linuxFixture{service: newEdKey(t), agent: newEdKey(t)}
	base := metaSpec(t)
	at := base.NotBefore
	nb, ex, b := at.Add(-time.Hour), at.Add(20*time.Hour), testBinding
	if mutate != nil {
		mutate(&b, &nb, &ex)
	}
	p, _, err := BuildKeymakerAgentAttestation(f.service.id, f.agent.pub, b, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	base.Subject, base.SubjectMXID = f.agent.id, linuxTestMXID
	base.SubjectAttestation = f.service.sign(t, p)
	base.ServiceRoot = f.service.id
	base.SubjectRegistry = &RegistryIdentity{MXID: linuxTestMXID, UID: testBinding.UID, RegistrationNumber: testBinding.RegistrationNumber}
	base.IssuedAt = at
	f.spec = base
	return f
}

// Claim (contract D3): a grant to an Ed25519 grantee builds when its Keymaker
// attestation verifies under the service root, is current at issuance and
// carries the registry identity; the 30-day grant is not limited by the
// 20-hour attestation. The rendering and the reason show the registry MXID.
// Each refusal changes one fact: attestation not current at issuance, uid or
// registration number different, MXID different, another service root,
// a re-identified attestation, no registry identity, no issuance time.
func TestGrantLinuxGrantee(t *testing.T) {
	f := linuxSpec(t, nil)
	g, err := BuildGrant(f.spec)
	if err != nil {
		t.Fatal("valid control refused", err)
	}
	r, err := g.Reason()
	if err != nil || !strings.Contains(r, linuxTestMXID) || !strings.Contains(g.Rendering(), "Linux agent; registry uid 1000, registration 7") {
		t.Fatal("rendering or reason", r, err)
	}
	other := newEdKey(t)
	cases := map[string]func(*GrantSpec){
		"issued-before-attestation": func(s *GrantSpec) { s.IssuedAt = s.IssuedAt.Add(-2 * time.Hour) },
		"issued-after-attestation":  func(s *GrantSpec) { s.IssuedAt = s.IssuedAt.Add(20 * time.Hour) },
		"uid-differs":               func(s *GrantSpec) { s.SubjectRegistry.UID = 1001 },
		"registration-differs":      func(s *GrantSpec) { s.SubjectRegistry.RegistrationNumber = 8 },
		"mxid-differs":              func(s *GrantSpec) { s.SubjectMXID = "@fixture-principal-9:interop.invalid" },
		"registry-mxid-differs":     func(s *GrantSpec) { s.SubjectRegistry.MXID = "@fixture-principal-9:interop.invalid" },
		"other-service-root":        func(s *GrantSpec) { s.ServiceRoot = other.id },
		"no-registry":               func(s *GrantSpec) { s.SubjectRegistry = nil },
		"no-issuance-time":          func(s *GrantSpec) { s.IssuedAt = time.Time{} },
		"mac-attestation-shape":     func(s *GrantSpec) { s.SubjectAttestation = metaSpec(t).SubjectAttestation },
	}
	for name, mutate := range cases {
		c := linuxSpec(t, nil)
		reg := *c.spec.SubjectRegistry
		c.spec.SubjectRegistry = &reg
		mutate(&c.spec)
		if _, err := BuildGrant(c.spec); !errors.Is(err, ErrGrantSpec) {
			t.Error("unbound linux grant admitted", name, err)
		}
	}
}

// Claim: the Keymaker verifier admits exactly the builder's body under the
// service root and refuses a tampered binding under the original
// signature, another root, and a window over 86 400 s at build time.
func TestKeymakerAttestation(t *testing.T) {
	service, agent := newEdKey(t), newEdKey(t)
	nb := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	p, id, err := BuildKeymakerAgentAttestation(service.id, agent.pub, testBinding, nb, nb.Add(MaxKeymakerWindow))
	if err != nil || id != agent.id {
		t.Fatal("exact 86400 s window refused", err)
	}
	wire := service.sign(t, p)
	k, err := VerifyKeymakerAttestation(wire, service.id)
	if err != nil || k.Key != agent.id || k.Binding != testBinding || k.ContentID != p.ContentID() {
		t.Fatal("valid attestation refused", err)
	}
	if _, _, err := BuildKeymakerAgentAttestation(service.id, agent.pub, testBinding, nb, nb.Add(MaxKeymakerWindow+time.Second)); !errors.Is(err, ErrKeymaker) {
		t.Error("window over 86400 s built")
	}
	if _, err := VerifyKeymakerAttestation(wire, agent.id); !errors.Is(err, ErrKeymaker) {
		t.Error("attestation admitted under another root")
	}
	// Signed by the service root over a body the builder never emits, but
	// carrying the legitimate record's id. Both the exact-body check and the
	// signature check over the builder's preimage refuse it; neither alone is
	// observable here.
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
	fp, err := PrepareEd25519("attestation/1", service.id, extra)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := record.Parse(service.sign(t, fp), MaxEnvelopeBytes, 16)
	if err != nil {
		t.Fatal(err)
	}
	foreign.(map[string]any)["id"] = p.ContentID()
	relabelled, err := record.Canonical(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKeymakerAttestation(relabelled, service.id); !errors.Is(err, ErrKeymaker) {
		t.Error("service-signed foreign body admitted")
	}
	tampered := strings.Replace(string(wire), `"generation-1"`, `"generation-9"`, 1)
	if tampered == string(wire) {
		t.Fatal("fixture")
	}
	if _, err := VerifyKeymakerAttestation([]byte(tampered), service.id); !errors.Is(err, ErrKeymaker) {
		t.Error("tampered binding admitted")
	}
}
