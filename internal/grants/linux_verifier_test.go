package grants

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// These fakes are protected in-process test fixtures, not registry providers.
// All private test keys are generated ephemerally and never leave the process.
type linuxVerifierFake struct {
	agent                               LinuxRegistryAgent
	attestations                        map[string][]byte
	snapshots                           map[string]LinuxSnapshot
	state                               LinuxVerificationState
	agentErr, attErr, snapErr, stateErr error
	lookups                             []string
	calls                               int
	requestHashes                       [][32]byte
}

func (f *linuxVerifierFake) CurrentAgent(string) (LinuxRegistryAgent, error) {
	f.calls++
	return f.agent, f.agentErr
}
func (f *linuxVerifierFake) Attestation(id string) ([]byte, error) {
	f.lookups = append(f.lookups, id)
	return f.attestations[id], f.attErr
}
func (f *linuxVerifierFake) Snapshot(root string) (LinuxSnapshot, error) {
	return f.snapshots[root], f.snapErr
}
func (f *linuxVerifierFake) VerificationState(requestHash [32]byte) (LinuxVerificationState, error) {
	f.requestHashes = append(f.requestHashes, requestHash)
	return f.state, f.stateErr
}

// Explicit fake session assurance, independently supplied from author keys.
func linuxVerifierAssurance(t *testing.T, level string) verifier.Evidence {
	t.Helper()
	e, err := verifier.Present(map[string]any{"level": level, "presence": false})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type linuxVerifierDock struct {
	t                                    *testing.T
	now                                  time.Time
	root, pub                            muKey
	service, revoker, agent              ed25519.PrivateKey
	serviceID, revokerID, agentID, attID string
	attBody                              map[string]any
	grantBody                            map[string]any
	config                               LinuxVerifierConfig
	fake                                 *linuxVerifierFake
	event                                MUEnvelopeEvent
}

func linuxVerifierEd(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, "ed25519:" + base64.RawURLEncoding.EncodeToString(pub)
}
func linuxVerifierSign(t *testing.T, key string, priv ed25519.PrivateKey, body map[string]any) []byte {
	t.Helper()
	kind := body["type"].(string)
	id, err := record.ContentID(kind, body)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := record.SigningPreimage(kind, key, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"key": key, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, pre))}}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func (g *linuxVerifierDock) signRoot(body map[string]any) []byte {
	g.t.Helper()
	b, err := record.Canonical(body)
	if err != nil {
		g.t.Fatal(err)
	}
	p, err := mugrant.Prepare(body["type"].(string), g.root.id, b)
	if err != nil {
		g.t.Fatal(err)
	}
	return g.root.sign(g.t, p)
}
func newLinuxVerifierDock(t *testing.T) *linuxVerifierDock {
	t.Helper()
	g := &linuxVerifierDock{t: t, now: time.Date(2026, 11, 5, 15, 0, 0, 0, time.UTC), root: newMUKey(t), pub: newMUKey(t)}
	g.service, g.serviceID = linuxVerifierEd(t)
	g.revoker, g.revokerID = linuxVerifierEd(t)
	g.agent, g.agentID = linuxVerifierEd(t)
	a := LinuxRegistryAgent{Key: g.agentID, MXID: "@linux:example.invalid", UID: 1000, RegistrationNumber: 42, Generation: "gen-1", MasterEpoch: "epoch-1", Owner: "owner:fixture-primary", Path: "agents/linux", Active: true}
	binding := a.binding()
	delete(binding, "active")
	g.attBody = map[string]any{"type": "attestation/1", "issuer": g.serviceID, "subject": map[string]any{"algorithm": "Ed25519", "key_id": g.agentID, "public_bytes": strings.TrimPrefix(g.agentID, "ed25519:")}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "binding": binding, "iat": g.now.Add(-time.Hour).Format(time.RFC3339), "exp": g.now.Add(time.Hour).Format(time.RFC3339)}
	att := linuxVerifierSign(t, g.serviceID, g.service, g.attBody)
	g.attID, _ = muRecordID(att, "attestation/1")
	pp, _, err := mugrant.BuildPublisherAttestation(g.root.id, g.pub.spki, g.now.Add(-time.Hour), g.now.AddDate(0, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	publisher := g.root.sign(t, pp)
	g.grantBody = map[string]any{"type": "grant/1", "aud": "linux-receiver-test", "nonce": base64.RawURLEncoding.EncodeToString(make([]byte, 16)), "iat": g.now.Add(-time.Hour).Format(time.RFC3339), "exp": g.now.AddDate(0, 1, 0).Format(time.RFC3339), "not_before": g.now.Add(-time.Hour).Format(time.RFC3339), "expires": g.now.AddDate(0, 1, 0).Format(time.RFC3339), "issuer": g.root.id, "subject": g.agentID, "actions": []any{"work.assign"}, "targets": []any{map[string]any{"kind": "product", "id": "swarma-platform"}}, "depth": int64(0), "parent": nil, "min_assurance": map[string]any{"level": "A2", "presence": false}, "caveats": map[string]any{"lang": "caveats/v2", "use": "until_expiry", "not_before": g.now.Add(-time.Hour).Format(time.RFC3339), "expires": g.now.AddDate(0, 1, 0).Format(time.RFC3339)}}
	g.config = LinuxVerifierConfig{GrantRoot: g.root.id, ServiceRoot: g.serviceID, AgentRevocationRoot: g.revokerID, PublisherKey: g.pub.id, Publisher: publisher, Audience: "linux-receiver-test", RoomID: "!requests:example.invalid", ReceiverMXID: "@receiver:example.invalid", Grants: [][]byte{g.signRoot(g.grantBody)}}
	g.config.LinuxAgents = map[string]MULinuxAgent{a.MXID: {Key: a.Key, UID: a.UID, RegistrationNumber: a.RegistrationNumber}}
	g.fake = &linuxVerifierFake{agent: a, attestations: map[string][]byte{g.attID: att}, snapshots: map[string]LinuxSnapshot{}, state: LinuxVerificationState{Now: g.now, AuthorityUntil: g.now.Add(time.Minute), Watermark: g.now, Trusted: true, Fresh: true, WatermarkAvailable: true, IDJournalAvailable: true, IDJournal: map[string][]byte{}, Assurance: linuxVerifierAssurance(t, "A2")}}
	g.snapshot(g.pub.id, g.now.Add(-5*time.Second), nil)
	g.snapshot(g.revokerID, g.now.Add(-5*time.Second), nil)
	g.request("request")
	return g
}
func (g *linuxVerifierDock) snapshot(root string, at time.Time, entries []any) {
	if entries == nil {
		entries = []any{}
	}
	b := map[string]any{"type": "revocation/1", "issuer": root, "issued_at": at.Format(time.RFC3339), "complete": true, "entries": entries}
	var wire []byte
	if root == g.pub.id {
		raw, err := record.Canonical(b)
		if err != nil {
			g.t.Fatal(err)
		}
		p, err := mugrant.Prepare("revocation/1", root, raw)
		if err != nil {
			g.t.Fatal(err)
		}
		wire = g.pub.sign(g.t, p)
	} else {
		wire = linuxVerifierSign(g.t, root, g.revoker, b)
	}
	g.fake.snapshots[root] = LinuxSnapshot{Wire: wire, Available: true, RollbackSafe: true}
}
func (g *linuxVerifierDock) request(text string) {
	// The landed builder prepares only P-256. Use its body as the fixture
	// template, then replace the author and sign with an ephemeral Ed25519 key.
	r, err := mugrant.BuildRequest(mugrant.RequestSpec{Author: g.root.id, AuthorAttestation: g.attID, Audience: g.config.Audience, Room: g.config.RoomID, To: g.config.ReceiverMXID, Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: "swarma-platform"}, Arguments: map[string]string{"module": "swarma-keyvault"}, Text: text, Nonce: make([]byte, 16), IssuedAt: g.now.Add(-time.Second), Lifetime: 120 * time.Second})
	if err != nil {
		g.t.Fatal(err)
	}
	b, err := record.Parse(r.Plan().Body(), 65536, 16)
	if err != nil {
		g.t.Fatal(err)
	}
	b.(map[string]any)["author"] = g.agentID
	g.event = MUEnvelopeEvent{Sender: g.fake.agent.MXID, Receiver: g.config.ReceiverMXID, Room: g.config.RoomID, EventID: "$request", Text: []byte(text), Envelope: linuxVerifierSign(g.t, g.agentID, g.agent, b.(map[string]any))}
}
func (g *linuxVerifierDock) adapter() *LinuxVerifier {
	g.t.Helper()
	p, err := NewLinuxVerifier(g.config, g.fake, g.fake, func(room, id string) (MUEnvelopeEvent, error) { return g.event, nil })
	if err != nil {
		g.t.Fatal(err)
	}
	return p
}
func linuxVerifierCode(err error) string {
	if err == nil {
		return "accept"
	}
	var e *ErrMUPlatform
	if errors.As(err, &e) {
		return e.Code
	}
	var r *record.Error
	if errors.As(err, &r) {
		return r.Code
	}
	return err.Error()
}
func linuxVerifierWant(t *testing.T, g *linuxVerifierDock, want string) {
	t.Helper()
	d, err := g.adapter().VerifyProjected(g.event, g.now)
	if got := linuxVerifierCode(err); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if err != nil && (d.Author != "" || d.Use != "" || d.RequestHash != [32]byte{}) {
		t.Fatal("refusal leaked decision", d)
	}
}

// Claim: Current Keymaker attestations admit long-lived Linux grants without requiring whole-interval attestation coverage.
func TestLinuxVerifierCurrentKeymakerLongGrant(t *testing.T) {
	g := newLinuxVerifierDock(t)
	p := g.adapter()
	d, err := p.VerifyProjected(g.event, g.now)
	if err != nil || d.Use != "until_expiry" || d.Author != g.agentID || d.AuthorAttestation != g.attID || len(g.fake.lookups) != 1 || g.fake.lookups[0] != g.attID {
		t.Fatal(d, err, g.fake.lookups)
	}
	a, err := p.AdmitLinuxGrantee(g.agentID, g.attID, g.fake.agent.MXID, 1000, 42, g.now)
	if err != nil || a.Key != g.agentID {
		t.Fatal(a, err)
	}
	// Evidence is refreshed on every request; an already-created verifier cannot
	// keep admitting a generation after it ceases to be current.
	g.fake.agent.Active = false
	if _, err = p.VerifyProjected(g.event, g.now); linuxVerifierCode(err) != "key_binding_invalid" {
		t.Fatal(err)
	}
	if g.fake.calls != 3 {
		t.Fatal("not refreshed per invocation", g.fake.calls)
	}
}

// Claim: Missing, expired or mismatched Keymaker identity and generation evidence refuses with the specified platform code.
func TestLinuxVerifierRegistryAdmission(t *testing.T) {
	cases := []struct {
		name string
		edit func(*linuxVerifierDock)
		want string
	}{
		{"registry-unavailable", func(g *linuxVerifierDock) { g.fake.agentErr = errors.New("offline") }, "key_binding_unavailable"},
		{"by-id-unavailable", func(g *linuxVerifierDock) { g.fake.attErr = errors.New("offline") }, "key_binding_unavailable"},
		{"by-id-missing", func(g *linuxVerifierDock) { delete(g.fake.attestations, g.attID) }, "key_binding_unavailable"},
		{"sender-substitution", func(g *linuxVerifierDock) { g.event.Sender = "@fixture-principal-9:example.invalid" }, "mu-sender-not-attested"},
		{"inactive", func(g *linuxVerifierDock) { g.fake.agent.Active = false }, "key_binding_invalid"},
		{"key-substitution", func(g *linuxVerifierDock) { g.fake.agent.Key = g.serviceID }, "key_binding_unavailable"},
		{"uid-mismatch", func(g *linuxVerifierDock) { g.fake.agent.UID++ }, "key_binding_unavailable"},
		{"registration-reused", func(g *linuxVerifierDock) { g.fake.agent.RegistrationNumber++ }, "key_binding_unavailable"},
		{"generation-changed", func(g *linuxVerifierDock) { g.fake.agent.Generation = "gen-2" }, "key_binding_invalid"},
		{"epoch-changed", func(g *linuxVerifierDock) { g.fake.agent.MasterEpoch = "epoch-2" }, "key_binding_invalid"},
		{"owner-mismatch", func(g *linuxVerifierDock) { g.fake.agent.Owner = "owner:fixture-3" }, "key_binding_invalid"},
		{"path-mismatch", func(g *linuxVerifierDock) { g.fake.agent.Path = "other/path" }, "key_binding_invalid"},
		{"expired-attestation-live-grant", func(g *linuxVerifierDock) { g.attBody["exp"] = g.now.Format(time.RFC3339); g.replaceAttestation() }, "key_binding_invalid"},
		{"future-attestation", func(g *linuxVerifierDock) {
			g.attBody["iat"] = g.now.Add(time.Second).Format(time.RFC3339)
			g.replaceAttestation()
		}, "key_binding_invalid"},
		{"window-over-24h", func(g *linuxVerifierDock) {
			g.attBody["exp"] = g.now.Add(24 * time.Hour).Format(time.RFC3339)
			g.replaceAttestation()
		}, "key_binding_invalid"},
		{"wrong-root-signature", func(g *linuxVerifierDock) {
			g.fake.attestations[g.attID] = linuxVerifierSign(g.t, g.revokerID, g.revoker, g.attBody)
		}, "key_binding_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLinuxVerifierDock(t)
			linuxVerifierWant(t, g, "accept")
			tc.edit(g)
			linuxVerifierWant(t, g, tc.want)
		})
	}
}
func (g *linuxVerifierDock) replaceAttestation() {
	att := linuxVerifierSign(g.t, g.serviceID, g.service, g.attBody)
	g.attID, _ = muRecordID(att, "attestation/1")
	g.fake.attestations[g.attID] = att
	g.request("request")
}

// Claim: Unqualified time, unavailable or stale snapshots and rollback refuse; the inclusive freshness boundary admits.
func TestLinuxVerifierProtectedClockAndSnapshots(t *testing.T) {
	cases := []struct {
		name string
		edit func(*linuxVerifierDock)
		want string
	}{
		{"assurance-unavailable", func(g *linuxVerifierDock) { g.fake.state.Assurance = verifier.Evidence{} }, "grant_assurance_unavailable"},
		{"keymaker-identity-is-only-A1", func(g *linuxVerifierDock) { g.fake.state.Assurance = linuxVerifierAssurance(g.t, "A1") }, "grant_assurance_insufficient"},
		{"clock-missing", func(g *linuxVerifierDock) { g.fake.stateErr = errors.New("offline") }, "time_unavailable"},
		{"clock-untrusted", func(g *linuxVerifierDock) { g.fake.state.Trusted = false }, "time_unavailable"},
		{"clock-stale", func(g *linuxVerifierDock) { g.fake.state.Fresh = false }, "time_unavailable"},
		{"clock-disagrees", func(g *linuxVerifierDock) { g.fake.state.Now = g.now.Add(time.Second) }, "time_unavailable"},
		{"clock-expired", func(g *linuxVerifierDock) { g.fake.state.AuthorityUntil = g.now }, "time_unavailable"},
		{"watermark-unavailable", func(g *linuxVerifierDock) { g.fake.state.WatermarkAvailable = false }, "watermark_unavailable"},
		{"journal-unavailable", func(g *linuxVerifierDock) { g.fake.state.IDJournalAvailable = false }, "id_journal_unavailable"},
		{"journal-nil", func(g *linuxVerifierDock) { g.fake.state.IDJournal = nil }, "id_journal_unavailable"},
		{"publisher-unavailable", func(g *linuxVerifierDock) { delete(g.fake.snapshots, g.pub.id) }, "revocation_unavailable"},
		{"registry-snapshot-unavailable", func(g *linuxVerifierDock) { delete(g.fake.snapshots, g.revokerID) }, "revocation_unavailable"},
		{"publisher-stale-61", func(g *linuxVerifierDock) { g.snapshot(g.pub.id, g.now.Add(-61*time.Second), nil) }, "revocation_unavailable"},
		{"registry-stale-61", func(g *linuxVerifierDock) { g.snapshot(g.revokerID, g.now.Add(-61*time.Second), nil) }, "key_binding_unavailable"},
		{"publisher-future", func(g *linuxVerifierDock) { g.snapshot(g.pub.id, g.now.Add(time.Second), nil) }, "revocation_unavailable"},
		{"publisher-rollback", func(g *linuxVerifierDock) {
			s := g.fake.snapshots[g.pub.id]
			s.RollbackSafe = false
			g.fake.snapshots[g.pub.id] = s
		}, "revocation_unavailable"},
		{"registry-rollback", func(g *linuxVerifierDock) {
			s := g.fake.snapshots[g.revokerID]
			s.RollbackSafe = false
			g.fake.snapshots[g.revokerID] = s
		}, "key_binding_unavailable"},
		{"revoked-agent", func(g *linuxVerifierDock) {
			g.snapshot(g.revokerID, g.now, []any{map[string]any{"kind": "key", "id": g.agentID, "from": g.now.Add(-time.Hour).Format(time.RFC3339)}})
		}, "revoked"},
		{"revoked-attestation", func(g *linuxVerifierDock) {
			g.snapshot(g.revokerID, g.now, []any{map[string]any{"kind": "record", "id": g.attID, "from": g.now.Format(time.RFC3339)}})
		}, "revoked"},
		{"revoked-grant", func(g *linuxVerifierDock) {
			id, _ := muRecordID(g.config.Grants[0], "grant/1")
			g.snapshot(g.pub.id, g.now, []any{map[string]any{"kind": "record", "id": id, "from": g.now.Format(time.RFC3339)}})
		}, "revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLinuxVerifierDock(t)
			linuxVerifierWant(t, g, "accept")
			tc.edit(g)
			linuxVerifierWant(t, g, tc.want)
		})
	}
	g := newLinuxVerifierDock(t)
	g.snapshot(g.pub.id, g.now.Add(-60*time.Second), nil)
	g.snapshot(g.revokerID, g.now.Add(-60*time.Second), nil)
	linuxVerifierWant(t, g, "accept")
}

// Claim: The shared text rule runs before identity and envelope checks, and projected event custody is exact.
func TestLinuxVerifierTextAndProjection(t *testing.T) {
	for _, text := range []string{"", " \t\n", strings.Repeat("a", 4097), "a\rb", "a\x00b", "a\u007fb", "a\u0085b", "a\ufffdb", "a\u202eb", "a\u2066b", "a\u200fb", string([]byte{0xff})} {
		g := newLinuxVerifierDock(t)
		g.event.Text = []byte(text)
		g.event.Envelope = []byte("malformed")
		g.fake.stateErr = errors.New("unavailable")
		linuxVerifierWant(t, g, "mu-request-text-refused")
	}
	for _, text := range []string{"a\tb\nc", strings.Repeat("a", 4096), strings.Repeat("Ж", 2048)} {
		g := newLinuxVerifierDock(t)
		g.request(text)
		linuxVerifierWant(t, g, "accept")
	}
	g := newLinuxVerifierDock(t)
	g.event.Text = []byte("substituted text")
	linuxVerifierWant(t, g, "message_text_mismatch")
	for _, edit := range []func(*linuxVerifierDock){func(g *linuxVerifierDock) { g.event.Room = "#swarma-grant-revocation:example.invalid" }, func(g *linuxVerifierDock) { g.event.Receiver = "@fixture-principal-9:example.invalid" }, func(g *linuxVerifierDock) { g.event.EventID = "bad" }} {
		g := newLinuxVerifierDock(t)
		edit(g)
		linuxVerifierWant(t, g, ErrMUProjection.Error())
	}
	g = newLinuxVerifierDock(t)
	p := g.adapter()
	ev := MUEvent{SenderMXID: g.event.Sender, RoomID: g.event.Room, EventID: g.event.EventID, Envelope: bytes.Clone(g.event.Envelope)}
	if _, err := p.Verify(ev, g.now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*MUEvent){func(e *MUEvent) { e.RoomID = "!fixture-principal-1:example.invalid" }, func(e *MUEvent) { e.EventID = "$other" }, func(e *MUEvent) { e.SenderMXID = "@fixture-principal-9:example.invalid" }, func(e *MUEvent) { e.Envelope = append(e.Envelope, ' ') }} {
		bad := ev
		change(&bad)
		if _, err := p.Verify(bad, g.now); !errors.Is(err, ErrMUProjection) {
			t.Fatal("projection mismatch accepted", err)
		}
	}
}

// Claim: Issuance requires the exact current Keymaker attestation and protected registry identity.
func TestLinuxVerifierIssuanceGate(t *testing.T) {
	g := newLinuxVerifierDock(t)
	p := g.adapter()
	for _, identity := range []struct {
		mxid     string
		uid, reg int64
	}{{"@fixture-principal-9:example.invalid", 1000, 42}, {g.fake.agent.MXID, 1001, 42}, {g.fake.agent.MXID, 1000, 43}} {
		if _, err := p.AdmitLinuxGrantee(g.agentID, g.attID, identity.mxid, identity.uid, identity.reg, g.now); linuxVerifierCode(err) != "key_binding_invalid" {
			t.Fatal("issuance identity mismatch", err)
		}
	}
	g.attBody["exp"] = g.now.Format(time.RFC3339)
	g.replaceAttestation()
	if _, err := p.AdmitLinuxGrantee(g.agentID, g.attID, g.fake.agent.MXID, 1000, 42, g.now); linuxVerifierCode(err) != "key_binding_invalid" {
		t.Fatal("expired issuance attestation", err)
	}
}

// Claim: Invalid or aliased protected pins refuse construction, and copying prevents caller mutation from changing policy.
func TestLinuxVerifierPinsAndPolicyCopy(t *testing.T) {
	for _, edit := range []func(*LinuxVerifierConfig){func(c *LinuxVerifierConfig) { c.ServiceRoot = "" }, func(c *LinuxVerifierConfig) { c.AgentRevocationRoot = c.ServiceRoot }, func(c *LinuxVerifierConfig) { c.RoomID = "#alias:example.invalid" }, func(c *LinuxVerifierConfig) { c.PublisherKey = c.GrantRoot }, func(c *LinuxVerifierConfig) { c.ReceiverMXID = "receiver" }, func(c *LinuxVerifierConfig) { c.Publisher = []byte("bad") }} {
		g := newLinuxVerifierDock(t)
		edit(&g.config)
		if _, err := NewLinuxVerifier(g.config, g.fake, g.fake, nil); err == nil {
			t.Fatal("invalid protected policy admitted")
		}
	}
	g := newLinuxVerifierDock(t)
	p := g.adapter()
	g.config.Publisher[0] = '!'
	g.config.Grants[0][0] = '!'
	g.config.Grants[0] = nil
	if _, err := p.VerifyProjected(g.event, g.now); err != nil {
		t.Fatal("policy alias mutation", err)
	}
}

// Claim: Mac authors retain pinned generation and whole-interval requirements through the Linux verifier.
func TestLinuxVerifierMacProfile(t *testing.T) {
	// Same real verifier and existing Mac builders, synthetic software P-256
	// stand-ins. This is not Secure Enclave or cross-host qualification.
	g := newMUDock(t)
	g.request("$mac", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault"}, "Mac request")
	_, serviceID := linuxVerifierEd(t)
	_, revokerID := linuxVerifierEd(t)
	f := &linuxVerifierFake{snapshots: map[string]LinuxSnapshot{g.pub.id: {Wire: g.snapshot, Available: true, RollbackSafe: true}}, state: LinuxVerificationState{Now: g.now, AuthorityUntil: g.now.Add(time.Minute), Watermark: g.now, Trusted: true, Fresh: true, WatermarkAvailable: true, IDJournalAvailable: true, IDJournal: map[string][]byte{}, Assurance: linuxVerifierAssurance(t, "A2")}}
	c := LinuxVerifierConfig{GrantRoot: g.root.id, ServiceRoot: serviceID, AgentRevocationRoot: revokerID, PublisherKey: g.pub.id, Publisher: g.pubAtt, Audience: muDockAud, RoomID: muDockRoom, ReceiverMXID: muDockReceiver, Grants: [][]byte{g.grant}, MacAgents: map[string]MUMacAgent{muDockSender: {Key: g.sender.id, Attestation: g.att, Generation: 1}}}
	p, err := NewLinuxVerifier(c, f, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := p.VerifyProjectedWithSnapshots(g.events["$mac"], g.now)
	d := verified.Decision
	if err != nil || d.Author != g.sender.id || len(verified.SnapshotMarks) != 1 || !verified.SnapshotMarks[g.pub.id].Equal(g.now.Add(-5*time.Second)) {
		t.Fatal(verified, err)
	}
	// Mutating the source config after construction cannot replace pinned Mac evidence.
	a := c.MacAgents[muDockSender]
	a.Attestation[0] = '!'
	a.Generation = 2
	c.MacAgents[muDockSender] = a
	if _, err := p.VerifyProjected(g.events["$mac"], g.now); err != nil {
		t.Fatal("Mac config was not copied", err)
	}
	c.MacAgents[muDockSender] = MUMacAgent{Key: g.sender.id, Attestation: p.config.MacAgents[muDockSender].Attestation, Generation: 2}
	p, err = NewLinuxVerifier(c, f, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyProjected(g.events["$mac"], g.now); linuxVerifierCode(err) != "key_binding_invalid" {
		t.Fatal("stale Mac generation", err)
	}

	// Whole-interval cover remains mandatory for Mac grantees. A currently
	// valid short Mac attestation cannot authenticate this month-long grant.
	short, _, err := mugrant.BuildMacAgentAttestation(g.root.id, g.sender.spki, muDockSender, 1, g.now.Add(-time.Hour), g.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	g.att = g.root.sign(t, short)
	g.attID = short.ContentID()
	g.request("$mac-short", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault"}, "short Mac attestation")
	c.MacAgents[muDockSender] = MUMacAgent{Key: g.sender.id, Attestation: g.att, Generation: 1}
	p, err = NewLinuxVerifier(c, f, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyProjected(g.events["$mac-short"], g.now); linuxVerifierCode(err) != "key_binding_invalid" {
		t.Fatal("Mac whole-interval coverage lost", err)
	}
	if f.calls != 0 || len(f.lookups) != 0 {
		t.Fatal("Mac profile fell through to Linux registry")
	}
}

// Claim: Malformed or unauthorized requests and grants refuse without a candidate decision.
func TestLinuxVerifierGrantAndEnvelopeRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(*linuxVerifierDock)
		want string
	}{
		{"wrong-signature", func(g *linuxVerifierDock) {
			b, _ := muMessageBody(g.event.Envelope)
			g.event.Envelope = linuxVerifierSign(g.t, g.agentID, g.revoker, b)
		}, "envelope_signature_invalid"},
		{"wrong-scope", func(g *linuxVerifierDock) {
			b, _ := muMessageBody(g.event.Envelope)
			b["action"] = "work.accept"
			g.event.Envelope = linuxVerifierSign(g.t, g.agentID, g.agent, b)
		}, ErrMUNoGrant.Error()},
		{"expired-grant", func(g *linuxVerifierDock) {
			at := g.now.Format(time.RFC3339)
			g.grantBody["exp"] = at
			g.grantBody["expires"] = at
			g.grantBody["caveats"].(map[string]any)["expires"] = at
			g.config.Grants[0] = g.signRoot(g.grantBody)
		}, "expired"},
		{"foreign-root", func(g *linuxVerifierDock) {
			other := newMUKey(g.t)
			g.grantBody["issuer"] = other.id
			b, _ := record.Canonical(g.grantBody)
			p, _ := mugrant.Prepare("grant/1", other.id, b)
			g.config.Grants[0] = other.sign(g.t, p)
		}, "key_binding_unavailable"},
		{"ambiguous-grants", func(g *linuxVerifierDock) { g.config.Grants = append(g.config.Grants, g.config.Grants[0]) }, ErrMUAmbiguous.Error()},
		{"nested-arguments", func(g *linuxVerifierDock) {
			b, _ := muMessageBody(g.event.Envelope)
			b["arguments"] = map[string]any{"module": map[string]any{"nested": "bad"}}
			g.event.Envelope = linuxVerifierSign(g.t, g.agentID, g.agent, b)
		}, ErrMUState.Error()},
		{"unknown-member", func(g *linuxVerifierDock) {
			b, _ := muMessageBody(g.event.Envelope)
			b["extra"] = true
			g.event.Envelope = linuxVerifierSign(g.t, g.agentID, g.agent, b)
		}, "envelope_malformed"},
		{"message-lifetime-over-120", func(g *linuxVerifierDock) {
			b, _ := muMessageBody(g.event.Envelope)
			b["exp"] = g.now.Add(120 * time.Second).Format(time.RFC3339)
			g.event.Envelope = linuxVerifierSign(g.t, g.agentID, g.agent, b)
		}, "envelope_malformed"},
		{"by-id-substitution", func(g *linuxVerifierDock) {
			g.attBody["exp"] = g.now.Add(2 * time.Hour).Format(time.RFC3339)
			g.fake.attestations[g.attID] = linuxVerifierSign(g.t, g.serviceID, g.service, g.attBody)
		}, "author_attestation_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLinuxVerifierDock(t)
			linuxVerifierWant(t, g, "accept")
			tc.edit(g)
			linuxVerifierWant(t, g, tc.want)
		})
	}
}

// Claim: Concurrent requests use their exact referenced attestation without substituting a peer reference.
func TestLinuxVerifierExactConcurrentAttestations(t *testing.T) {
	g := newLinuxVerifierDock(t)
	old := g.event
	oldID := g.attID
	g.attBody["exp"] = g.now.Add(2 * time.Hour).Format(time.RFC3339)
	g.replaceAttestation()
	if oldID == g.attID {
		t.Fatal("expected distinct references")
	}
	p := g.adapter()
	for _, ev := range []MUEnvelopeEvent{old, g.event} {
		d, err := p.VerifyProjected(ev, g.now)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := muMessageBody(ev.Envelope)
		if d.AuthorAttestation != strOr(body["author_attestation"]) {
			t.Fatal("attestation selector substituted")
		}
	}
	if len(g.fake.lookups) != 2 || g.fake.lookups[0] != oldID || g.fake.lookups[1] != g.attID {
		t.Fatal(g.fake.lookups)
	}
	for i, ev := range []MUEnvelopeEvent{old, g.event} {
		if g.fake.requestHashes[i] != sha256.Sum256(ev.Envelope) {
			t.Fatal("state not bound to exact envelope")
		}
	}
}

// r4 M-N-snapshot-older requires a same-call sequence handoff. The verifier
// returns older/equal/future-in-sequence marks; the receiver owns durable order.
// Claim: Each invocation returns its own independently copied signer marks and exact request hash.
func TestLinuxVerifierSnapshotSequenceHandoff(t *testing.T) {
	g := newLinuxVerifierDock(t)
	p := g.adapter()
	result, err := p.VerifyProjectedWithSnapshots(g.event, g.now)
	if err != nil {
		t.Fatal(err)
	}
	pubAt, revAt := g.now.Add(-5*time.Second), g.now.Add(-5*time.Second)
	if len(result.SnapshotMarks) != 2 || !result.SnapshotMarks[g.pub.id].Equal(pubAt) || !result.SnapshotMarks[g.revokerID].Equal(revAt) || result.Decision.RequestHash != sha256.Sum256(g.event.Envelope) {
		t.Fatal("missing exact per-signer marks", result)
	}
	// Caller mutation and a newer source sample cannot alter the earlier result.
	result.SnapshotMarks[g.pub.id] = g.now.Add(time.Hour)
	g.snapshot(g.pub.id, g.now.Add(-6*time.Second), nil)
	next, err := p.VerifyWithSnapshots(MUEvent{SenderMXID: g.event.Sender, RoomID: g.event.Room, EventID: g.event.EventID, Envelope: g.event.Envelope}, g.now)
	if err != nil || len(next.SnapshotMarks) != 2 || !next.SnapshotMarks[g.pub.id].Equal(g.now.Add(-6*time.Second)) || !next.SnapshotMarks[g.revokerID].Equal(revAt) {
		t.Fatal("older verified sequence lost in bridge", next, err)
	}
	// A refusal must expose neither a candidate nor apparently verified marks.
	g.event.Sender = "@unregistered:example.invalid"
	refused, err := p.VerifyProjectedWithSnapshots(g.event, g.now)
	if !errors.Is(err, ErrMUSender) || refused.Decision.Author != "" || refused.SnapshotMarks != nil {
		t.Fatal("sender witness refusal or metadata custody", refused, err)
	}
}
