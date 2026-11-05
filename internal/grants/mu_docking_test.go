package grants

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Software stand-ins for Secure Enclave keys; tests only.
type muKey struct {
	priv *ecdsa.PrivateKey
	spki []byte
	id   string
}

func newMUKey(t *testing.T) muKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	id, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	return muKey{k, spki, id}
}

func (k muKey) sign(t *testing.T, p *mugrant.Plan) []byte {
	t.Helper()
	d := p.Digest()
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mugrant.AssembleNative(p, der)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

const (
	muDockMeta     = "@meta-keeper.keeper-sirius:gr.relux.works"
	muDockReceiver = "@keyvault.orch-altair:gr.relux.works"
	muDockRoom     = "!room:gr.relux.works"
	muDockAud      = "swarma-keyvault-receiver"
)

type muDock struct {
	t                  *testing.T
	now                time.Time
	root, meta, pub    muKey
	grant, att, pubAtt []byte
	attID              string
	snapshot           []byte
	events             map[string]MUEnvelopeEvent
	receiver           *MUReceiver
	effect             *countingEffect
}

func newMUDock(t *testing.T) *muDock {
	t.Helper()
	g := &muDock{t: t, now: time.Date(2026, 11, 5, 18, 0, 0, 0, time.UTC), root: newMUKey(t), meta: newMUKey(t), pub: newMUKey(t), events: map[string]MUEnvelopeEvent{}}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	grant, err := mugrant.BuildGrant(mugrant.GrantSpec{Issuer: g.root.id, Subject: g.meta.id, SubjectMXID: muDockMeta, Audience: muDockAud,
		Entries:   []mugrant.Entry{{Action: "work.assign", Target: mugrant.Target{Kind: "product", ID: "swarma-platform"}}, {Action: "account.manage", Target: mugrant.Target{Kind: "account-scope", ID: "owner:alexis"}}},
		NotBefore: g.now.Add(-time.Hour), Expires: g.now.Add(30 * 24 * time.Hour), Use: mugrant.UseUntilExpiry, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	g.grant = g.root.sign(t, grant.Plan())
	ap, _, err := mugrant.BuildMacAgentAttestation(g.root.id, g.meta.spki, muDockMeta, 1, g.now.Add(-2*time.Hour), g.now.Add(60*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	g.att, g.attID = g.root.sign(t, ap), ap.ContentID()
	pp, _, err := mugrant.BuildPublisherAttestation(g.root.id, g.pub.spki, g.now.Add(-2*time.Hour), g.now.Add(60*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	g.pubAtt = g.root.sign(t, pp)
	g.publish(g.now.Add(-5*time.Second), nil)
	dir := filepath.Join(t.TempDir(), "mu")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("dock"))}
	binding := MUBinding{Audience: muDockAud, GrantRoot: g.root.id}
	if err := InitializeMUState(state, binding); err != nil {
		t.Fatal(err)
	}
	platform := NewMUPlatform(MUPlatformConfig{GrantRoot: g.root.id, Audience: muDockAud, Grants: [][]byte{g.grant},
		Agents:    map[string]MUMacAgent{muDockMeta: {Key: g.meta.id, Attestation: g.att, Generation: 1}},
		Publisher: g.pubAtt, PublisherKey: g.pub.id, Snapshot: func() ([]byte, error) { return g.snapshot, nil }, TimeAuthority: 5 * time.Minute},
		func(id string) (MUEnvelopeEvent, error) {
			e, ok := g.events[id]
			if !ok {
				return MUEnvelopeEvent{}, errors.New("no such event")
			}
			return e, nil
		})
	reg := fakeRegistry{keys: map[string]string{muDockMeta: g.meta.id}, owners: map[string]string{"@agent-a:gr.relux.works": "owner:alexis", "@ivan-agent:relux.works": "owner:ivan"}}
	g.effect = &countingEffect{}
	g.receiver = NewMUReceiver(MUReceiverConfig{Binding: binding, State: state, Owner: "owner:alexis", RoomScope: "swarma-space", Modules: map[string]bool{"swarma-keyvault": true}, Paused: map[string]bool{}},
		platform, reg, map[string]MUEffect{"work.assign": g.effect, "account.manage": g.effect})
	g.receiver.now = func() time.Time { return g.now }
	return g
}

func (g *muDock) publish(at time.Time, entries []mugrant.SnapshotEntry) {
	p, err := mugrant.BuildSnapshot(g.pub.id, at, entries)
	if err != nil {
		g.t.Fatal(err)
	}
	g.snapshot = g.pub.sign(g.t, p)
}

// request signs a message/1 by Meta's key and registers its projection.
func (g *muDock) request(eventID, action, kind, id string, args map[string]string, text string) {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	r, err := mugrant.BuildRequest(mugrant.RequestSpec{Author: g.meta.id, AuthorAttestation: g.attID, Audience: muDockAud, Room: muDockRoom, To: muDockReceiver,
		Action: action, Target: mugrant.Target{Kind: kind, ID: id}, Arguments: args, Text: text, Nonce: nonce, IssuedAt: g.now.Add(-time.Second), Lifetime: 120 * time.Second})
	if err != nil {
		g.t.Fatal(err)
	}
	g.events[eventID] = MUEnvelopeEvent{Sender: muDockMeta, Receiver: muDockReceiver, Room: muDockRoom, EventID: eventID, Envelope: g.meta.sign(g.t, r.Plan()), Text: []byte(text)}
}

func (g *muDock) handle(eventID string) (*MUOutcome, error) {
	return g.receiver.Handle(context.Background(), MUEvent{SenderMXID: muDockMeta, RoomID: muDockRoom, EventID: eventID})
}

func platformCode(err error) string {
	var p *ErrMUPlatform
	if errors.As(err, &p) {
		return p.Code
	}
	return ""
}

// Claim (docking, platform verifier at the pinned swarma-envelope commit, all
// records built by our issuer/requester and signed by software stand-ins):
// the sitting sequence holds end to end: an in-scope work.assign under the
// until_expiry grant succeeds, a second one with a fresh nonce succeeds, a
// replay of the second refuses without a new effect, and account.manage on an
// Ivan-side account refuses before reservation.
func TestMUDockingSittingSequence(t *testing.T) {
	g := newMUDock(t)
	args := map[string]string{"module": "swarma-keyvault", "title": "Review the integrated solution"}
	g.request("$in1", "work.assign", "product", "swarma-platform", args, "Meta assigns: review the integrated solution")
	g.request("$in2", "work.assign", "product", "swarma-platform", args, "Meta assigns: second task")
	for _, id := range []string{"$in1", "$in2"} {
		if out, err := g.handle(id); err != nil || out.State != "succeeded" {
			t.Fatal("in-scope request refused", id, out, err)
		}
	}
	if _, err := g.handle("$in2"); !errors.Is(err, ErrMUNonceHeld) || g.effect.calls != 2 {
		t.Fatal("replay admitted", err, g.effect.calls)
	}
	g.request("$out", "account.manage", "account-scope", "owner:alexis", map[string]string{"account": "@ivan-agent:relux.works"}, "Meta retires an Ivan-side account")
	if _, err := g.handle("$out"); !errors.Is(err, ErrMUScope) || g.effect.calls != 2 {
		t.Fatal("out-of-scope request not refused", err, g.effect.calls)
	}
}

// Claim (docking refusals through the real verifier): a publisher snapshot
// 61 s old refuses (fail closed); a snapshot revoking the grant refuses; an
// event whose delivered text differs from the signed body_sha256 refuses; a
// request for an action the grant does not cover refuses. None executes.
func TestMUDockingRefusals(t *testing.T) {
	args := map[string]string{"module": "swarma-keyvault", "title": "x"}
	g := newMUDock(t)
	g.publish(g.now.Add(-61*time.Second), nil)
	g.request("$stale", "work.assign", "product", "swarma-platform", args, "stale snapshot")
	// VerifyMessage checks the author's Mac attestation against the same
	// publisher snapshot first, so staleness refuses there with its code.
	if _, err := g.handle("$stale"); platformCode(err) != "key_binding_unavailable" {
		t.Error("stale snapshot", err)
	}
	g = newMUDock(t)
	grantID, err := muRecordID(g.grant, "grant/1")
	if err != nil {
		t.Fatal(err)
	}
	g.publish(g.now.Add(-5*time.Second), []mugrant.SnapshotEntry{{Kind: "record", ID: grantID, From: g.now.Add(-time.Minute).Format("2006-01-02T15:04:05Z")}})
	g.request("$rev", "work.assign", "product", "swarma-platform", args, "revoked grant")
	if _, err := g.handle("$rev"); platformCode(err) != "revoked" {
		t.Error("revoked grant", err)
	}
	g = newMUDock(t)
	g.request("$txt", "work.assign", "product", "swarma-platform", args, "signed text")
	e := g.events["$txt"]
	e.Text = []byte("different text")
	g.events["$txt"] = e
	if _, err := g.handle("$txt"); platformCode(err) == "" {
		t.Error("text substitution accepted", err)
	}
	g.request("$act", "work.accept", "product", "swarma-platform", args, "uncovered action")
	if _, err := g.handle("$act"); !errors.Is(err, ErrMUNoGrant) {
		t.Error("uncovered action", err)
	}
	if g.effect.calls != 0 {
		t.Error("refused request executed", g.effect.calls)
	}
}
