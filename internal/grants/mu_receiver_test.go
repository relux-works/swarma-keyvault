package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeVNextVerifier stands in for the platform verifier v-next (vocabulary
// v2, caveats/v2, Mac P-256 authors). It NEVER qualifies anything: it returns
// the decision configured per event id, or the configured refusal.
type fakeVNextVerifier struct {
	decisions map[string]MUDecision
	refusals  map[string]error
}

func (f *fakeVNextVerifier) Verify(ev MUEvent, now time.Time) (MUDecision, error) {
	if err := f.refusals[ev.EventID]; err != nil {
		return MUDecision{}, err
	}
	d, ok := f.decisions[ev.EventID]
	if !ok {
		return MUDecision{}, ErrA2ANoGrant
	}
	return d, nil
}

type fakeRegistry struct{ keys, owners map[string]string }

func (r fakeRegistry) AttestedKey(m string) (string, bool) { k, ok := r.keys[m]; return k, ok }
func (r fakeRegistry) OwnerOf(a string) (string, bool)     { o, ok := r.owners[a]; return o, ok }

type countingEffect struct {
	calls int
	fail  bool
}

func (e *countingEffect) Execute(ctx context.Context, d MUDecision) ([]byte, error) {
	e.calls++
	if e.fail {
		return nil, errors.New("effect failed")
	}
	return []byte("created " + d.Arguments["title"]), nil
}

const muSender = "@fixture-principal-7:example.invalid"

var muNow = time.Date(2026, 11, 5, 15, 0, 0, 0, time.UTC)

func muDecision(id, nonce, use string) MUDecision {
	return MUDecision{GrantRoot: "p256:root", GrantID: id, Use: use, Author: "p256:sender", Audience: "swarma-keyvault-receiver", Nonce: nonce,
		Action: "work.assign", TargetKind: "product", TargetID: "swarma-platform", Arguments: map[string]string{"module": "swarma-keyvault", "title": "t-" + nonce},
		Expires: muNow.Add(24 * time.Hour), RequestHash: sha256.Sum256([]byte(id + nonce))}
}

type muRig struct {
	r      *MUReceiver
	v      *fakeVNextVerifier
	effect *countingEffect
	state  MUStateConfig
}

func newMURig(t *testing.T) *muRig {
	t.Helper()
	c, b := muFixture(t)
	v := &fakeVNextVerifier{decisions: map[string]MUDecision{}, refusals: map[string]error{}}
	reg := fakeRegistry{keys: map[string]string{muSender: "p256:sender"}, owners: map[string]string{"@fixture-principal-4:example.invalid": "owner:fixture-primary", "@fixture-principal-5:example.invalid": "owner:fixture-3"}}
	e := &countingEffect{}
	r := NewMUReceiver(MUReceiverConfig{Binding: b, State: c, Owner: "owner:fixture-primary", RoomScope: "swarma-space", Modules: map[string]bool{"swarma-keyvault": true}, Paused: map[string]bool{}},
		v, reg, map[string]MUEffect{"work.assign": e, "account.manage": e, "room.membership": e})
	r.now = func() time.Time { return muNow }
	return &muRig{r: r, v: v, effect: e, state: c}
}

func (g *muRig) journal(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.state.Directory, "mu.journal"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (g *muRig) handle(id string) (*MUOutcome, error) {
	return g.r.Handle(context.Background(), MUEvent{SenderMXID: muSender, RoomID: "!fixture-principal-3:example.invalid", EventID: id, Envelope: []byte("env-" + id)})
}

// Claim: an until_expiry grant admits two in-scope requests with distinct
// nonces (one effect each) and refuses a replay of the second nonce without a
// new effect; a once grant refuses its second use with a fresh nonce. This is
// the sitting sequence of contract r3 section 10 against a fake verifier.
func TestMUReceiverMultiUseSequence(t *testing.T) {
	g := newMURig(t)
	g.v.decisions["$e1"] = muDecision("grant-U", "n1", "until_expiry")
	g.v.decisions["$e2"] = muDecision("grant-U", "n2", "until_expiry")
	g.v.decisions["$e3"] = muDecision("grant-U", "n2", "until_expiry")
	for _, id := range []string{"$e1", "$e2"} {
		if out, err := g.handle(id); err != nil || out.State != "succeeded" {
			t.Fatal("in-scope request refused", id, out, err)
		}
	}
	if _, err := g.handle("$e3"); !errors.Is(err, ErrMUNonceHeld) || g.effect.calls != 2 {
		t.Fatal("replay admitted or re-executed", err, g.effect.calls)
	}
	g.v.decisions["$o1"] = muDecision("grant-O", "o1", "once")
	g.v.decisions["$o2"] = muDecision("grant-O", "o2", "once")
	if _, err := g.handle("$o1"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.handle("$o2"); !errors.Is(err, ErrMUUseHeld) || g.effect.calls != 3 {
		t.Fatal("once grant used twice", err, g.effect.calls)
	}
}

// Claim: every pre-reservation refusal leaves the journal byte-identical and
// performs no effect, and each refuses with its own error.
func TestMUReceiverRefusalsBeforeReservation(t *testing.T) {
	cases := map[string]struct {
		setup func(*muRig)
		event MUEvent
		want  error
	}{
		"sender-not-attested": {nil, MUEvent{SenderMXID: "@fixture-principal-10:example.invalid", EventID: "$x"}, ErrMUSender},
		"author-not-attested-key": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Author = "p256:copied"
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUSender},
		"verifier-refusal": {func(g *muRig) { g.v.refusals["$x"] = errSignatureInvalid }, MUEvent{SenderMXID: muSender, EventID: "$x"}, errSignatureInvalid},
		"expired": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Expires = muNow
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUState},
		"wrong-audience": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Audience = "other-receiver"
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUAudience},
		"paused": {func(g *muRig) {
			g.v.decisions["$x"] = muDecision("grant-U", "n1", "until_expiry")
			g.r.config.Paused["grant-U"] = true
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUPaused},
		"grant-widening": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Action = "grant.issue"
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUWidening},
		"unknown-module": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Arguments["module"] = "unknown-module"
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUScope},
		"ivan-side-account": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Action, d.TargetKind, d.TargetID = "account.manage", "account-scope", "owner:fixture-primary"
			d.Arguments = map[string]string{"account": "@fixture-principal-5:example.invalid"}
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUScope},
		"room-invitee-not-owner": {func(g *muRig) {
			d := muDecision("grant-U", "n1", "until_expiry")
			d.Action, d.TargetKind, d.TargetID = "room.membership", "room-scope", "swarma-space"
			d.Arguments = map[string]string{"room": "!fixture-principal-2:example.invalid", "account": "@fixture-principal-5:example.invalid"}
			g.v.decisions["$x"] = d
		}, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUScope},
		"unknown-policy": {func(g *muRig) { g.v.decisions["$x"] = muDecision("grant-U", "n1", "unlimited") }, MUEvent{SenderMXID: muSender, EventID: "$x"}, ErrMUState},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g := newMURig(t)
			if c.setup != nil {
				c.setup(g)
			}
			before := g.journal(t)
			if out, err := g.r.Handle(context.Background(), c.event); !errors.Is(err, c.want) || out != nil {
				t.Fatal("wrong refusal", out, err, "wanted", c.want)
			}
			if g.effect.calls != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatal("refusal executed or wrote state", g.effect.calls)
			}
		})
	}
}

// Claim: in-scope account and room actions for an owner:alexis account pass the
// executor checks (positive neighbours of the scope refusals).
func TestMUReceiverOwnerScopeAdmits(t *testing.T) {
	g := newMURig(t)
	acc := muDecision("grant-U", "a1", "until_expiry")
	acc.Action, acc.TargetKind, acc.TargetID = "account.manage", "account-scope", "owner:fixture-primary"
	acc.Arguments = map[string]string{"account": "@fixture-principal-4:example.invalid"}
	room := muDecision("grant-U", "a2", "until_expiry")
	room.Action, room.TargetKind, room.TargetID = "room.membership", "room-scope", "swarma-space"
	room.Arguments = map[string]string{"room": "!fixture-principal-2:example.invalid", "account": "@fixture-principal-4:example.invalid"}
	g.v.decisions["$acc"], g.v.decisions["$room"] = acc, room
	for _, id := range []string{"$acc", "$room"} {
		if _, err := g.handle(id); err != nil {
			t.Fatal("in-scope owner action refused", id, err)
		}
	}
}

// Claim: an effect failure after the intent is UNKNOWN; the use stays held, a
// retry is refused and the effect is never run a second time.
func TestMUReceiverUnknownHolds(t *testing.T) {
	g := newMURig(t)
	g.effect.fail = true
	g.v.decisions["$u"] = muDecision("grant-U", "u1", "until_expiry")
	if out, err := g.handle("$u"); !errors.Is(err, ErrMUUnknown) || out == nil || out.State != "unknown" {
		t.Fatal("failed effect not unknown", out, err)
	}
	g.effect.fail = false
	if _, err := g.handle("$u"); !errors.Is(err, ErrMUNonceHeld) || g.effect.calls != 1 {
		t.Fatal("unknown released or retried", err, g.effect.calls)
	}
}
