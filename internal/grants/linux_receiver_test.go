package grants

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// This fake models only the agreed adapter boundary. It authenticates nothing
// and is never linked into a runtime constructor or an interoperability claim.
type linuxFakeVerifier struct {
	use                    string
	root, grant, publisher string
	revocations            []MURevocation
	refusal                error
	calls                  atomic.Int32
	mutate                 func(*MUDecision, int32)
}

func (v *linuxFakeVerifier) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	d, err := v.VerifyProjected(e, now)
	return LinuxAdmission{Decision: d, Snapshots: []LinuxVerifiedSnapshot{{Signer: v.publisher, IssuedAt: muNow, Entries: append([]MURevocation(nil), v.revocations...)}}}, err
}
func (v *linuxFakeVerifier) VerifyProjected(e MUEnvelopeEvent, now time.Time) (MUDecision, error) {
	n := v.calls.Add(1)
	if v.refusal != nil {
		return MUDecision{}, v.refusal
	}
	b, err := muMessageBody(e.Envelope)
	if err != nil {
		return MUDecision{}, err
	}
	target := b["target"].(map[string]any)
	args := map[string]string{}
	for k, x := range b["arguments"].(map[string]any) {
		args[k] = x.(string)
	}
	exp, _ := time.Parse("2006-01-02T15:04:05Z", b["exp"].(string))
	d := MUDecision{GrantRoot: v.root, GrantID: v.grant, Use: v.use, Author: b["author"].(string), AuthorAttestation: b["author_attestation"].(string),
		Audience: b["aud"].(string), Nonce: b["nonce"].(string), Action: b["action"].(string), TargetKind: target["kind"].(string), TargetID: target["id"].(string),
		Arguments: args, PublisherKey: v.publisher, Revocations: append([]MURevocation(nil), v.revocations...), Expires: exp, RequestHash: sha256.Sum256(e.Envelope)}
	if v.mutate != nil {
		v.mutate(&d, n)
	}
	return d, nil
}

type linuxEffectFunc func(context.Context, MUDecision) ([]byte, error)

func (f linuxEffectFunc) Execute(c context.Context, d MUDecision) ([]byte, error) { return f(c, d) }

type linuxRig struct {
	r     *LinuxReceiver
	v     *linuxFakeVerifier
	calls atomic.Int32
	fail  bool
}

func newLinuxRig(t *testing.T) *linuxRig {
	t.Helper()
	g := &linuxRig{v: &linuxFakeVerifier{use: "until_expiry", root: "p256:synthetic-root", grant: "sha256:synthetic-grant", publisher: "p256:synthetic-publisher"}}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := LinuxReceiverConfig{MUReceiverConfig: MUReceiverConfig{Binding: MUBinding{Audience: muDockAud, GrantRoot: g.v.root}, State: MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("synthetic-epoch"))},
		Signers: map[string]bool{g.v.publisher: true, "ed25519:synthetic-agent-revoker": true}, Owner: "owner:alexis", RoomScope: "swarma-space", Modules: map[string]bool{"swarma-keyvault": true}, RootRevocations: func() ([]MURevocation, error) { return nil, nil }}, PublisherKey: g.v.publisher, AgentRevocationRoot: "ed25519:synthetic-agent-revoker", RoomID: muDockRoom, ReceiverMXID: muDockReceiver, AllowedRooms: map[string]bool{muDockRoom: true}}
	if err := InitializeLinuxReceiverState(c.State, c.Binding, c.RootRevocations); err != nil {
		t.Fatal(err)
	}
	reg := fakeRegistry{keys: map[string]string{}, owners: map[string]string{"@owned:example.invalid": "owner:alexis", "@foreign:example.invalid": "owner:ivan"}}
	f := linuxEffectFunc(func(_ context.Context, _ MUDecision) ([]byte, error) {
		g.calls.Add(1)
		if g.fail {
			return nil, errors.New("synthetic unknown")
		}
		return []byte("synthetic receipt"), nil
	})
	g.r = NewLinuxReceiver(c, g.v, reg, map[string]MUEffect{"work.assign": f, "account.manage": f, "room.membership": f}, func() (time.Time, error) { return muNow, nil })
	return g
}
func (g *linuxRig) event(t *testing.T, id string) MUEnvelopeEvent {
	t.Helper()
	spec, s := linuxTestSpec(t)
	g.r.registry.(fakeRegistry).keys["@synthetic:example.invalid"] = spec.Author
	wire, err := SignLinuxRequest(context.Background(), spec, s)
	if err != nil {
		t.Fatal(err)
	}
	return MUEnvelopeEvent{Sender: "@synthetic:example.invalid", Receiver: muDockReceiver, Room: muDockRoom, EventID: id, Envelope: wire, Text: []byte(spec.Text)}
}
func (g *linuxRig) reopen() {
	g.r = NewLinuxReceiver(g.r.config, g.v, g.r.registry, g.r.effects, g.r.clock)
}
func (g *linuxRig) journal(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.r.config.State.Directory, "mu.journal"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Claim: Reopen preserves nonce and once-grant holds, while fresh until-expiry uses remain independent.
func TestLinuxReceiverDurableUse(t *testing.T) {
	for _, use := range []string{"once", "until_expiry"} {
		t.Run(use, func(t *testing.T) {
			g := newLinuxRig(t)
			g.v.use = use
			e := g.event(t, "$one")
			if out, err := g.r.Handle(context.Background(), e); err != nil || out.State != "succeeded" {
				t.Fatal(out, err)
			}
			g.reopen()
			want := ErrMUNonceHeld
			if use == "once" {
				want = ErrMUUseHeld
			}
			if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, want) {
				t.Fatal("replay", err)
			}
			// A new key and nonce still cannot refill this once allowance.
			e2 := g.event(t, "$two")
			out, err := g.r.Handle(context.Background(), e2)
			if use == "once" {
				if !errors.Is(err, ErrMUUseHeld) {
					t.Fatal(err)
				}
			} else if err != nil || out.State != "succeeded" {
				t.Fatal(out, err)
			}
			wantCalls := int32(1)
			if use == "until_expiry" {
				wantCalls = 2
			}
			if g.calls.Load() != wantCalls {
				t.Fatal(g.calls.Load())
			}
		})
	}
}

// Claim: An unknown effect outcome holds its nonce and is never redispatched after reopen.
func TestLinuxReceiverUnknownNeverReplays(t *testing.T) {
	g := newLinuxRig(t)
	g.fail = true
	e := g.event(t, "$unknown")
	if out, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUUnknown) || out.State != "unknown" {
		t.Fatal(out, err)
	}
	g.fail = false
	g.reopen()
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUNonceHeld) || g.calls.Load() != 1 {
		t.Fatal(err, g.calls.Load())
	}
}

// Inject failures at the intent write and outcome sync. A complete reserve
// survives the first; a complete intent precedes every effect. Reopening a
// possibly successful outcome never executes it again.
// Claim: Failures at reserve, intent and outcome preserve conservative holds and never dispatch before intent.
func TestLinuxReceiverCrashBoundaries(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$crash")
			// Prime snapshot continuity separately so these failures target exactly
			// reservation, intent and outcome, as in the original accounting test.
			g.r.config.Paused[g.v.grant] = true
			if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUPaused) {
				t.Fatal(err)
			}
			g.r.config.Paused[g.v.grant] = false
			g.r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
				s, err := openMUState(ctx, c, b)
				if err != nil {
					return nil, err
				}
				sync := s.sync
				n := 0
				s.sync = func(f *os.File) error {
					n++
					if n == failAt {
						return errors.New("synthetic fsync failure")
					}
					return sync(f)
				}
				return s, nil
			}
			out, err := g.r.Handle(context.Background(), e)
			if failAt == 1 {
				if !errors.Is(err, ErrMUState) || out != nil {
					t.Fatal(out, err)
				}
			} else if !errors.Is(err, ErrMUUnknown) || out.State != "unknown" {
				t.Fatal(out, err)
			}
			before := g.calls.Load()
			if failAt < 3 && before != 0 || failAt == 3 && before != 1 {
				t.Fatal("effect before durable intent", before)
			}
			g.reopen()
			if _, err := g.r.Handle(context.Background(), e); err == nil || g.calls.Load() != before {
				t.Fatal("crash replayed", err, g.calls.Load())
			}
		})
	}
}

// Claim: Concurrent copies of one request dispatch at most once under the MU lock.
func TestLinuxReceiverConcurrentReplay(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$race")
	other := NewLinuxReceiver(g.r.config, g.v, g.r.registry, g.r.effects, g.r.clock)
	results := make(chan error, 2)
	for _, r := range []*LinuxReceiver{g.r, other} {
		go func(r *LinuxReceiver) { _, err := r.Handle(context.Background(), e); results <- err }(r)
	}
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrMUNonceHeld)) || (b == nil && errors.Is(a, ErrMUNonceHeld))) || g.calls.Load() != 1 {
		t.Fatal(a, b, g.calls.Load())
	}
}

// Claim: Projection, clock, verification, local pause and final decision changes refuse before reservation or effect.
func TestLinuxReceiverRechecksAndPolicy(t *testing.T) {
	cases := map[string]struct {
		change func(*linuxRig, *MUEnvelopeEvent)
		want   error
	}{
		"room":                        {func(g *linuxRig, e *MUEnvelopeEvent) { e.Room = "!other:invalid" }, ErrMUProjection},
		"receiver":                    {func(g *linuxRig, e *MUEnvelopeEvent) { e.Receiver = "@other:invalid" }, ErrMUProjection},
		"text-before-broken-envelope": {func(g *linuxRig, e *MUEnvelopeEvent) { e.Envelope = []byte("broken"); e.Text = []byte("a\r") }, ErrLinuxRequestText},
		"paused-grant":                {func(g *linuxRig, e *MUEnvelopeEvent) { g.r.config.Paused[g.v.grant] = true }, ErrMUPaused},
		"paused-module":               {func(g *linuxRig, e *MUEnvelopeEvent) { g.r.config.PausedModules["swarma-keyvault"] = true }, ErrMUPaused},
		"clock-missing": {func(g *linuxRig, e *MUEnvelopeEvent) {
			g.r.clock = func() (time.Time, error) { return time.Time{}, ErrMUState }
		}, ErrMUState},
		"verifier-refusal": {func(g *linuxRig, e *MUEnvelopeEvent) { g.v.refusal = ErrMUAmbiguous }, ErrMUAmbiguous},
		"under-lock-change": {func(g *linuxRig, e *MUEnvelopeEvent) {
			g.v.mutate = func(d *MUDecision, n int32) {
				if n == 2 {
					d.GrantID = "different"
				}
			}
		}, ErrMUState},
		"hash-miswire": {func(g *linuxRig, e *MUEnvelopeEvent) {
			g.v.mutate = func(d *MUDecision, n int32) { d.RequestHash = sha256.Sum256([]byte("other")) }
		}, ErrMUState},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$x")
			c.change(g, &e)
			if out, err := g.r.Handle(context.Background(), e); !errors.Is(err, c.want) || out != nil {
				t.Fatal(out, err, c.want)
			}
			state, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.close()
			if g.calls.Load() != 0 || len(state.reservations) != 0 {
				t.Fatal("refusal wrote reservation or executed")
			}

		})
	}
}

// Claim: Only protected owner accounts and allowed room scopes admit their corresponding actions.
func TestLinuxReceiverOwnerAndRoomScope(t *testing.T) {
	for _, action := range []string{"account.manage", "room.membership"} {
		for _, allowed := range []bool{true, false} {
			g := newLinuxRig(t)
			spec, s := linuxTestSpec(t)
			spec.Action = action
			spec.Target.Kind = "account-scope"
			spec.Target.ID = "owner:alexis"
			spec.Arguments = map[string]string{"account": "@owned:example.invalid"}
			if !allowed {
				spec.Arguments["account"] = "@foreign:example.invalid"
			}
			if action == "room.membership" {
				spec.Target.Kind = "room-scope"
				spec.Target.ID = "swarma-space"
				spec.Arguments["room"] = muDockRoom
			}
			g.r.registry.(fakeRegistry).keys["@synthetic:example.invalid"] = spec.Author
			wire, err := SignLinuxRequest(context.Background(), spec, s)
			if err != nil {
				t.Fatal(err)
			}
			e := MUEnvelopeEvent{Sender: "@synthetic:example.invalid", Receiver: muDockReceiver, Room: muDockRoom, EventID: "$scope", Envelope: wire, Text: []byte(spec.Text)}
			_, err = g.r.Handle(context.Background(), e)
			if allowed && err != nil || !allowed && !errors.Is(err, ErrMUScope) {
				t.Fatal(action, allowed, err)
			}
		}
	}
}

// A new verified snapshot is retained even if local policy refuses execution;
// a restarted receiver refuses a snapshot which subsequently drops its entry.
// Claim: A policy-refused observation remains durable and later omission refuses; complete history permits admission.
func TestLinuxReceiverRevocationUnion(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$rev")
	x := MURevocation{"record", "sha256:unrelated"}
	g.v.revocations = []MURevocation{x}
	g.r.config.Paused[g.v.grant] = true
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUPaused) {
		t.Fatal(err)
	}
	g.r.config.Paused[g.v.grant] = false
	g.v.revocations = nil
	g.reopen()
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURollback) {
		t.Fatal("lost durable union", err)
	}
	g.v.revocations = []MURevocation{x}
	if _, err := g.r.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if g.calls.Load() != 1 {
		t.Fatal(g.calls.Load())
	}
}

// Claim: Grant, publisher, attestation and author revocations prevent effects and remain held.
func TestLinuxReceiverRevocationBlocksAndPersists(t *testing.T) {
	for _, field := range []string{"grant", "publisher", "attestation", "author"} {
		g := newLinuxRig(t)
		e := g.event(t, "$rev")
		b, _ := muMessageBody(e.Envelope)
		rev := MURevocation{"record", g.v.grant}
		switch field {
		case "publisher":
			rev = MURevocation{"key", g.v.publisher}
		case "attestation":
			rev = MURevocation{"record", b["author_attestation"].(string)}
		case "author":
			rev = MURevocation{"key", b["author"].(string)}
		}
		g.v.revocations = []MURevocation{rev}
		if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURevoked) {
			t.Fatal(field, err)
		}
		g.v.revocations = nil
		g.reopen()
		if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
			t.Fatal(field, err)
		}
	}
}

// Claim: An authenticated owner-root hold wins even when old and absent from the publisher snapshot.
func TestLinuxReceiverOldRootRevocationWins(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$root")
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{{"key", g.v.publisher}}, nil }
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURevoked) {
		t.Fatal(err)
	}
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	g.reopen()
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
		t.Fatal(err)
	}
}

// A root revocation must survive even when all platform evidence is currently
// unavailable. Later recovery cannot erase it and re-enable that publisher.
// Claim: Owner-root holds remain durable when the same request fails verification.
func TestLinuxReceiverRootPersistsBeforeVerifierRefusal(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$root-unavailable")
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{{"key", g.v.publisher}}, nil }
	g.v.refusal = ErrMUState
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUState) {
		t.Fatal(err)
	}
	g.v.refusal = nil
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	g.reopen()
	if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMURevoked) || g.calls.Load() != 0 {
		t.Fatal("root forgotten", err)
	}
}

// Claim: Forbidden or oversized text refuses even when its valid signature binds the exact bytes.
func TestLinuxReceiverTextLimitEvenWithValidSignatureAndHash(t *testing.T) {
	g := newLinuxRig(t)
	spec, s := linuxTestSpec(t)
	spec.Text = string(bytes.Repeat([]byte("x"), 4096))
	g.r.registry.(fakeRegistry).keys["@synthetic:example.invalid"] = spec.Author
	wire, err := SignLinuxRequest(context.Background(), spec, s)
	if err != nil {
		t.Fatal(err)
	}
	e := MUEnvelopeEvent{Sender: "@synthetic:example.invalid", Receiver: muDockReceiver, Room: muDockRoom, EventID: "$at-limit", Envelope: wire, Text: []byte(spec.Text)}
	if _, err := g.r.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	for _, text := range [][]byte{bytes.Repeat([]byte("x"), 4097), []byte("a\r")} {
		parsed, err := muParseEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		b := parsed["body"].(map[string]any)
		h := sha256.Sum256(text)
		b["body_sha256"] = hex.EncodeToString(h[:])
		id, _ := record.ContentID("message/1", b)
		pre, _ := record.SigningPreimage("message/1", spec.Author, "author", b)
		parsed["id"] = id
		parsed["signatures"] = []any{map[string]any{"key": spec.Author, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, pre))}}
		e.Envelope, err = record.Canonical(parsed)
		if err != nil {
			t.Fatal(err)
		}
		e.Text = text
		before, calls := g.journal(t), g.v.calls.Load()
		if _, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrLinuxRequestText) {
			t.Fatal("signed refused text admitted", err)
		}
		if g.v.calls.Load() != calls || !bytes.Equal(before, g.journal(t)) || g.calls.Load() != 1 {
			t.Fatal("text refusal reached verifier, journal or effect")
		}
	}
}

// Actual pinned platform crypto on ephemeral Mac keys exercises the Linux
// execution boundary. This is synthetic docking, not published interop.
type linuxMacDockVerifier struct{ p *MUPlatform }

func (v linuxMacDockVerifier) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	d, err := v.p.Verify(MUEvent{SenderMXID: e.Sender, RoomID: e.Room, EventID: e.EventID, Envelope: e.Envelope}, now)
	if err != nil {
		return LinuxAdmission{}, err
	}
	raw, err := v.p.config.Snapshot()
	if err != nil {
		return LinuxAdmission{}, err
	}
	env, err := muParseEnvelope(raw)
	if err != nil {
		return LinuxAdmission{}, err
	}
	b := env["body"].(map[string]any)
	issued, err := time.Parse(time.RFC3339, strOr(b["issued_at"]))
	return LinuxAdmission{Decision: d, Snapshots: []LinuxVerifiedSnapshot{{Signer: d.PublisherKey, IssuedAt: issued, Entries: d.Revocations}}}, err
}

// Claim: Actual pinned platform verification admits valid Mac requests and refuses stale or ambiguous evidence.
func TestLinuxReceiverPinnedPlatformDock(t *testing.T) {
	g := newMUDock(t)
	g.request("$dock", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault", "title": "synthetic"}, "hello")
	g.receiver.config.RootRevocations = func() ([]MURevocation, error) { return nil, nil }
	g.receiver.config.Signers = map[string]bool{g.pub.id: true, "ed25519:synthetic-agent-revoker": true}
	r := NewLinuxReceiver(LinuxReceiverConfig{MUReceiverConfig: g.receiver.config, PublisherKey: g.pub.id, AgentRevocationRoot: "ed25519:synthetic-agent-revoker", RoomID: muDockRoom, ReceiverMXID: muDockReceiver}, linuxMacDockVerifier{g.receiver.verifier.(*MUPlatform)}, g.receiver.registry, g.receiver.effects, func() (time.Time, error) { return g.now, nil })
	e := g.events["$dock"]
	if _, err := r.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	g.publish(g.now.Add(-61*time.Second), nil)
	g.request("$stale", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault", "title": "synthetic"}, "hello")
	if _, err := r.Handle(context.Background(), g.events["$stale"]); platformCode(err) != "key_binding_unavailable" {
		t.Fatal("stale snapshot", err)
	}
	g.publish(g.now.Add(-time.Second), nil)
	g.request("$ambiguous", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault", "title": "synthetic"}, "hello")
	p := g.receiver.verifier.(*MUPlatform)
	p.config.Grants = append(p.config.Grants, p.config.Grants[0])
	if _, err := r.Handle(context.Background(), g.events["$ambiguous"]); !errors.Is(err, ErrMUAmbiguous) {
		t.Fatal(err)
	}
	if g.effect.calls != 1 {
		t.Fatal(g.effect.calls)
	}
}
