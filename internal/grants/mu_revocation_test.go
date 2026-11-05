package grants

import (
	"context"
	"errors"
	"testing"
	"time"
)

func muWithSnapshot(d MUDecision, publisher string, entries ...MURevocation) MUDecision {
	d.PublisherKey, d.Revocations = publisher, entries
	return d
}

// Claim (r5 constraint 2): the receiver's revocation union only grows. After a
// snapshot listing X was accepted, a later snapshot that drops X is refused as
// rollback, also after the journal is reopened by a new receiver; a newer
// snapshot keeping X and adding Y is accepted.
func TestMURevocationMonotonic(t *testing.T) {
	g := newMURig(t)
	x := MURevocation{"record", "sha256:x"}
	y := MURevocation{"key", "p256:y"}
	g.v.decisions["$1"] = muWithSnapshot(muDecision("grant-U", "r1", "until_expiry"), "p256:pub", x)
	if _, err := g.handle("$1"); err != nil {
		t.Fatal("snapshot with X refused", err)
	}
	g.v.decisions["$2"] = muWithSnapshot(muDecision("grant-U", "r2", "until_expiry"), "p256:pub")
	if _, err := g.handle("$2"); !errors.Is(err, ErrMURollback) {
		t.Fatal("snapshot dropping X accepted", err)
	}
	fresh := NewMUReceiver(g.r.config, g.v, g.r.registry, g.r.effects)
	fresh.now = g.r.now
	g.v.decisions["$3"] = muWithSnapshot(muDecision("grant-U", "r3", "until_expiry"), "p256:pub")
	if _, err := fresh.Handle(nil2ctx(), MUEvent{SenderMXID: muMeta, EventID: "$3"}); !errors.Is(err, ErrMURollback) {
		t.Fatal("union lost across reopen", err)
	}
	g.v.decisions["$4"] = muWithSnapshot(muDecision("grant-U", "r4", "until_expiry"), "p256:pub", x, y)
	if _, err := g.handle("$4"); err != nil {
		t.Fatal("newer superset snapshot refused", err)
	}
	if g.effect.calls != 2 {
		t.Fatal("refused requests executed", g.effect.calls)
	}
}

// Claim (r5 constraint 3): a revocation signed by the owner root is honoured
// at once, whatever the publisher snapshot says, for the grant, the author key
// and the author attestation; an unrelated root revocation does not refuse the
// request by itself once the publisher mirrors it.
func TestMURevocationRootWins(t *testing.T) {
	for name, rev := range map[string]MURevocation{
		"grant":       {"record", "grant-U"},
		"author-key":  {"key", "p256:meta"},
		"attestation": {"record", "sha256:att"},
	} {
		g := newMURig(t)
		g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{rev}, nil }
		d := muWithSnapshot(muDecision("grant-U", "w1", "until_expiry"), "p256:pub")
		d.AuthorAttestation = "sha256:att"
		g.v.decisions["$w"] = d
		if _, err := g.handle("$w"); !errors.Is(err, ErrMURevoked) || g.effect.calls != 0 {
			t.Fatal("root revocation not honoured", name, err, g.effect.calls)
		}
	}
	g := newMURig(t)
	other := MURevocation{"record", "sha256:unrelated"}
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{other}, nil }
	g.v.decisions["$ok"] = muWithSnapshot(muDecision("grant-U", "w2", "until_expiry"), "p256:pub", other)
	if _, err := g.handle("$ok"); err != nil {
		t.Fatal("unrelated mirrored root revocation refused the request", err)
	}
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return nil, errors.New("root source unavailable") }
	g.v.decisions["$down"] = muWithSnapshot(muDecision("grant-U", "w3", "until_expiry"), "p256:pub", other)
	if _, err := g.handle("$down"); !errors.Is(err, ErrMUState) {
		t.Fatal("unavailable root revocations did not fail closed", err)
	}
}

// Claim (r5 constraint 5): once the owner root revokes the publisher key, its
// snapshots are refused (fail closed), beside the same request before that.
func TestMURevocationPublisherRevoked(t *testing.T) {
	g := newMURig(t)
	g.v.decisions["$a"] = muWithSnapshot(muDecision("grant-U", "p1", "until_expiry"), "p256:pub")
	if _, err := g.handle("$a"); err != nil {
		t.Fatal("valid neighbour refused", err)
	}
	pub := MURevocation{"key", "p256:pub"}
	g.r.config.RootRevocations = func() ([]MURevocation, error) { return []MURevocation{pub}, nil }
	g.v.decisions["$b"] = muWithSnapshot(muDecision("grant-U", "p2", "until_expiry"), "p256:pub", pub)
	if _, err := g.handle("$b"); !errors.Is(err, ErrMURevoked) || g.effect.calls != 1 {
		t.Fatal("revoked publisher accepted", err, g.effect.calls)
	}
}

func nil2ctx() context.Context { return context.Background() }

// Claim (contract §2.4, high-water): the newest accepted snapshot issued_at
// per signer is durable. An older snapshot refuses as rollback in the same
// receiver and in a receiver reopened on the same journal; an equal issued_at
// is admitted, and so is a newer one.
func TestMURevocationHighWater(t *testing.T) {
	g := newMURig(t)
	at := time.Date(2026, 11, 5, 18, 0, 0, 0, time.UTC)
	mark := func(d MUDecision, t time.Time) MUDecision {
		d.SnapshotMarks = map[string]time.Time{"p256:pub": t}
		return d
	}
	g.v.decisions["$1"] = mark(muWithSnapshot(muDecision("grant-U", "h1", "until_expiry"), "p256:pub"), at)
	if _, err := g.handle("$1"); err != nil {
		t.Fatal("first snapshot refused", err)
	}
	g.v.decisions["$2"] = mark(muWithSnapshot(muDecision("grant-U", "h2", "until_expiry"), "p256:pub"), at)
	if _, err := g.handle("$2"); err != nil {
		t.Fatal("equal issued_at refused", err)
	}
	g.v.decisions["$3"] = mark(muWithSnapshot(muDecision("grant-U", "h3", "until_expiry"), "p256:pub"), at.Add(-time.Second))
	if _, err := g.handle("$3"); !errors.Is(err, ErrMURollback) {
		t.Fatal("older snapshot accepted", err)
	}
	fresh := NewMUReceiver(g.r.config, g.v, g.r.registry, g.r.effects)
	fresh.now = g.r.now
	g.v.decisions["$4"] = mark(muWithSnapshot(muDecision("grant-U", "h4", "until_expiry"), "p256:pub"), at.Add(-time.Second))
	if _, err := fresh.Handle(nil2ctx(), MUEvent{SenderMXID: muMeta, EventID: "$4"}); !errors.Is(err, ErrMURollback) {
		t.Fatal("high-water lost across reopen", err)
	}
	g.v.decisions["$5"] = mark(muWithSnapshot(muDecision("grant-U", "h5", "until_expiry"), "p256:pub"), at.Add(time.Second))
	if _, err := fresh.Handle(nil2ctx(), MUEvent{SenderMXID: muMeta, EventID: "$5"}); err != nil {
		t.Fatal("newer snapshot refused", err)
	}
	if g.effect.calls != 3 {
		t.Fatal("effects", g.effect.calls)
	}
}
