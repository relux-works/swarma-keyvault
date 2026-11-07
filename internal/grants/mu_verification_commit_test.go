package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func linuxCommitTestCandidate(t *testing.T, d *linuxVerifierDock) (*linuxProviderView, LinuxAdmission, muVerificationCommit, MUUse) {
	t.Helper()
	v := linuxProviderTestView(t, d)
	// Exercise the actual pinned verifier plans independently of the elapsed
	// budget test. Race instrumentation can exceed 100 ms; it grants no effect.
	p, err := NewLinuxVerifier(v.input.Config, v, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.VerifyAdmission(v.input.Event, d.now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.commitCandidate(a)
	if err != nil {
		t.Fatal(err)
	}
	x := a.Decision
	u := MUUse{Once: x.Use == "once", GrantRoot: x.GrantRoot, GrantID: x.GrantID, Action: x.Action, TargetKind: x.TargetKind, TargetID: x.TargetID, Requester: x.Author, Nonce: x.Nonce, Audience: x.Audience, RequestHash: x.RequestHash}
	return v, a, c, u
}

func TestMUVerificationCommitAtomicOriginalsAndUnknown(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	linuxContractScope(d, "once")
	_, a, c, u := linuxCommitTestCandidate(t, d)
	if len(a.plan.message.IDs) != 1 || len(a.plan.grant.IDs) != 1 || len(a.plan.originals) != 2 {
		t.Fatal("platform plans lost")
	}
	s := muOpen(t, g.config.State, g.config.Binding)
	seq, err := s.reserveVerified(u, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.nonces) != 1 || len(s.allowances) != 1 || len(s.verificationIDs) != 2 || !s.verificationWatermark.Equal(c.watermark) {
		t.Fatal("incomplete atomic reservation")
	}
	for id, wire := range a.plan.originals {
		if !bytes.Equal(s.verificationIDs[id], wire) {
			t.Fatal("original bytes changed")
		}
	}
	if err := s.markIntent(seq); err != nil {
		t.Fatal(err)
	}
	// Deliberately lose the reply: no outcome is recorded. Reopen must retain
	// the reservation, watermark, exact ID bytes and unknown dispatch intent.
	s.close()
	s = muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	if r := s.reservations[seq]; r == nil || !r.intent || r.complete {
		t.Fatal("unknown outcome lost")
	}
	if !s.verificationWatermark.Equal(c.watermark) || len(s.verificationIDs) != 2 {
		t.Fatal("history lost on reopen")
	}
	u.Nonce = "fresh-does-not-refill"
	if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUUseHeld) {
		t.Fatal("unknown once use refunded", err)
	}
	if !bytes.Equal(s.verificationIDs[a.plan.message.IDs[0]], d.event.Envelope) {
		t.Fatal("exact request bytes changed")
	}
	if _, err := s.reserve(u); !errors.Is(err, ErrMUState) {
		t.Fatal("legacy reservation downgraded plan-aware epoch", err)
	}
}

func TestMUVerificationCommitCurrentRevocationAndLegacyReceiver(t *testing.T) {
	for _, mode := range []string{"revocation", "legacy-receiver"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			linuxContractScope(d, "until_expiry")
			_, _, c, u := linuxCommitTestCandidate(t, d)
			s := muOpen(t, g.config.State, g.config.Binding)
			if mode == "revocation" {
				if err := s.absorbSigned(MUOwnerRootSigner, []MURevocation{{Kind: "key", ID: d.agentID}}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMURevoked) {
					t.Fatal("known revocation committed use", err)
				}
				if len(s.reservations) != 0 || len(s.verificationIDs) != 0 {
					t.Fatal("revoked admission consumed state")
				}
				s.close()
				s = muOpen(t, g.config.State, g.config.Binding)
				defer s.close()
				if !s.revoked[MURevocation{Kind: "key", ID: d.agentID}] {
					t.Fatal("rollback erased revocation union")
				}
				return
			}
			if _, err := s.reserveVerified(u, c); err != nil {
				t.Fatal(err)
			}
			s.close()
			d.fake.state.IDJournal = c.ids
			body, err := muMessageBody(d.event.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte("another-nonce-16"))
			d.event.Envelope = linuxVerifierSign(t, d.agentID, d.agent, body)
			if err := g.handle(); !errors.Is(err, ErrMUState) || g.calls != 0 {
				t.Fatal("legacy receiver bypassed atomic plan", err, g.calls)
			}
		})
	}
}

func TestMUVerificationCommitConcurrentOnce(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	linuxContractScope(d, "once")
	_, _, first, u1 := linuxCommitTestCandidate(t, d)
	body, err := muMessageBody(d.event.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte("another-nonce-16"))
	d.event.Envelope = linuxVerifierSign(t, d.agentID, d.agent, body)
	_, _, second, u2 := linuxCommitTestCandidate(t, d)
	// Each complete history must retain either competing request if it was
	// already committed. This avoids mistaking a rollback refusal for once.
	for id, wire := range first.ids {
		second.ids[id] = bytes.Clone(wire)
	}
	for id, wire := range second.ids {
		first.ids[id] = bytes.Clone(wire)
	}
	type attempt struct {
		u MUUse
		c muVerificationCommit
	}
	done := make(chan error, 2)
	var effects atomic.Int32
	for _, item := range []attempt{{u1, first}, {u2, second}} {
		go func(x attempt) {
			s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
			if err != nil {
				done <- err
				return
			}
			defer s.close()
			seq, err := s.reserveVerified(x.u, x.c)
			if err == nil {
				err = s.markIntent(seq)
			}
			if err == nil {
				effects.Add(1)
				err = s.recordOutcome(seq, []byte("synthetic atomic effect receipt"))
			}
			done <- err
		}(item)
	}
	a, b := <-done, <-done
	if !((a == nil && errors.Is(b, ErrMUUseHeld)) || (b == nil && errors.Is(a, ErrMUUseHeld))) || effects.Load() != 1 {
		t.Fatal("atomic once race", a, b, effects.Load())
	}
}

func TestMUVerificationCommitRollbackRefusalPairs(t *testing.T) {
	for _, mode := range []string{"time", "watermark", "dropped-history", "changed-original", "incomplete", "nil-history", "wrong-request", "wrong-grant", "frame-cap"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			linuxContractScope(d, "until_expiry")
			_, _, c, u := linuxCommitTestCandidate(t, d)
			s := muOpen(t, g.config.State, g.config.Binding)
			if _, err := s.reserveVerified(u, c); err != nil {
				t.Fatal("paired valid commit", err)
			}
			s.close()
			s = muOpen(t, g.config.State, g.config.Binding)
			defer s.close()
			originalNow, originalMark := s.verificationNow, s.verificationWatermark
			original := map[string][]byte{}
			for id, wire := range s.verificationIDs {
				original[id] = bytes.Clone(wire)
			}
			// Use a genuinely signed fresh request and a complete baseline so
			// every negative below changes only its named failing premise.
			d.fake.state.IDJournal = original
			body, err := muMessageBody(d.event.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			body["nonce"] = base64.RawURLEncoding.EncodeToString([]byte("another-nonce-16"))
			d.event.Envelope = linuxVerifierSign(t, d.agentID, d.agent, body)
			_, _, c, u = linuxCommitTestCandidate(t, d)
			switch mode {
			case "time":
				c.now = c.now.Add(-time.Second)
			case "watermark":
				c.watermark = c.watermark.Add(-time.Second)
			case "dropped-history":
				for id := range original {
					delete(c.ids, id)
					break
				}
			case "changed-original":
				for id := range original {
					wire := c.ids[id]
					wire[0] ^= 1
					break
				}
			case "incomplete":
				c.complete = false
			case "nil-history":
				c.ids = nil
			case "wrong-request":
				u.RequestHash = sha256.Sum256([]byte("unverified"))
			case "wrong-grant":
				u.GrantID = "sha256:" + fmt.Sprintf("%064x", 123)
			case "frame-cap":
				for i := 0; i < 5; i++ {
					h := sha256.Sum256([]byte(fmt.Sprint(i)))
					c.ids["sha256:"+hex.EncodeToString(h[:])] = make([]byte, 65536)
				}
			}
			if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUState) {
				t.Fatal("unsafe commit admitted", err)
			}
			if len(s.reservations) != 1 || len(s.nonces) != 1 || !s.verificationNow.Equal(originalNow) || !s.verificationWatermark.Equal(originalMark) || len(s.verificationIDs) != len(original) {
				t.Fatal("refusal changed committed state")
			}
			for id, wire := range original {
				if !bytes.Equal(s.verificationIDs[id], wire) {
					t.Fatal("rollback erased exact history")
				}
			}
		})
	}
}

func TestMUVerificationCommitLateSyncRetainsHold(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	linuxContractScope(d, "once")
	_, _, c, u := linuxCommitTestCandidate(t, d)
	s := muOpen(t, g.config.State, g.config.Binding)
	s.sync = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		// Finite in-process synchronous storage premise, no timeout worker and
		// no continued operation after return. Exercise the actual 100 ms cap.
		c.clock.(*linuxTestClock).advance(linuxProviderFinalLimit)
		return nil
	}
	if _, err := s.reserveVerifiedUntil(u, c, c.clock.now().Add(linuxProviderFinalLimit)); !errors.Is(err, ErrMUState) {
		t.Fatal("late sync admitted effect", err)
	}
	if len(s.allowances) != 1 || len(s.verificationIDs) != 2 || len(s.reservations) != 1 {
		t.Fatal("late committed state refunded")
	}
	s.close()
	s = muOpen(t, g.config.State, g.config.Binding)
	defer s.close()
	if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUUseHeld) {
		t.Fatal("late reservation refilled", err)
	}
}

func TestMUVerificationCommitStorageUnknownAndPartialWrite(t *testing.T) {
	for _, mode := range []string{"sync-unknown", "partial-write"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			linuxContractScope(d, "once")
			_, _, c, u := linuxCommitTestCandidate(t, d)
			s := muOpen(t, g.config.State, g.config.Binding)
			if mode == "sync-unknown" {
				s.sync = func(f *os.File) error {
					if err := f.Sync(); err != nil {
						return err
					}
					return errors.New("lost sync acknowledgement")
				}
			} else {
				s.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
			}
			if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUState) || !s.failed {
				t.Fatal("uncertain commit accepted", err)
			}
			if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUState) {
				t.Fatal("poisoned handle reused", err)
			}
			s.close()
			s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
			if mode == "partial-write" {
				if !errors.Is(err, ErrMUState) {
					if s != nil {
						s.close()
					}
					t.Fatal("partial frame adopted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if len(s.verificationIDs) != 2 || !s.verificationWatermark.Equal(c.watermark) || len(s.allowances) != 1 {
				t.Fatal("uncertain committed bytes not reconciled")
			}
			if _, err := s.reserveVerified(u, c); !errors.Is(err, ErrMUUseHeld) {
				t.Fatal("unknown reservation refunded", err)
			}
		})
	}
}
