package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
)

func linuxProviderTestInput(d *linuxVerifierDock) linuxProviderInput {
	s := d.fake.state
	s.Assurance = verifier.Evidence{}
	return linuxProviderInput{ObservedAt: time.Now(), Config: d.config, Event: d.event, State: s,
		Attestations: d.fake.attestations, Agents: map[string]LinuxRegistryAgent{d.agentID: d.fake.agent}, Snapshots: d.fake.snapshots,
		Assurance: map[string]any{"level": "A1", "presence": false}}
}

func linuxProviderTestView(t *testing.T, d *linuxVerifierDock) *linuxProviderView {
	t.Helper()
	v, err := newLinuxProviderView(linuxProviderTestInput(d))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLinuxProviderViewRealAdvisoryAndReceiverFence(t *testing.T) {
	g := newLinuxCombinedRig(t)
	d := g.dock
	linuxContractScope(d, "once")
	v := linuxProviderTestView(t, d)
	a, err := v.advisory()
	if err != nil || a.Decision.RequestHash != sha256.Sum256(d.event.Envelope) || len(a.Snapshots) != 2 {
		t.Fatal("real verifier valid control", err)
	}
	r := NewLinuxReceiver(g.config, v, fakeRegistry{keys: map[string]string{d.event.Sender: d.agentID}},
		map[string]MUEffect{"work.assign": g.effect}, func() (time.Time, error) { return d.now, nil })
	if _, err = r.Handle(context.Background(), d.event); !errors.Is(err, ErrMUState) || g.calls != 0 {
		t.Fatal("unfinished provider admitted effect", err, g.calls)
	}
	linuxContractNoUse(t, g)
	s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if len(s.highWater) != 2 {
		t.Fatal("refusal dropped verified snapshot observations")
	}
	if len(v.privateDiagnostic()) > linuxProviderDiagnosticLimit || strings.Contains(v.privateDiagnostic(), d.agentID) {
		t.Fatal("private diagnostics exposed evidence")
	}
}

func TestLinuxProviderViewDetachedConcurrentInputUpdates(t *testing.T) {
	d := newLinuxVerifierDock(t)
	linuxContractScope(d, "once")
	in := linuxProviderTestInput(d)
	v, err := newLinuxProviderView(in)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(d.event.Envelope)
	p, err := NewLinuxVerifier(v.input.Config, v, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 20; n++ {
			in.Event.Envelope[0] ^= 1
			in.Config.Publisher[0] ^= 1
			in.Config.Grants[0][0] ^= 1
			in.Attestations[d.attID][0] ^= 1
			s := in.Snapshots[d.pub.id]
			s.Wire[0] ^= 1
			in.Snapshots[d.pub.id] = s
			a := in.Agents[d.agentID]
			a.Active = false
			in.Agents[d.agentID] = a
			in.State.IDJournal["concurrent-update"] = []byte("never in staged history")
			in.Config.LinuxAgents[d.fake.agent.MXID] = MULinuxAgent{}
			in.Assurance["level"] = "A3"
		}
	}()
	for n := 0; n < 20; n++ {
		// Check detached-copy races with the real verifier directly. The
		// advisory path's separate 100 ms refusal is tested without race
		// instrumentation, which can exceed that fixed budget on this host.
		a, err := p.VerifyAdmission(v.input.Event, v.input.State.Now)
		if err != nil || a.Decision.RequestHash != sha256.Sum256(original) {
			t.Errorf("detached view raced input update: %v", err)
			break
		}
	}
	wg.Wait()
	// An immutable historical view is still only advisory. It cannot claim
	// that its old generation/revocation state excludes authoritative updates.
	if _, err := v.VerifyAdmission(v.input.Event, v.input.State.Now); err == nil {
		t.Fatal("stale immutable view became final authority", err)
	}
}

func TestLinuxProviderViewDetachedResultsAndExactRequest(t *testing.T) {
	d := newLinuxVerifierDock(t)
	linuxContractScope(d, "once")
	in := linuxProviderTestInput(d)
	in.State.IDJournal["retained"] = []byte("original bytes")
	v, err := newLinuxProviderView(in)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(d.event.Envelope)
	s, err := v.VerificationState(hash)
	if err != nil {
		t.Fatal(err)
	}
	s.IDJournal["retained"][0] ^= 1
	delete(s.IDJournal, "retained")
	again, err := v.VerificationState(hash)
	if err != nil || string(again.IDJournal["retained"]) != "original bytes" {
		t.Fatal("journal alias", err)
	}
	b, _ := v.Attestation(d.attID)
	b[0] ^= 1
	b2, _ := v.Attestation(d.attID)
	if bytes.Equal(b, b2) {
		t.Fatal("attestation alias")
	}
	snap, _ := v.Snapshot(d.pub.id)
	snap.Wire[0] ^= 1
	snap2, _ := v.Snapshot(d.pub.id)
	if bytes.Equal(snap.Wire, snap2.Wire) {
		t.Fatal("snapshot alias")
	}
	for _, h := range [][32]byte{{}, sha256.Sum256([]byte("different request"))} {
		if _, err := v.VerificationState(h); !errors.Is(err, ErrMUState) {
			t.Fatal("unbound state", err)
		}
	}
	e := linuxCloneEvent(d.event)
	e.EventID = "$different"
	if _, err := v.VerifyAdmission(e, d.now); !errors.Is(err, ErrMUState) {
		t.Fatal("different delivery", err)
	}
}

func TestLinuxProviderViewRefusalPairs(t *testing.T) {
	for _, mode := range []string{"generation", "revocation", "time", "history", "A2-required", "A3-asserted", "missing-attestation", "altered-attestation", "authority-expired"} {
		t.Run(mode, func(t *testing.T) {
			d := newLinuxVerifierDock(t)
			linuxContractScope(d, "once")
			if _, err := linuxProviderTestView(t, d).advisory(); err != nil {
				t.Fatal("paired valid control", err)
			}
			in := linuxProviderTestInput(d)
			switch mode {
			case "generation":
				a := in.Agents[d.agentID]
				a.Generation = "new-generation"
				in.Agents[d.agentID] = a
			case "revocation":
				d.snapshot(d.pub.id, d.now, []any{map[string]any{"kind": "key", "id": d.agentID, "from": d.now.Add(-time.Second).Format(time.RFC3339)}})
			case "time":
				in.State.Trusted = false
			case "history":
				in.State.IDJournal = nil
			case "A2-required":
				d.grantBody["min_assurance"] = map[string]any{"level": "A2", "presence": false}
				in.Config.Grants = [][]byte{d.signRoot(d.grantBody)}
			case "A3-asserted":
				in.Assurance["level"] = "A3"
			case "missing-attestation":
				delete(in.Attestations, d.attID)
			case "altered-attestation":
				in.Attestations[d.attID][len(in.Attestations[d.attID])-2] ^= 1
			case "authority-expired":
				in.State.AuthorityUntil = in.State.Now
			}
			v, err := newLinuxProviderView(in)
			if err == nil {
				_, err = v.advisory()
			}
			if err == nil {
				t.Fatal("forbidden view accepted")
			}
			if mode == "A2-required" && linuxVerifierCode(err) != "grant_assurance_insufficient" {
				t.Fatal("A2 refusal changed", err)
			}
		})
	}
}

func TestLinuxProviderViewBoundsAndOriginalExpiry(t *testing.T) {
	d := newLinuxVerifierDock(t)
	linuxContractScope(d, "once")
	for _, mode := range []string{"records-at", "records-over", "bindings-at", "bindings-over", "bytes-over", "evidence-over", "nil-history", "opaque-assurance"} {
		t.Run(mode, func(t *testing.T) {
			in := linuxProviderTestInput(d)
			in.State.IDJournal = map[string][]byte{}
			want := mode == "records-at" || mode == "bindings-at"
			switch mode {
			case "records-at", "records-over":
				// The base has eight records including the Linux identity pin.
				for i := 0; i < 120; i++ {
					in.State.IDJournal[fmt.Sprint(i)] = []byte{1}
				}
				if mode == "records-over" {
					in.State.IDJournal["extra"] = []byte{1}
				}
			case "bindings-at", "bindings-over":
				for i := 0; i < 4096; i++ {
					in.State.IDJournal[fmt.Sprint(i)] = nil
				}
				if mode == "bindings-over" {
					in.State.IDJournal["extra"] = nil
				}
			case "bytes-over":
				in.State.IDJournal[strings.Repeat("x", 1<<20)] = nil
			case "evidence-over":
				in.Attestations = map[string][]byte{"oversize": make([]byte, 8193)}
			case "nil-history":
				in.State.IDJournal = nil
			case "opaque-assurance":
				in.State.Assurance = linuxVerifierAssurance(t, "A1")
			}
			if linuxProviderInputFits(in) != want {
				t.Fatal("capacity boundary", mode)
			}
		})
	}
	in := linuxProviderTestInput(d)
	in.State.AuthorityUntil = d.now.Add(time.Second)
	start := time.Now()
	v, err := newLinuxProviderView(in)
	if err != nil {
		t.Fatal(err)
	}
	if v.deadline.After(start.Add(time.Second)) {
		t.Fatal("original authority expiry extended")
	}
	again, err := newLinuxProviderView(in)
	if err != nil || !again.deadline.Equal(v.deadline) {
		t.Fatal("restaging extended original expiry", err)
	}
	old := in
	old.ObservedAt = time.Now().Add(-linuxProviderStageLimit)
	if _, err := newLinuxProviderView(old); !errors.Is(err, ErrMUState) {
		t.Fatal("staging deadline refreshed", err)
	}
	future := in
	future.ObservedAt = time.Now().Add(time.Hour)
	if _, err := newLinuxProviderView(future); !errors.Is(err, ErrMUState) {
		t.Fatal("future local observation", err)
	}
	wallOnly := in
	wallOnly.ObservedAt = wallOnly.ObservedAt.Round(0)
	if _, err := newLinuxProviderView(wallOnly); !errors.Is(err, ErrMUState) {
		t.Fatal("wall-only observation could extend expiry on clock rollback", err)
	}
	v.deadline = time.Now().Add(-time.Nanosecond)
	if _, err := v.advisory(); linuxVerifierCode(err) != "time_unavailable" {
		t.Fatal("expired local fence", err)
	}
	if _, err := v.VerificationState(sha256.Sum256(d.event.Envelope)); !errors.Is(err, ErrMUState) {
		t.Fatal("expired state disclosed", err)
	}
}
