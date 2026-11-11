package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// These are offline, in-process provider premises with ephemeral test records.
// They are not native provider, protected-custody or live admission evidence.
func linuxApplicationTestBindings(d *linuxVerifierDock) LinuxApplicationBindings {
	return LinuxApplicationBindings{
		Attestation: d.fake.Attestation, CurrentAgent: d.fake.CurrentAgent,
		Snapshot: d.fake.Snapshot, VerificationState: d.fake.VerificationState,
	}
}

func linuxApplicationTestSource(t *testing.T, b LinuxApplicationBindings) *LinuxApplicationSource {
	t.Helper()
	s, err := NewLinuxApplicationSource(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Claim: each missing protected binding fails closed; zero/nil receivers cannot
// turn missing deployment values into usable evidence.
func TestLinuxApplicationSourceMissingBindings(t *testing.T) {
	d := newLinuxVerifierDock(t)
	for _, field := range []string{"attestation", "current", "snapshot", "state"} {
		t.Run(field, func(t *testing.T) {
			b := linuxApplicationTestBindings(d)
			switch field {
			case "attestation":
				b.Attestation = nil
			case "current":
				b.CurrentAgent = nil
			case "snapshot":
				b.Snapshot = nil
			case "state":
				b.VerificationState = nil
			}
			if s, err := NewLinuxApplicationSource(b); s != nil || !errors.Is(err, ErrMUState) {
				t.Fatal("missing binding accepted", err)
			}
		})
	}
	for _, s := range []*LinuxApplicationSource{nil, {}} {
		if b, err := s.Attestation(d.attID); b != nil || err == nil {
			t.Fatal("missing attestation accepted")
		}
		if a, err := s.CurrentAgent(d.agentID); a != (LinuxRegistryAgent{}) || err == nil {
			t.Fatal("missing current identity accepted")
		}
		if a, err := s.Snapshot(d.pub.id); a.Wire != nil || a.Available || a.RollbackSafe || err == nil {
			t.Fatal("missing snapshot accepted")
		}
		if a, err := s.VerificationState([32]byte{}); !a.Now.IsZero() || a.Trusted || a.Fresh || a.IDJournal != nil || err == nil {
			t.Fatal("missing state accepted")
		}
	}
}

// Claim: original bytes survive exactly, reads are by the requested ID, and
// wrong-ID/oversized/error results never trigger fallback or usable output.
func TestLinuxApplicationSourceExactAttestation(t *testing.T) {
	d := newLinuxVerifierDock(t)
	original := bytes.Clone(d.fake.attestations[d.attID])
	s := linuxApplicationTestSource(t, linuxApplicationTestBindings(d))
	got, err := s.Attestation(d.attID)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("original bytes changed", err)
	}
	got[0] ^= 1
	if !bytes.Equal(d.fake.attestations[d.attID], original) {
		t.Fatal("caller mutated provider bytes")
	}
	// A different, well-formed ID must not select this envelope as newest-for-key.
	wrong := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	d.fake.attestations[wrong] = original
	if b, err := s.Attestation(wrong); b != nil || err == nil {
		t.Fatal("wrong-ID bytes accepted")
	}
	if len(d.fake.lookups) != 2 || d.fake.lookups[0] != d.attID || d.fake.lookups[1] != wrong {
		t.Fatal("fallback or ID substitution", d.fake.lookups)
	}
	if b, err := s.Attestation("not-an-id"); b != nil || err == nil || len(d.fake.lookups) != 2 {
		t.Fatal("invalid ID reached provider")
	}
	d.fake.attestations[d.attID] = make([]byte, mugrant.MaxEnvelopeBytes+1)
	if b, err := s.Attestation(d.attID); b != nil || err == nil {
		t.Fatal("over-bound envelope accepted")
	}
	d.fake.attErr = errors.New("synthetic unavailable")
	if b, err := s.Attestation(d.attID); b != nil || !errors.Is(err, d.fake.attErr) {
		t.Fatal("provider failure lost", err)
	}
}

// Claim: fresh reads preserve inactive/conflicting identity, continuity/trust
// flags and request hashes; returned journal/snapshot bytes have independent ownership.
func TestLinuxApplicationSourceEvidenceOwnership(t *testing.T) {
	d := newLinuxVerifierDock(t)
	s := linuxApplicationTestSource(t, linuxApplicationTestBindings(d))
	a, err := s.CurrentAgent(d.agentID)
	if err != nil || a != d.fake.agent {
		t.Fatal("identity changed", err)
	}
	d.fake.agent.Generation = "changed-generation"
	d.fake.agent.Active = false
	a, err = s.CurrentAgent(d.agentID)
	if err != nil || a != d.fake.agent || d.fake.calls != 2 {
		t.Fatal("cached or promoted identity", err)
	}
	d.fake.agent.Key = d.serviceID
	if a, err := s.CurrentAgent(d.agentID); a != (LinuxRegistryAgent{}) || err == nil {
		t.Fatal("wrong key admitted")
	}
	calls := d.fake.calls
	if _, err := s.CurrentAgent("invalid"); err == nil || d.fake.calls != calls {
		t.Fatal("invalid key reached provider")
	}

	snapshot := d.fake.snapshots[d.pub.id]
	snapshot.Available, snapshot.RollbackSafe = false, false
	d.fake.snapshots[d.pub.id] = snapshot
	got, err := s.Snapshot(d.pub.id)
	if err != nil || got.Available || got.RollbackSafe || !bytes.Equal(got.Wire, snapshot.Wire) {
		t.Fatal("snapshot flags promoted", err)
	}
	got.Wire[0] ^= 1
	if bytes.Equal(got.Wire, snapshot.Wire) {
		t.Fatal("snapshot storage shared")
	}
	d.fake.snapshots[d.pub.id] = LinuxSnapshot{Wire: make([]byte, mugrant.MaxEnvelopeBytes+1), Available: true, RollbackSafe: true}
	if got, err := s.Snapshot(d.pub.id); got.Wire != nil || got.Available || got.RollbackSafe || err == nil {
		t.Fatal("over-bound snapshot accepted")
	}

	hash := sha256.Sum256(d.event.Envelope)
	d.fake.state.IDJournal = map[string][]byte{d.attID: {1, 2, 3}}
	d.fake.state.Trusted, d.fake.state.Fresh = false, false
	d.fake.state.WatermarkAvailable, d.fake.state.IDJournalAvailable = false, false
	state, err := s.VerificationState(hash)
	if err != nil || state.Trusted || state.Fresh || state.WatermarkAvailable || state.IDJournalAvailable {
		t.Fatal("state flags promoted", err)
	}
	state.IDJournal[d.attID][0] = 9
	delete(state.IDJournal, d.attID)
	if !bytes.Equal(d.fake.state.IDJournal[d.attID], []byte{1, 2, 3}) {
		t.Fatal("journal storage shared")
	}
	d.fake.state.IDJournal = nil
	state, err = s.VerificationState([32]byte{})
	if err != nil || state.IDJournal != nil || len(d.fake.requestHashes) != 2 || d.fake.requestHashes[0] != hash || d.fake.requestHashes[1] != ([32]byte{}) {
		t.Fatal("request hash or nil journal replaced", err)
	}
}

// Claim: the composed source reaches the real verifier and durable receiver;
// failures at either sampling point leave zero reservations/nonces/effects.
// Restoring the exact provider permits the identical request once, proving the
// refusal came from the changed input and did not consume its allowance.
func TestLinuxApplicationSourceFinalAdmission(t *testing.T) {
	for _, mode := range []string{"valid", "attestation-unavailable", "wrong-attestation", "current-unavailable", "wrong-uid", "wrong-mxid", "inactive", "changed-generation-final", "snapshot-unavailable", "continuity-unavailable", "state-unavailable", "untrusted-time", "missing-journal", "A1-only"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			b := linuxApplicationTestBindings(d)
			reads := 0
			b.CurrentAgent = func(key string) (LinuxRegistryAgent, error) {
				reads++
				a, err := d.fake.CurrentAgent(key)
				switch mode {
				case "current-unavailable":
					return LinuxRegistryAgent{}, errors.New("synthetic unavailable")
				case "wrong-uid":
					a.UID++
				case "wrong-mxid":
					a.MXID = "@fixture-principal-9:example.invalid"
				case "inactive":
					a.Active = false
				case "changed-generation-final":
					if reads == 2 {
						a.Generation = "changed-after-first-admission"
					}
				}
				return a, err
			}
			b.Attestation = func(id string) ([]byte, error) {
				if mode == "attestation-unavailable" {
					return nil, errors.New("synthetic unavailable")
				}
				if mode == "wrong-attestation" {
					return d.fake.snapshots[d.pub.id].Wire, nil
				}
				return d.fake.Attestation(id)
			}
			b.Snapshot = func(root string) (LinuxSnapshot, error) {
				s, err := d.fake.Snapshot(root)
				if mode == "snapshot-unavailable" && root == d.revokerID {
					s.Available = false
				}
				if mode == "continuity-unavailable" {
					s.RollbackSafe = false
				}
				return s, err
			}
			b.VerificationState = func(hash [32]byte) (LinuxVerificationState, error) {
				s, err := d.fake.VerificationState(hash)
				switch mode {
				case "state-unavailable":
					return LinuxVerificationState{}, errors.New("synthetic unavailable")
				case "untrusted-time":
					s.Trusted = false
				case "missing-journal":
					s.IDJournal = nil
				case "A1-only":
					s.Assurance = linuxVerifierAssurance(t, "A1")
				}
				return s, err
			}
			source := linuxApplicationTestSource(t, b)
			v, err := NewLinuxVerifier(d.config, source, source, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := NewLinuxReceiver(g.config, v, fakeRegistry{keys: map[string]string{d.event.Sender: d.agentID}}, map[string]MUEffect{"work.assign": g.effect}, func() (time.Time, error) { return d.now, nil })
			out, err := r.Handle(context.Background(), d.event)
			if mode == "valid" {
				if err != nil || out == nil || out.State != "succeeded" || g.calls != 1 || reads != 2 {
					t.Fatal("valid source refused", err, g.calls, reads)
				}
				return
			}
			if err == nil || out != nil || g.calls != 0 {
				t.Fatal("refusal executed or returned outcome", err, g.calls)
			}
			if mode == "changed-generation-final" && reads != 2 {
				t.Fatal("final source not refreshed", reads)
			}
			state, openErr := openMUState(context.Background(), g.config.State, g.config.Binding)
			if openErr != nil {
				t.Fatal(openErr)
			}
			if len(state.reservations) != 0 || len(state.nonces) != 0 || len(state.allowances) != 0 {
				t.Fatal("refusal reserved an effect")
			}
			state.close()
			// Preserve the real journal/observations and repair only the source.
			source.bindings = linuxApplicationTestBindings(d)
			out, err = r.Handle(context.Background(), d.event)
			if err != nil || out == nil || out.State != "succeeded" || g.calls != 1 {
				t.Fatal("repaired provider did not admit exact request", err, g.calls)
			}
		})
	}
}
