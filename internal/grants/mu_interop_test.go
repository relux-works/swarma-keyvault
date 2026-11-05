package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
	"github.com/relux-works/swarma-keyvault/internal/muinterop"
)

// muInteropRun handles every step of one interop case with a fresh receiver
// and returns the observed verdict per step and the number of effects.
func muInteropRun(t *testing.T, c muinterop.Case) ([]string, int) {
	t.Helper()
	return muInteropRunWith(t, c, nil)
}

// muInteropRunWith runs a case; a non-nil override replaces the platform
// verifier (used to show the set rejects degenerate implementations).
func muInteropRunWith(t *testing.T, c muinterop.Case, override MUVerifier) ([]string, int) {
	t.Helper()
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(c.ID, err)
		}
		return b
	}
	var grants [][]byte
	for _, g := range c.Records.Grants {
		grants = append(grants, dec(g))
	}
	events := map[string]MUEnvelopeEvent{}
	for _, e := range c.Events {
		events[e.ID] = MUEnvelopeEvent{Sender: c.Pins.SenderMXID, Receiver: c.Pins.ReceiverMXID, Room: c.Pins.Room, EventID: e.ID, Envelope: dec(e.Envelope), Text: dec(e.Text)}
	}
	var snapshot, agentSnapshot []byte
	cfg := MUPlatformConfig{GrantRoot: c.Pins.GrantRoot, Audience: c.Pins.Audience, Grants: grants,
		Publisher: dec(c.Records.PublisherAttestation), PublisherKey: c.Pins.PublisherKey, TimeAuthority: 5 * time.Minute,
		Snapshot: func() ([]byte, error) { return snapshot, nil }}
	registryKey := c.Pins.AgentKey
	if l := c.Pins.Linux; l != nil {
		registryKey = l.AgentKey
		served := map[string][]byte{}
		var gen muinterop.ActiveGeneration
		if c.Registry != nil {
			for id, b := range c.Registry.Attestations {
				served[id] = dec(b)
			}
			gen = c.Registry.ActiveGeneration
		}
		cfg.Linux = map[string]MULinuxAgent{l.AgentMXID: {Key: l.AgentKey, UID: l.UID, RegistrationNumber: l.RegistrationNumber}}
		cfg.Registry = MURegistryEvidence{ServiceRoot: l.ServiceRoot, AgentRevocationKey: l.AgentRevocationKey,
			Attestation: func(id string) ([]byte, error) {
				b, ok := served[id]
				if !ok {
					return nil, errors.New("not served")
				}
				return b, nil
			},
			ActiveGeneration: func(string) (mugrant.KeymakerBinding, error) { return gen.Binding(), nil },
			AgentSnapshot:    func() ([]byte, error) { return agentSnapshot, nil }}
	} else {
		cfg.Agents = map[string]MUMacAgent{c.Pins.SenderMXID: {Key: c.Pins.AgentKey, Attestation: dec(c.Records.AgentAttestation), Generation: c.Pins.AgentGeneration}}
	}
	platform := NewMUPlatform(cfg,
		func(id string) (MUEnvelopeEvent, error) {
			e, ok := events[id]
			if !ok {
				return MUEnvelopeEvent{}, errors.New("no such event")
			}
			return e, nil
		})
	dir := filepath.Join(t.TempDir(), "mu")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte(c.ID))}
	binding := MUBinding{Audience: c.Pins.Audience, GrantRoot: c.Pins.GrantRoot}
	if err := InitializeMUState(state, binding); err != nil {
		t.Fatal(err)
	}
	modules := map[string]bool{}
	for _, m := range c.Pins.Modules {
		modules[m] = true
	}
	effect := &countingEffect{}
	var verifier MUVerifier = platform
	if override != nil {
		verifier = override
	}
	r := NewMUReceiver(MUReceiverConfig{Binding: binding, State: state, Owner: c.Pins.Owner, RoomScope: c.Pins.RoomScope, Modules: modules, Paused: map[string]bool{},
		RootRevocations: func() ([]MURevocation, error) {
			var snaps [][]byte
			for _, r := range c.Records.RootRevocations {
				snaps = append(snaps, dec(r))
			}
			return VerifyRootRevocations(c.Pins.GrantRoot, snaps)
		}},
		verifier, fakeRegistry{keys: map[string]string{c.Pins.SenderMXID: registryKey}, owners: c.Pins.RegistryOwners},
		map[string]MUEffect{"work.assign": effect, "account.manage": effect})
	var got []string
	for _, s := range c.Steps {
		at, err := time.Parse("2006-01-02T15:04:05Z", s.Now)
		if err != nil {
			t.Fatal(c.ID, err)
		}
		r.now = func() time.Time { return at }
		snapshot = dec(s.Snapshot)
		agentSnapshot = nil
		if s.AgentSnapshot != "" {
			agentSnapshot = dec(s.AgentSnapshot)
		}
		out, err := r.Handle(context.Background(), MUEvent{SenderMXID: c.Pins.SenderMXID, RoomID: c.Pins.Room, EventID: s.Event})
		switch {
		case err == nil && out != nil:
			got = append(got, out.State)
		case platformCode(err) != "":
			got = append(got, platformCode(err))
		case err != nil:
			got = append(got, err.Error())
		default:
			got = append(got, "no-outcome")
		}
	}
	return got, effect.calls
}

// muInteropDir is the committed vector set.
const muInteropDir = "../../interop/multi-use-grants/cases"

func loadMUInterop(t *testing.T) []muinterop.Case {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(muInteropDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("no committed interop cases", err)
	}
	var cases []muinterop.Case
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytesReader(raw))
		d.DisallowUnknownFields()
		var c muinterop.Case
		if err := d.Decode(&c); err != nil || c.Format != muinterop.Format || filepath.Base(f) != c.ID+".json" {
			t.Fatal("case file refused", f, err)
		}
		cases = append(cases, c)
	}
	return cases
}

// Claim: every committed interop case gives exactly its expected verdict per
// step through the real platform verifier (pinned swarma-envelope) and the
// KV receiver; effects run exactly once per succeeded step; every negative
// names a positive control that exists and itself succeeds.
func TestMUInteropVectors(t *testing.T) {
	cases := loadMUInterop(t)
	byID := map[string]muinterop.Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, c := range cases {
		got, calls := muInteropRun(t, c)
		succeeded := 0
		for i, s := range c.Steps {
			if got[i] != s.Expected {
				t.Errorf("%s step %d: got %s, want %s", c.ID, i, got[i], s.Expected)
			}
			if s.Expected == "succeeded" {
				succeeded++
			}
		}
		if calls != succeeded {
			t.Errorf("%s: %d effects for %d succeeded steps", c.ID, calls, succeeded)
		}
		if c.PositiveControl != "" {
			p, ok := byID[c.PositiveControl]
			if !ok || p.PositiveControl != "" || p.Steps[0].Expected != "succeeded" {
				t.Errorf("%s: positive control %s missing or not positive", c.ID, c.PositiveControl)
			}
		}
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// TestMUInteropFresh prints the observed verdicts of freshly generated cases
// (diagnostic for regeneration; not a pass condition beyond running).
func TestMUInteropFresh(t *testing.T) {
	if os.Getenv("MU_INTEROP_FRESH") == "" {
		t.Skip("diagnostic")
	}
	cases, err := muinterop.MacFamily()
	if err != nil {
		t.Fatal(err)
	}
	linux, err := muinterop.LinuxFamily()
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, linux...)
	for _, c := range cases {
		got, calls := muInteropRun(t, c)
		t.Logf("%s: got %v effects %d", c.ID, got, calls)
	}
}

type muRefuseAll struct{}

func (muRefuseAll) Verify(MUEvent, time.Time) (MUDecision, error) { return MUDecision{}, ErrMUState }

// muAcceptAll admits every event without verifying anything, as an
// in-scope work.assign under an until_expiry grant with a fresh nonce.
type muAcceptAll struct {
	pins muinterop.Pins
	n    int
}

func (a *muAcceptAll) Verify(ev MUEvent, now time.Time) (MUDecision, error) {
	a.n++
	nonce := fmt.Sprintf("%s-%d", ev.EventID, a.n)
	return MUDecision{GrantRoot: a.pins.GrantRoot, GrantID: "sha256:any", Use: "until_expiry", Author: a.pins.AgentKey, Audience: a.pins.Audience, Nonce: nonce,
		Action: "work.assign", TargetKind: "product", TargetID: "swarma-platform", Arguments: map[string]string{"module": "swarma-keyvault", "title": "t"},
		Expires: now.Add(time.Minute), RequestHash: sha256.Sum256([]byte(nonce))}, nil
}

// Claim: the committed set rejects degenerate implementations. A receiver
// whose verifier refuses everything fails every positive step, and one
// whose verifier accepts everything fails every negative step that expects
// a platform, text or grant-selection refusal. Limit: this shows the set
// discriminates; it is not a mutation test of the real receiver.
func TestMUInteropRejectsDegenerate(t *testing.T) {
	positives, refuseMisses, verifierNegatives, acceptMisses := 0, 0, 0, 0
	for _, c := range loadMUInterop(t) {
		refused, _ := muInteropRunWith(t, c, muRefuseAll{})
		accepted, _ := muInteropRunWith(t, c, &muAcceptAll{pins: c.Pins})
		for i, s := range c.Steps {
			switch {
			case s.Expected == "succeeded":
				positives++
				if refused[i] != "succeeded" {
					refuseMisses++
				}
			case !strings.HasPrefix(s.Expected, "mu-") || s.Expected == "mu-no-applicable-grant" || s.Expected == "mu-ambiguous-grant" || s.Expected == "mu-request-text-refused":
				verifierNegatives++
				if accepted[i] != s.Expected {
					acceptMisses++
				}
			}
		}
	}
	if positives == 0 || refuseMisses != positives {
		t.Errorf("refuse-all passes %d of %d positive steps", positives-refuseMisses, positives)
	}
	if verifierNegatives == 0 || acceptMisses != verifierNegatives {
		t.Errorf("accept-all passes %d of %d verifier-refusal steps", verifierNegatives-acceptMisses, verifierNegatives)
	}
}
