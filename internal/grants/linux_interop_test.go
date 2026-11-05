package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

const linuxInteropDir = "../../interop/multi-use-grants/cases"

// These tests consume only committed signed bytes, never keys.json, generators,
// signing providers, transport, or live credentials. Trusted time, A2 assurance,
// registry protection and source continuity are synthetic fixture premises.
func linuxInteropDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatal("invalid fixture base64url:", err)
	}
	return b
}

func loadLinuxInterop(t *testing.T) []linuxInteropCase {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(linuxInteropDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("no committed interop cases", err)
	}
	var cases []linuxInteropCase
	seen := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		var c linuxInteropCase
		if err := d.Decode(&c); err != nil {
			t.Fatal(f, err)
		}
		if d.Decode(new(any)) != io.EOF || c.Format != linuxInteropFormat || filepath.Base(f) != c.ID+".json" || seen[c.ID] || len(c.Steps) == 0 || len(c.Events) == 0 {
			t.Fatal("invalid case shape:", f)
		}
		if !linuxCaseCovered(c.ID) {
			t.Fatal("unclassified canonical case", c.ID)
		}
		seen[c.ID] = true
		t.Logf("LINUX_INTEROP_FILE %s %x", filepath.Base(f), sha256.Sum256(raw))
		cases = append(cases, c)
	}
	raw, err := os.ReadFile(filepath.Join(linuxInteropDir, "..", "CONTRACT.md"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LINUX_INTEROP_CONTRACT %x", sha256.Sum256(raw))
	return cases
}

// Return literal platform codes or literal receiver errors. This helper does
// no vocabulary translation (in particular revoked != mu-grant-revoked).
func linuxInteropCode(err error) string {
	if err == nil {
		return "accept"
	}
	var platform *ErrMUPlatform
	if errors.As(err, &platform) {
		return platform.Code
	}
	return err.Error()
}

type linuxInteropSource struct {
	c         linuxInteropCase
	snapshots map[string]LinuxSnapshot
	now       time.Time
	hashes    map[[32]byte]bool
}

func (s *linuxInteropSource) Attestation(id string) ([]byte, error) {
	if s.c.Registry == nil {
		return nil, errors.New("fixture registry unavailable")
	}
	b, ok := s.c.Registry.Attestations[id]
	if !ok {
		return nil, errors.New("fixture attestation unavailable")
	}
	return base64.RawURLEncoding.Strict().DecodeString(b)
}
func (s *linuxInteropSource) CurrentAgent(key string) (LinuxRegistryAgent, error) {
	l := s.c.Pins.Linux
	if l == nil || s.c.Registry == nil || key != l.AgentKey {
		return LinuxRegistryAgent{}, errors.New("fixture registry unavailable")
	}
	g := s.c.Registry.ActiveGeneration
	// Pass the published active generation verbatim, separately from the
	// protected identity in LinuxAgents. Only the real verifier compares them;
	// the adapter never substitutes a binding or synthesizes a mismatch error.
	return LinuxRegistryAgent{Key: l.AgentKey, MXID: l.AgentMXID, UID: g.UID, RegistrationNumber: g.RegistrationNumber,
		Generation: g.Generation, MasterEpoch: g.MasterEpoch, Owner: g.Owner, Path: g.Path, Active: true}, nil
}
func (s *linuxInteropSource) Snapshot(root string) (LinuxSnapshot, error) {
	snap, ok := s.snapshots[root]
	if !ok {
		return LinuxSnapshot{}, errors.New("fixture snapshot unavailable")
	}
	return snap, nil
}
func (s *linuxInteropSource) VerificationState(hash [32]byte) (LinuxVerificationState, error) {
	if !s.hashes[hash] {
		return LinuxVerificationState{}, errors.New("no fixture request-bound assurance")
	}
	a, err := verifier.Present(map[string]any{"level": "A2", "presence": false})
	if err != nil {
		return LinuxVerificationState{}, err
	}
	return LinuxVerificationState{Now: s.now, AuthorityUntil: s.now.Add(5 * time.Minute), Watermark: s.now,
		Trusted: true, Fresh: true, WatermarkAvailable: true, IDJournalAvailable: true, IDJournal: map[string][]byte{}, Assurance: a}, nil
}

type linuxInteropRegistry struct {
	key, mxid string
	owners    map[string]string
}

func (r linuxInteropRegistry) AttestedKey(mxid string) (string, bool) { return r.key, mxid == r.mxid }
func (r linuxInteropRegistry) OwnerOf(account string) (string, bool) {
	owner, ok := r.owners[account]
	return owner, ok
}

type linuxInteropCall struct {
	Code      string                  `json:"code"`
	Snapshots []LinuxVerifiedSnapshot `json:"snapshots,omitempty"`
}
type linuxInteropTrace struct {
	actual *LinuxVerifier
	calls  []linuxInteropCall
}

func (v *linuxInteropTrace) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	a, err := v.actual.VerifyAdmission(e, now)
	v.calls = append(v.calls, linuxInteropCall{Code: linuxInteropCode(err), Snapshots: a.Snapshots})
	return a, err // exact same-call result; no reread or reconstructed metadata
}

type linuxInteropRig struct {
	c              linuxInteropCase
	source         *linuxInteropSource
	verifierConfig LinuxVerifierConfig
	receiverConfig LinuxReceiverConfig
	registry       linuxInteropRegistry
	events         map[string]MUEnvelopeEvent
	calls          int
	effect         MUEffect
	active         *muState
	stepT          *testing.T
}

type linuxInteropEffect struct{ rig *linuxInteropRig }

func (e linuxInteropEffect) Execute(_ context.Context, d MUDecision) ([]byte, error) {
	g, t := e.rig, e.rig.stepT
	g.calls++
	if g.active == nil {
		t.Error("effect without journal lock")
		return nil, ErrMUState
	}
	u := MUUse{Once: d.Use == "once", GrantRoot: d.GrantRoot, GrantID: d.GrantID, Action: d.Action,
		TargetKind: d.TargetKind, TargetID: d.TargetID, Requester: d.Author, Nonce: d.Nonce, Audience: d.Audience, RequestHash: d.RequestHash}
	r := g.active.nonces[muNonceKey(u)]
	if r == nil || !r.intent || r.complete || r.requestHash != d.RequestHash || r.once != u.Once || (u.Once && g.active.allowances[muAllowanceKey(u)] != r) {
		t.Error("effect before held reservation and intent")
	}
	// Read the on-disk journal without acquiring its held lock. Replaying the
	// bytes independently checks reserve+intent existed before the countereffect.
	disk := linuxInteropReplay(t, g.receiverConfig.State, g.receiverConfig.Binding)
	held := disk.nonces[muNonceKey(u)]
	if held == nil || !held.intent || held.complete || held.requestHash != d.RequestHash {
		t.Error("reservation/intent absent on disk at effect")
	}
	return []byte("committed interop synthetic receipt"), nil
}

func linuxInteropReplay(t *testing.T, c MUStateConfig, b MUBinding) *muState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.Directory, "mu.journal"))
	if err != nil {
		t.Fatal(err)
	}
	s := &muState{binding: b, reservations: map[uint64]*muReservation{}, allowances: map[[32]byte]*muReservation{}, nonces: map[[32]byte]*muReservation{}, revoked: map[MURevocation]bool{}}
	// Only accounting frames are interpreted here; the frame reader checks the
	// digest chain, sequence and epoch for every frame, including revocations.
	rd := bytes.NewReader(raw)
	link := journalFrameLink{sequence: 1, epoch: c.Epoch}
	for {
		f, err := readJournalFrame(rd, link)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("on-disk journal frame:", err)
		}
		if link.sequence == 1 {
			if f.kind != journalActivation || !bytes.Equal(f.body, muActivation(b)) {
				t.Fatal("on-disk activation mismatch")
			}
		} else if f.kind == journalReservation || f.kind == journalDispatchIntent || f.kind == journalOutcome {
			if err := s.replay(f); err != nil {
				t.Fatal("on-disk accounting replay:", err)
			}
		}
		link.sequence++
		link.previous = f.digest
	}
	return s
}

func newLinuxInteropRig(t *testing.T, c linuxInteropCase) *linuxInteropRig {
	t.Helper()
	g := &linuxInteropRig{c: c, events: map[string]MUEnvelopeEvent{}}
	g.source = &linuxInteropSource{c: c, hashes: map[[32]byte]bool{}}
	for _, e := range c.Events {
		if _, ok := g.events[e.ID]; ok {
			t.Fatal(c.ID, "duplicate event", e.ID)
		}
		event := MUEnvelopeEvent{Sender: c.Pins.SenderMXID, Receiver: c.Pins.ReceiverMXID, Room: c.Pins.Room, EventID: e.ID,
			Envelope: linuxInteropDecode(t, e.Envelope), Text: linuxInteropDecode(t, e.Text)}
		g.events[e.ID] = event
		g.source.hashes[sha256.Sum256(event.Envelope)] = true
	}
	cfg := LinuxVerifierConfig{GrantRoot: c.Pins.GrantRoot, Audience: c.Pins.Audience, PublisherKey: c.Pins.PublisherKey,
		Publisher: linuxInteropDecode(t, c.Records.PublisherAttestation), RoomID: c.Pins.Room, ReceiverMXID: c.Pins.ReceiverMXID}
	for _, b := range c.Records.Grants {
		cfg.Grants = append(cfg.Grants, linuxInteropDecode(t, b))
	}
	// Public, unused Linux-role pins from the committed L-P-accept fixture.
	// The constructor requires them also for Mac-author requests.
	cfg.ServiceRoot = "ed25519:uxB6PugIJegpB6pq9adXrocdpMJ50FdMsxLBxlhDbJ0"
	cfg.AgentRevocationRoot = "ed25519:HTKprxyrH3pqWICWw3dZGl4ZNs6Rs3xqzPQ-RtQnYDU"
	g.registry = linuxInteropRegistry{key: c.Pins.AgentKey, mxid: c.Pins.SenderMXID, owners: c.Pins.RegistryOwners}
	if l := c.Pins.Linux; l != nil {
		cfg.ServiceRoot, cfg.AgentRevocationRoot = l.ServiceRoot, l.AgentRevocationKey
		g.registry.key, g.registry.mxid = l.AgentKey, l.AgentMXID
		cfg.LinuxAgents = map[string]MULinuxAgent{l.AgentMXID: {
			Key: l.AgentKey, UID: l.UID, RegistrationNumber: l.RegistrationNumber,
		}}
	} else {
		cfg.MacAgents = map[string]MUMacAgent{c.Pins.SenderMXID: {Key: c.Pins.AgentKey, Attestation: linuxInteropDecode(t, c.Records.AgentAttestation), Generation: c.Pins.AgentGeneration}}
	}
	g.verifierConfig = cfg
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte(c.ID))}
	binding := MUBinding{Audience: c.Pins.Audience, GrantRoot: c.Pins.GrantRoot}
	var roots [][]byte
	for _, b := range c.Records.RootRevocations {
		roots = append(roots, linuxInteropDecode(t, b))
	}
	rootSource := func() ([]MURevocation, error) { return VerifyRootRevocations(c.Pins.GrantRoot, roots) }
	if err := InitializeLinuxReceiverState(state, binding, rootSource); err != nil {
		t.Fatal(c.ID, "state initialization:", err)
	}
	modules := map[string]bool{}
	for _, m := range c.Pins.Modules {
		modules[m] = true
	}
	g.receiverConfig = LinuxReceiverConfig{MUReceiverConfig: MUReceiverConfig{State: state, Binding: binding, Owner: c.Pins.Owner,
		RoomScope: c.Pins.RoomScope, Modules: modules, Paused: map[string]bool{}, RootRevocations: rootSource, Signers: map[string]bool{cfg.PublisherKey: true, cfg.AgentRevocationRoot: true}}, PublisherKey: cfg.PublisherKey, AgentRevocationRoot: cfg.AgentRevocationRoot, RoomID: c.Pins.Room, ReceiverMXID: c.Pins.ReceiverMXID,
		// Additional Linux local policy, fixed independently of incoming arguments.
		// This is the positive room-membership fixture's protected room allowlist.
		AllowedRooms: map[string]bool{"!member-room:interop.invalid": true}}
	g.effect = linuxInteropEffect{rig: g}
	return g
}

func (g *linuxInteropRig) prepare(t *testing.T, s linuxInteropStep) (*LinuxVerifier, *linuxInteropTrace, *LinuxReceiver, MUEnvelopeEvent) {
	t.Helper()
	at, err := time.Parse("2006-01-02T15:04:05Z", s.Now)
	if err != nil {
		t.Fatal(err)
	}
	g.source.now = at
	g.source.snapshots = map[string]LinuxSnapshot{g.verifierConfig.PublisherKey: {Wire: linuxInteropDecode(t, s.Snapshot), Available: true, RollbackSafe: true}}
	if s.AgentSnapshot != "" {
		g.source.snapshots[g.verifierConfig.AgentRevocationRoot] = LinuxSnapshot{Wire: linuxInteropDecode(t, s.AgentSnapshot), Available: true, RollbackSafe: true}
	}
	event, ok := g.events[s.Event]
	if !ok {
		t.Fatal("missing fixture event", s.Event)
	}
	// Rebuild both actual objects on every step; only on-disk state survives.
	v, err := NewLinuxVerifier(g.verifierConfig, g.source, g.source, func(room, id string) (MUEnvelopeEvent, error) {
		e, ok := g.events[id]
		if !ok || room != e.Room {
			return MUEnvelopeEvent{}, ErrMUProjection
		}
		return e, nil
	})
	if err != nil {
		if linuxConstructionRefusals[g.c.ID] == "" {
			t.Fatal("unexpected construction refusal", g.c.ID, err)
		}
		t.Logf("LINUX_INTEROP_CONSTRUCTION_REFUSAL case=%s error=%s effects=%d reason=%s", g.c.ID, err, g.calls, linuxConstructionRefusals[g.c.ID])
		return nil, nil, nil, event
	}
	if linuxConstructionRefusals[g.c.ID] != "" {
		t.Fatal("invalid publisher configuration constructed", g.c.ID)
	}
	trace := &linuxInteropTrace{actual: v}
	r := NewLinuxReceiver(g.receiverConfig, trace, g.registry, map[string]MUEffect{"work.assign": g.effect, "account.manage": g.effect, "room.membership": g.effect}, func() (time.Time, error) { return at, nil })
	// Observe the real state under its real lock; no alternate journal or reserve.
	r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
		s, err := openMUState(ctx, c, b)
		g.active = s
		return s, err
	}
	g.stepT = t
	return v, trace, r, event
}

func linuxInteropProjection(t *testing.T, e MUEnvelopeEvent) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": "a2a.event-envelope-input/1", "sender_mxid": e.Sender, "receiver_mxid": e.Receiver,
		"requested_room_id": e.Room, "returned_room_id": e.Room, "requested_event_id": e.EventID, "returned_event_id": e.EventID,
		"envelope_base64": base64.RawURLEncoding.EncodeToString(e.Envelope), "body_text_base64": base64.RawURLEncoding.EncodeToString(e.Text)})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

type linuxInteropStepResult struct {
	Case                string                           `json:"case"`
	Step                int                              `json:"step"`
	Expected            string                           `json:"expected"`
	Actual              string                           `json:"actual"`
	DirectCode          string                           `json:"direct_code"`
	Calls               []linuxInteropCall               `json:"admission_calls"`
	Effects             int                              `json:"effect_delta"`
	Reservations        int                              `json:"reservations"`
	Nonces              int                              `json:"nonces"`
	Allowances          int                              `json:"allowances"`
	Snapshots           map[string]LinuxVerifiedSnapshot `json:"durable_snapshots"`
	ConstructionRefused bool                             `json:"construction_refused"`
	Matched             bool                             `json:"matched"`
}

func (g *linuxInteropRig) step(t *testing.T, index int, s linuxInteropStep) linuxInteropStepResult {
	t.Helper()
	v, trace, r, event := g.prepare(t, s)
	if v == nil {
		want := "key_binding_invalid"
		if g.c.ID == "P2-L-N-publisher-is-agent-revocation-root" || g.c.ID == "P2-L-N-publisher-is-service-root" {
			want = "revocation_invalid"
		}
		if s.Expected != want {
			t.Fatal("construction refusal not an exact invalid-attestation case", g.c.ID, s.Expected)
		}
		state := linuxInteropReplay(t, g.receiverConfig.State, g.receiverConfig.Binding)
		if g.calls != 0 || len(state.reservations) != 0 {
			t.Fatal("construction refusal reached an effect/reservation")
		}
		result := linuxInteropStepResult{Case: g.c.ID, Step: index, Expected: s.Expected, Actual: "construction-refused", DirectCode: "construction-refused", ConstructionRefused: true, Matched: true}
		raw, _ := json.Marshal(result)
		t.Logf("LINUX_INTEROP_STEP %s", raw)
		return result
	}
	// Direct verification checks the literal platform verdict independently;
	// journal replay, local scope and root overrides are receiver-only duties.
	_, directErr := v.VerifyProjectedWithSnapshots(event, g.source.now)
	directWant := s.Expected
	switch s.Expected {
	case "succeeded", "mu-grant-revoked", "mu-revocation-snapshot-rollback", "mu-request-nonce-already-held", "mu-grant-use-already-held", "mu-request-out-of-owner-scope":
		directWant = "accept"
	}
	if got := linuxInteropCode(directErr); got != directWant {
		t.Errorf("direct verifier verdict: %s, want %s (receiver %s)", got, directWant, s.Expected)
	}
	before := g.calls
	out, err := r.HandleProjection(context.Background(), linuxInteropProjection(t, event), event.Room, event.EventID)
	actual := linuxInteropCode(err)
	if err == nil {
		actual = "no-outcome"
		if out != nil {
			actual = out.State
		}
	}
	result := linuxInteropStepResult{Case: g.c.ID, Step: index, Expected: s.Expected, Actual: actual, DirectCode: linuxInteropCode(directErr), Calls: trace.calls, Effects: g.calls - before}
	expectedEffects := 0
	if s.Expected == "succeeded" {
		expectedEffects = 1
	}
	result.Matched = actual == s.Expected && result.Effects == expectedEffects
	if !result.Matched {
		t.Errorf("step %d: verdict %s, want %s; effects %d, want %d", index, actual, s.Expected, result.Effects, expectedEffects)
	}
	state, e := openMUState(context.Background(), g.receiverConfig.State, g.receiverConfig.Binding)
	if e != nil {
		t.Fatal("reopen accounting:", e)
	}
	defer state.close()
	result.Reservations, result.Nonces, result.Allowances = len(state.reservations), len(state.nonces), len(state.allowances)
	for _, held := range state.reservations {
		if !held.intent || !held.complete {
			t.Error("completed fixture effect lost intent/outcome after reopen")
		}
	}
	snapshotState, e := openLinuxRevocationState(state)
	if e != nil {
		t.Fatal("reopen snapshot state:", e)
	}
	defer snapshotState.close()
	result.Snapshots = snapshotState.latest
	if actual == "succeeded" {
		if len(trace.calls) == 0 {
			t.Error("effect without actual verifier admission")
		}
		for _, call := range trace.calls {
			for _, snapshot := range call.Snapshots {
				durable, ok := snapshotState.latest[snapshot.Signer]
				if !ok || !durable.IssuedAt.Equal(snapshot.IssuedAt) {
					t.Errorf("same-call signer mark not durable: %s", snapshot.Signer)
				}
				for _, entry := range snapshot.Entries {
					if !state.revoked[entry] {
						t.Errorf("same-call revocation not durable: %+v", entry)
					}
				}
			}
		}
	}
	raw, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("LINUX_INTEROP_STEP %s", raw)
	return result
}

// TestLinuxInteropVectors executes every committed case through the actual
// LinuxVerifier -> LinuxReceiver -> MU journal, not a mock verifier or overlay.
// All cases are explicitly served, including Mac authors. Only named invalid
// publisher configurations refuse construction; those emit no synthetic code.
// Claim: Every explicitly rostered canonical case is checked for exact verifier/receiver verdict and effect count or named construction refusal.
func TestLinuxInteropVectors(t *testing.T) {
	cases := loadLinuxInterop(t)
	byID := map[string]linuxInteropCase{}
	passed := map[string]bool{}
	caseCount, steps, effects, matches, constructionRefusals := 0, 0, 0, 0, 0
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, c := range cases {
		passed[c.ID] = t.Run(c.ID, func(t *testing.T) {
			g := newLinuxInteropRig(t, c)
			observedReservations := 0
			for i, s := range c.Steps {
				t.Run(fmt.Sprintf("step-%d", i), func(t *testing.T) {
					got := g.step(t, i, s)
					steps++
					if got.ConstructionRefused {
						constructionRefusals++
					}
					effects += got.Effects
					if got.Matched {
						matches++
					}
					observedReservations += got.Effects
					if got.Reservations != observedReservations || got.Nonces != observedReservations {
						t.Errorf("reopened accounting: reservations=%d nonces=%d countereffects=%d", got.Reservations, got.Nonces, observedReservations)
					}
				})
			}
		})
		caseCount++
	}
	t.Run("positive-controls", func(t *testing.T) {
		for _, c := range cases {
			if c.PositiveControl == "" {
				continue
			}
			p, ok := byID[c.PositiveControl]
			if !ok || p.PositiveControl != "" || !passed[c.PositiveControl] {
				t.Errorf("%s: positive control %s missing, nonpositive, or failed", c.ID, c.PositiveControl)
				continue
			}
			for _, s := range p.Steps {
				if s.Expected != "succeeded" {
					t.Errorf("%s: control %s contains refusal", c.ID, p.ID)
				}
			}
		}
	})
	t.Logf("LINUX_INTEROP_TOTAL cases=%d steps=%d matched=%d effects=%d construction_refusals=%d unsupported=0", caseCount, steps, matches, effects, constructionRefusals)
}

// A shared journal must admit both algorithms, retain their distinct nonce
// namespaces, and refuse both replays after constructing fresh actual objects.
// These are unchanged published M-P-accept and L-P-accept records; this composed
// sequence is an additional regression, not a new published corpus case.
// Claim: Mac and Linux authors share accounting while retaining distinct nonce namespaces and both replay holds.
func TestLinuxInteropMixedAuthors(t *testing.T) {
	byID := map[string]linuxInteropCase{}
	for _, c := range loadLinuxInterop(t) {
		byID[c.ID] = c
	}
	mac, mok := byID["M-P-accept"]
	linux, lok := byID["L-P-accept"]
	if !mok || !lok {
		t.Fatal("mixed-author regression requires r6 M-P-accept and L-P-accept")
	}
	m, l := newLinuxInteropRig(t, mac), newLinuxInteropRig(t, linux)
	if m.receiverConfig.Binding != l.receiverConfig.Binding {
		t.Fatal("published controls do not share a grant domain")
	}
	l.receiverConfig.State = m.receiverConfig.State
	t.Run("mac", func(t *testing.T) { m.step(t, 0, mac.Steps[0]) })
	t.Run("linux", func(t *testing.T) {
		got := l.step(t, 0, linux.Steps[0])
		if got.Reservations != 2 || got.Nonces != 2 {
			t.Error("mixed accounting not shared")
		}
	})
	for _, g := range []*linuxInteropRig{m, l} {
		t.Run(g.c.ID+"-replay", func(t *testing.T) {
			_, _, receiver, event := g.prepare(t, g.c.Steps[0])
			_, err := receiver.HandleProjection(context.Background(), linuxInteropProjection(t, event), event.Room, event.EventID)
			if !errors.Is(err, ErrMUNonceHeld) {
				t.Errorf("mixed replay: %v, want %s", err, ErrMUNonceHeld)
			}
			state, err := openMUState(context.Background(), g.receiverConfig.State, g.receiverConfig.Binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.close()
			if len(state.reservations) != 2 || len(state.nonces) != 2 {
				t.Error("mixed replay changed accounting")
			}
		})
	}
	if m.calls != 1 || l.calls != 1 {
		t.Errorf("mixed effects: mac=%d linux=%d", m.calls, l.calls)
	}
}

// Literal published text verdicts plus the shared contract rule catch drift in
// either Linux text entry point. The corpus includes all 22 forbidden classes,
// exactly 4096 bytes, TAB, and text-rule-before-hash ordering.
// Claim: Both Linux text entry points agree with every literal canonical text verdict and the shared rule.
func TestLinuxInteropTextRule(t *testing.T) {
	for _, c := range loadLinuxInterop(t) {
		t.Run(c.ID, func(t *testing.T) {
			steps := map[string]bool{}
			for _, s := range c.Steps {
				steps[s.Event] = s.Expected != "mu-request-text-refused"
			}
			for _, e := range c.Events {
				want, ok := steps[e.ID]
				if !ok {
					continue
				}
				text := linuxInteropDecode(t, e.Text)
				if shared := mugrant.RequestTextAdmissible(text); shared != want {
					t.Errorf("event %s: shared text rule=%v, published=%v", e.ID, shared, want)
				}
				if got := ValidateLinuxRequestText(text) == nil; got != want {
					t.Errorf("event %s: Linux requester/receiver text rule=%v, published=%v", e.ID, got, want)
				}
			}
		})
	}
}

type linuxInteropEffectFunc func(context.Context, MUDecision) ([]byte, error)

func (f linuxInteropEffectFunc) Execute(ctx context.Context, d MUDecision) ([]byte, error) {
	return f(ctx, d)
}

// Fail after the synthetic countereffect using the unchanged published positive
// controls. An unknown outcome must retain reserve+intent without a completion,
// then refuse replay after rebuilding both actual objects from the same journal.
// This is injected effect failure, not abrupt-process or cross-host qualification.
// Claim: A post-effect failure keeps reserve and intent without an outcome, and reopen never redispatches.
func TestLinuxInteropUnknownOutcome(t *testing.T) {
	byID := map[string]linuxInteropCase{}
	for _, c := range loadLinuxInterop(t) {
		byID[c.ID] = c
	}
	for _, id := range []string{"M-P-accept", "L-P-accept"} {
		t.Run(id, func(t *testing.T) {
			c, ok := byID[id]
			if !ok {
				t.Fatal("unknown-outcome regression requires r6 positive control", id)
			}
			g := newLinuxInteropRig(t, c)
			original := g.effect
			g.effect = linuxInteropEffectFunc(func(ctx context.Context, d MUDecision) ([]byte, error) {
				if d.Use != "until_expiry" {
					t.Errorf("published control policy changed: %s", d.Use)
				}
				_, err := original.Execute(ctx, d)
				if err != nil {
					return nil, err
				}
				return nil, errors.New("synthetic post-effect failure")
			})
			_, trace, receiver, event := g.prepare(t, c.Steps[0])
			out, err := receiver.HandleProjection(context.Background(), linuxInteropProjection(t, event), event.Room, event.EventID)
			if !errors.Is(err, ErrMUUnknown) || out == nil || out.State != "unknown" || g.calls != 1 {
				t.Fatalf("unknown dispatch: outcome=%+v err=%v effects=%d", out, err, g.calls)
			}
			state, err := openMUState(context.Background(), g.receiverConfig.State, g.receiverConfig.Binding)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.reservations) != 1 || len(state.nonces) != 1 {
				t.Error("unknown dispatch lost reservation")
			}
			for _, held := range state.reservations {
				if !held.intent || held.complete {
					t.Error("unknown dispatch intent/outcome changed")
				}
			}
			snapshots, err := openLinuxRevocationState(state)
			if err != nil {
				state.close()
				t.Fatal(err)
			}
			for _, call := range trace.calls {
				for _, snapshot := range call.Snapshots {
					if !snapshots.latest[snapshot.Signer].IssuedAt.Equal(snapshot.IssuedAt) {
						t.Error("unknown dispatch lost signer mark")
					}
				}
			}
			snapshots.close()
			state.close()
			_, _, receiver, event = g.prepare(t, c.Steps[0])
			_, err = receiver.HandleProjection(context.Background(), linuxInteropProjection(t, event), event.Room, event.EventID)
			if !errors.Is(err, ErrMUNonceHeld) || g.calls != 1 {
				t.Errorf("unknown replay: %v effects=%d", err, g.calls)
			}
		})
	}
}

// Explicit served roster: adding a canonical case requires an intentional rig review.
var linuxServedCases = map[string]bool{
	"L-N-agent-revoked-then-equal":              true,
	"L-N-agent-revoked-then-older":              true,
	"L-N-agent-revoked":                         true,
	"L-N-agent-rollback-drops-unrelated":        true,
	"L-N-agent-rollback-older-mark":             true,
	"L-N-attestation-expired":                   true,
	"L-N-attestation-unavailable":               true,
	"L-N-cross-algorithm":                       true,
	"L-N-generation-moved":                      true,
	"L-N-registry-uid-mismatch":                 true,
	"L-N-replay":                                true,
	"L-N-sender-not-registered":                 true,
	"L-N-stale-agent-snapshot":                  true,
	"L-N-wrong-action":                          true,
	"L-N-wrong-key":                             true,
	"L-P-accept":                                true,
	"M-N-account-other-owner":                   true,
	"M-N-ambiguous-grant":                       true,
	"M-N-audience-mismatch":                     true,
	"M-N-body-hash":                             true,
	"M-N-expired":                               true,
	"M-N-foreign-domain":                        true,
	"M-N-lifetime-over-120s":                    true,
	"M-N-module-outside":                        true,
	"M-N-publisher-is-grant-root":               true,
	"M-N-recipient-mismatch":                    true,
	"M-N-refused-then-older-mark":               true,
	"M-N-replay":                                true,
	"M-N-revoked-then-equal":                    true,
	"M-N-revoked-then-older":                    true,
	"M-N-revoked":                               true,
	"M-N-room-mismatch":                         true,
	"M-N-room-outside-scope":                    true,
	"M-N-root-revoked":                          true,
	"M-N-snapshot-older":                        true,
	"M-N-snapshot-rollback":                     true,
	"M-N-stale-snapshot":                        true,
	"M-N-text-bidi-061c":                        true,
	"M-N-text-bidi-200e":                        true,
	"M-N-text-bidi-200f":                        true,
	"M-N-text-bidi-202a":                        true,
	"M-N-text-bidi-202b":                        true,
	"M-N-text-bidi-202c":                        true,
	"M-N-text-bidi-202d":                        true,
	"M-N-text-bidi-202e":                        true,
	"M-N-text-bidi-2066":                        true,
	"M-N-text-bidi-2067":                        true,
	"M-N-text-bidi-2068":                        true,
	"M-N-text-bidi-2069":                        true,
	"M-N-text-blank":                            true,
	"M-N-text-c1":                               true,
	"M-N-text-cr":                               true,
	"M-N-text-del":                              true,
	"M-N-text-fffd":                             true,
	"M-N-text-ideographic-space":                true,
	"M-N-text-invalid-utf8":                     true,
	"M-N-text-nul":                              true,
	"M-N-text-over-limit":                       true,
	"M-N-text-rule-before-hash":                 true,
	"M-N-use-refill":                            true,
	"M-N-wrong-action":                          true,
	"M-N-wrong-key":                             true,
	"M-N-wrong-target":                          true,
	"M-P-accept":                                true,
	"M-P-account-own-owner":                     true,
	"M-P-future-then-fresh":                     true,
	"M-P-incomplete-then-older":                 true,
	"M-P-oversize-then-older":                   true,
	"M-P-room-membership":                       true,
	"M-P-root-revocation-unmirrored":            true,
	"M-P-text-at-limit":                         true,
	"M-P-text-tab":                              true,
	"M-P-until-expiry-second-use":               true,
	"P2-L-N-publisher-is-agent-revocation-root": true,
	"P2-L-N-publisher-is-service-root":          true,
	"P2-L-N-replay":                             true,
	"P2-L-N-revoked-then-older":                 true,
	"P2-L-N-revoked":                            true,
	"P2-L-N-snapshot-older":                     true,
	"P2-L-P-accept":                             true,
	"P2-N-issued-by-service-root":               true,
	"P2-N-profile-1-ed25519-subject":            true,
	"P2-N-profile-2-p256-subject":               true,
	"P2-N-revoked":                              true,
	"P2-N-snapshot-foreign-signer":              true,
	"P2-N-snapshot-older":                       true,
	"P2-N-unknown-profile":                      true,
	"P2-P-accept":                               true,
}

func linuxCaseCovered(id string) bool { return linuxServedCases[id] }

// These exact malformed publisher attestations may refuse at construction (§2.3).
var linuxConstructionRefusals = map[string]string{
	"M-N-publisher-is-grant-root":               "publisher aliases grant root",
	"P2-N-issued-by-service-root":               "publisher appointment is not owner-root signed",
	"P2-N-profile-1-ed25519-subject":            "profile 1 requires a P-256 subject",
	"P2-N-profile-2-p256-subject":               "profile 2 requires an Ed25519 subject",
	"P2-N-unknown-profile":                      "unknown publisher profile",
	"P2-L-N-publisher-is-agent-revocation-root": "publisher aliases agent revocation root",
	"P2-L-N-publisher-is-service-root":          "publisher aliases service root",
}
