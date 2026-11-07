package grants

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

const (
	linuxProviderMaxRecords      = 128
	linuxProviderStageLimit      = 2 * time.Second
	linuxProviderFinalLimit      = 100 * time.Millisecond
	linuxProviderDiagnosticLimit = 1024
)

// This local staging input is not a read admission or an installed provider.
// Its owner must exclude mutation for the duration of construction. No caller
// callback, transport, clock service or storage operation runs in construction.
// State and its complete history must be explicitly supplied, never defaulted.
type linuxProviderInput struct {
	// Original local observation instant paired with State.Now by the source.
	// Restaging preserves this instant; it must never be reset at a retry.
	// It is an expiry fence, not evidence that the source clock is qualified.
	ObservedAt   time.Time
	Config       LinuxVerifierConfig
	Event        MUEnvelopeEvent
	State        LinuxVerificationState
	Attestations map[string][]byte
	Agents       map[string]LinuxRegistryAgent
	Snapshots    map[string]LinuxSnapshot
	// Explicit protected grant-scope evidence only. An opaque Evidence cannot
	// be costed through the pinned API, so State.Assurance must be unavailable.
	// No A2 or presence claim can be staged through this unfinished path.
	Assurance map[string]any
}

// linuxProviderView owns detached immutable originals. It is advisory only:
// VerifyAdmission always refuses effects until existing-journal commitment and
// exclusion across the authoritative update sources are implemented together.
// In particular, publishing a newer view cannot invalidate an outstanding view.
type linuxProviderView struct {
	input    linuxProviderInput
	deadline time.Time // monotonic local fence; never a qualified clock source
}

// Check the complete content budget before detached copies or parsing. The
// budget includes collection/scalar overhead as well as all strings and original
// wire bytes. It is a projected-content limit, not a process RSS guarantee.
func linuxProviderInputFits(in linuxProviderInput) bool {
	return linuxProviderInputFitsBudget(in, 0, 0)
}

func linuxProviderInputFitsBudget(in linuxProviderInput, extraBytes, extraRecords int) bool {
	if extraBytes < 0 || extraBytes > linuxVerificationMaxViewBytes-1024 || extraRecords < 0 || extraRecords > linuxProviderMaxRecords {
		return false
	}
	c := in.Config
	if len(c.Grants) > linuxProviderMaxRecords || len(c.MacAgents) > linuxProviderMaxRecords || len(c.LinuxAgents) > linuxProviderMaxRecords ||
		len(in.Attestations) > linuxProviderMaxRecords || len(in.Agents) > linuxProviderMaxRecords || len(in.Snapshots) > linuxProviderMaxRecords ||
		len(in.State.IDJournal) > linuxVerificationMaxIDBindings || in.State.IDJournal == nil || in.State.Assurance.IsAvailable() {
		return false
	}
	records := extraRecords + 2 + len(c.Grants) + len(c.MacAgents) + len(c.LinuxAgents) + len(in.Attestations) + len(in.Agents) + len(in.Snapshots)
	remaining := linuxVerificationMaxViewBytes - 1024 - extraBytes // fixed scalar/collection overhead
	charge := func(n int) bool {
		if n < 0 || n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	text := func(s string) bool { return charge(16) && charge(len(s)) }
	wire := func(b []byte, max int) bool { return len(b) <= max && charge(16) && charge(len(b)) }
	for _, s := range []string{c.GrantRoot, c.ServiceRoot, c.AgentRevocationRoot, c.PublisherKey, c.Audience, c.RoomID, c.ReceiverMXID,
		in.Event.Sender, in.Event.Receiver, in.Event.Room, in.Event.EventID} {
		if !text(s) {
			return false
		}
	}
	if !wire(c.Publisher, 8192) || !wire(in.Event.Envelope, mugrant.MaxEnvelopeBytes) || !wire(in.Event.Text, 4096) {
		return false
	}
	for _, b := range c.Grants {
		if !wire(b, mugrant.MaxEnvelopeBytes) {
			return false
		}
	}
	for k, a := range c.MacAgents {
		if !text(k) || !text(a.Key) || !charge(32) || !wire(a.Attestation, 8192) {
			return false
		}
	}
	for k, a := range c.LinuxAgents {
		if !text(k) || !text(a.Key) || !charge(32) {
			return false
		}
	}
	for k, b := range in.Attestations {
		if !text(k) || !wire(b, 8192) {
			return false
		}
	}
	for k, a := range in.Agents {
		if !charge(64) {
			return false
		}
		for _, s := range []string{k, a.Key, a.MXID, a.Generation, a.MasterEpoch, a.Owner, a.Path} {
			if !text(s) {
				return false
			}
		}
	}
	for k, s := range in.Snapshots {
		if !text(k) || !charge(32) || !wire(s.Wire, 8192) {
			return false
		}
	}
	for k, b := range in.State.IDJournal {
		if len(b) != 0 {
			records++
		}
		if !text(k) || !wire(b, mugrant.MaxEnvelopeBytes) {
			return false
		}
	}
	if len(in.Assurance) != 0 {
		if len(in.Assurance) != 2 || in.Assurance["level"] != "A1" || in.Assurance["presence"] != false || !charge(128) {
			return false
		}
	}
	return records <= linuxProviderMaxRecords
}

func newLinuxProviderView(in linuxProviderInput) (*linuxProviderView, error) {
	start := time.Now()
	if !linuxProviderInputFits(in) || in.ObservedAt.IsZero() || in.ObservedAt == in.ObservedAt.Round(0) || in.ObservedAt.After(start) || start.Sub(in.ObservedAt) >= linuxProviderStageLimit ||
		in.State.Now.IsZero() || !in.State.AuthorityUntil.After(in.State.Now) {
		return nil, ErrMUState
	}
	earliest := in.State.AuthorityUntil
	// Only narrow the original deadline. Never derive qualified time or trust
	// from these fields, a local wall clock or successful parsing.
	interval := func(raw []byte, snapshot bool) bool {
		e, err := muParseEnvelope(raw)
		if err != nil {
			return false
		}
		b, ok := e["body"].(map[string]any)
		if !ok {
			return false
		}
		field := "exp"
		if snapshot {
			field = "issued_at"
		}
		at, err := time.Parse("2006-01-02T15:04:05Z", strOr(b[field]))
		if err != nil {
			return false
		}
		if snapshot {
			at = at.Add(60 * time.Second)
		}
		if at.Before(earliest) {
			earliest = at
		}
		if !snapshot {
			// Grant caveats may narrow the envelope interval. Keep that
			// original expiry even though qualified Now is an immutable fact.
			for _, value := range []any{b["expires"], func() any {
				if caveats, ok := b["caveats"].(map[string]any); ok {
					return caveats["expires"]
				}
				return nil
			}()} {
				if value == nil {
					continue
				}
				narrow, err := time.Parse("2006-01-02T15:04:05Z", strOr(value))
				if err != nil {
					return false
				}
				if narrow.Before(earliest) {
					earliest = narrow
				}
			}
		}
		return true
	}
	if !interval(in.Config.Publisher, false) || !interval(in.Event.Envelope, false) {
		return nil, ErrMUState
	}
	for _, b := range in.Config.Grants {
		if !interval(b, false) {
			return nil, ErrMUState
		}
	}
	for _, a := range in.Config.MacAgents {
		if !interval(a.Attestation, false) {
			return nil, ErrMUState
		}
	}
	for _, b := range in.Attestations {
		if !interval(b, false) {
			return nil, ErrMUState
		}
	}
	for _, s := range in.Snapshots {
		if !interval(s.Wire, true) {
			return nil, ErrMUState
		}
	}
	if !earliest.After(in.State.Now) {
		return nil, ErrMUState
	}
	v := &linuxProviderView{deadline: in.ObservedAt.Add(earliest.Sub(in.State.Now))}
	// NewLinuxVerifier already owns the complete policy-copy rules.
	p, err := NewLinuxVerifier(in.Config, v, v, nil)
	if err != nil {
		return nil, err
	}
	v.input = in
	v.input.Config = p.config
	v.input.Event = linuxCloneEvent(in.Event)
	v.input.Attestations = make(map[string][]byte, len(in.Attestations))
	for k, b := range in.Attestations {
		v.input.Attestations[k] = bytes.Clone(b)
	}
	v.input.Agents = make(map[string]LinuxRegistryAgent, len(in.Agents))
	for k, a := range in.Agents {
		v.input.Agents[k] = a
	}
	v.input.Snapshots = make(map[string]LinuxSnapshot, len(in.Snapshots))
	for k, s := range in.Snapshots {
		s.Wire = bytes.Clone(s.Wire)
		v.input.Snapshots[k] = s
	}
	v.input.State.IDJournal = make(map[string][]byte, len(in.State.IDJournal))
	for k, b := range in.State.IDJournal {
		v.input.State.IDJournal[k] = bytes.Clone(b)
	}
	v.input.Assurance = nil
	if len(in.Assurance) != 0 {
		v.input.State.Assurance, err = verifier.Present(map[string]any{"level": "A1", "presence": false})
		if err != nil {
			return nil, ErrMUState
		}
	}
	if time.Since(in.ObservedAt) >= linuxProviderStageLimit || !time.Now().Before(v.deadline) {
		return nil, ErrMUState
	}
	return v, nil
}

func (v *linuxProviderView) usable() bool { return v != nil && time.Now().Before(v.deadline) }
func (v *linuxProviderView) Attestation(id string) ([]byte, error) {
	if !v.usable() {
		return nil, ErrMUState
	}
	b, ok := v.input.Attestations[id]
	if !ok {
		return nil, ErrMUState
	}
	return bytes.Clone(b), nil
}
func (v *linuxProviderView) CurrentAgent(key string) (LinuxRegistryAgent, error) {
	if !v.usable() {
		return LinuxRegistryAgent{}, ErrMUState
	}
	a, ok := v.input.Agents[key]
	if !ok {
		return LinuxRegistryAgent{}, ErrMUState
	}
	return a, nil
}
func (v *linuxProviderView) Snapshot(key string) (LinuxSnapshot, error) {
	if !v.usable() {
		return LinuxSnapshot{}, ErrMUState
	}
	s, ok := v.input.Snapshots[key]
	if !ok {
		return LinuxSnapshot{}, ErrMUState
	}
	s.Wire = bytes.Clone(s.Wire)
	return s, nil
}
func (v *linuxProviderView) VerificationState(hash [32]byte) (LinuxVerificationState, error) {
	if !v.usable() || hash == [32]byte{} || hash != sha256.Sum256(v.input.Event.Envelope) {
		return LinuxVerificationState{}, ErrMUState
	}
	s := v.input.State
	s.IDJournal = make(map[string][]byte, len(v.input.State.IDJournal))
	for k, b := range v.input.State.IDJournal {
		s.IDJournal[k] = bytes.Clone(b)
	}
	return s, nil
}

// Advisory checks use only the staged exact request and local detached sources.
// There is no timeout goroutine: bounded in-process work finishes before return.
// Elapsed-time refusal does not cancel or bound a blocking storage operation;
// none is called here. The final storage boundary remains disabled below.
func (v *linuxProviderView) advisory() (LinuxAdmission, error) {
	start := time.Now()
	if !v.usable() {
		return LinuxAdmission{}, linuxVerifierRefuse("time_unavailable")
	}
	p, err := NewLinuxVerifier(v.input.Config, v, v, nil)
	if err != nil {
		return LinuxAdmission{}, err
	}
	a, err := p.VerifyAdmission(linuxCloneEvent(v.input.Event), v.input.State.Now)
	if time.Since(start) >= linuxProviderFinalLimit || !v.usable() {
		return LinuxAdmission{Snapshots: a.Snapshots}, linuxVerifierRefuse("time_unavailable")
	}
	return a, err
}

func (v *linuxProviderView) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	if !v.usable() || !now.Equal(v.input.State.Now) || !bytes.Equal(e.Envelope, v.input.Event.Envelope) || !bytes.Equal(e.Text, v.input.Event.Text) ||
		e.Sender != v.input.Event.Sender || e.Room != v.input.Event.Room || e.Receiver != v.input.Event.Receiver || e.EventID != v.input.Event.EventID {
		return LinuxAdmission{}, ErrMUState
	}
	a, err := v.advisory()
	if err != nil {
		return a, err
	}
	// Return authenticated observations, never an effect candidate. No complete
	// time/ID plan has been atomically committed with the MU use reservation.
	return LinuxAdmission{Snapshots: a.Snapshots}, ErrMUState
}

func (v *linuxProviderView) privateDiagnostic() string {
	// Static bounded status only: no request, identity, evidence or backend text.
	return "provider unavailable: authoritative update exclusion and atomic MU time/ID commitment pending"
}
