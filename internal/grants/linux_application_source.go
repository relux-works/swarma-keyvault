package grants

import (
	"bytes"
	"strings"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// LinuxApplicationBindings supplies the existing consumer ports from protected
// installation dependencies. The function signatures are those of
// LinuxEvidenceSource and LinuxStateSource; this is not a transport protocol.
//
// Each function must perform an authenticated, authorized, bounded read with a
// finite operation deadline. Attestation serves original issuer-signed bytes by
// content ID. CurrentAgent refreshes protected current-generation evidence on
// every call. Snapshot owns durable continuity; VerificationState owns qualified
// time, durable history and independent exact-request assurance. These provider
// obligations cannot be established by a response, constructor or local clock.
// Missing deployment bindings must remain nil; no default provider is installed.
type LinuxApplicationBindings struct {
	Attestation       func(contentID string) ([]byte, error)
	CurrentAgent      func(key string) (LinuxRegistryAgent, error)
	Snapshot          func(root string) (LinuxSnapshot, error)
	VerificationState func(requestHash [32]byte) (LinuxVerificationState, error)
}

// LinuxApplicationSource composes protected providers for the first Linux
// application-key consumer. It caches no evidence, derives no identity from a
// sender and grants no authority. The pinned verifier authenticates envelopes
// and compares all binding fields; the receiver owns final serialized recheck,
// durable revocation observation, replay accounting and effect admission.
//
// Returned mutable bytes are detached from provider storage. Providers must not
// mutate their results during a call (including while this adapter copies them).
// Actual read principal/disclosure, currentness/high-water recovery, snapshot
// continuity and time/A2 custody remain required deployment inputs.
type LinuxApplicationSource struct {
	bindings LinuxApplicationBindings
}

var _ LinuxEvidenceSource = (*LinuxApplicationSource)(nil)
var _ LinuxStateSource = (*LinuxApplicationSource)(nil)

// NewLinuxApplicationSource requires every provider explicitly. Construction
// checks wiring only; it does not qualify a provider or authorize activation.
func NewLinuxApplicationSource(b LinuxApplicationBindings) (*LinuxApplicationSource, error) {
	if b.Attestation == nil || b.CurrentAgent == nil || b.Snapshot == nil || b.VerificationState == nil {
		return nil, ErrMUState
	}
	return &LinuxApplicationSource{bindings: b}, nil
}

func (s *LinuxApplicationSource) Attestation(contentID string) ([]byte, error) {
	if s == nil || s.bindings.Attestation == nil || !record.IsContentID(contentID) {
		return nil, ErrMUState
	}
	wire, err := s.bindings.Attestation(contentID)
	if err != nil {
		return nil, err
	}
	// Use the existing parser/bound. No latest-for-key lookup, reserialization
	// or substitution of a registry storage signature is permitted. Signature
	// and exact profile checks still belong to the pinned verifier.
	id, err := muRecordID(wire, "attestation/1")
	if err != nil || id != contentID {
		return nil, ErrMUState
	}
	return bytes.Clone(wire), nil
}

func (s *LinuxApplicationSource) CurrentAgent(key string) (LinuxRegistryAgent, error) {
	if s == nil || s.bindings.CurrentAgent == nil || !strings.HasPrefix(key, "ed25519:") || record.ValidateKey(key) != nil {
		return LinuxRegistryAgent{}, ErrMUState
	}
	a, err := s.bindings.CurrentAgent(key)
	if err != nil {
		return LinuxRegistryAgent{}, err
	}
	if a.Key != key {
		return LinuxRegistryAgent{}, ErrMUState
	}
	// Preserve inactive/conflicting fields for the existing verifier's checks;
	// neither a successful read nor a previous generation makes them current.
	return a, nil
}

func (s *LinuxApplicationSource) Snapshot(root string) (LinuxSnapshot, error) {
	if s == nil || s.bindings.Snapshot == nil || record.ValidateKey(root) != nil {
		return LinuxSnapshot{}, ErrMUState
	}
	snapshot, err := s.bindings.Snapshot(root)
	if err != nil {
		return LinuxSnapshot{}, err
	}
	if len(snapshot.Wire) > mugrant.MaxEnvelopeBytes {
		return LinuxSnapshot{}, ErrMUState
	}
	// Do not promote availability or rollback safety from bytes/signatures.
	// Do not pre-filter old, future or incomplete signed observations: the
	// receiver must retain authenticated observations even on refusal.
	snapshot.Wire = bytes.Clone(snapshot.Wire)
	return snapshot, nil
}

func (s *LinuxApplicationSource) VerificationState(requestHash [32]byte) (LinuxVerificationState, error) {
	if s == nil || s.bindings.VerificationState == nil {
		return LinuxVerificationState{}, ErrMUState
	}
	state, err := s.bindings.VerificationState(requestHash)
	if err != nil {
		return LinuxVerificationState{}, err
	}
	if !linuxVerificationJournalFits(state.IDJournal) {
		return LinuxVerificationState{}, ErrMUState
	}
	// Preserve nil versus empty and all availability/trust flags. The zero
	// hash remains the existing issuance-only check; it never becomes A2.
	if state.IDJournal != nil {
		journal := make(map[string][]byte, len(state.IDJournal))
		for id, wire := range state.IDJournal {
			journal[id] = bytes.Clone(wire)
		}
		state.IDJournal = journal
	}
	return state, nil
}
