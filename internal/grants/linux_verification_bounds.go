package grants

import "github.com/relux-works/swarma-keyvault/internal/mugrant"

// These are consumer-side ceilings for the state port, not transport admission
// or proof of a complete bounded provider view. History is never truncated.
const (
	linuxVerificationMaxViewBytes  = 1 << 20
	linuxVerificationMaxIDBindings = 4096
)

// Check before allocating the detached journal or the verifier evidence map.
// Account for the pinned Evidence representation: 16 bytes for the map, and
// each key's bytes plus 16 bytes and the original raw value. This also bounds
// integer arithmetic before addition. No failed or partial copy is returned.
func linuxVerificationJournalFits(journal map[string][]byte) bool {
	if len(journal) > linuxVerificationMaxIDBindings {
		return false
	}
	remaining := linuxVerificationMaxViewBytes - 16
	for id, wire := range journal {
		if len(wire) > mugrant.MaxEnvelopeBytes || len(id) > remaining {
			return false
		}
		remaining -= len(id)
		if remaining < 16 || len(wire) > remaining-16 {
			return false
		}
		remaining -= 16 + len(wire)
	}
	return true
}
