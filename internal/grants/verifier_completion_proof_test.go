package grants

import (
	"bytes"
	"context"
	"fmt"
)

// The real measurement uses a fresh once-use fixture. Reopen validates the
// actual persisted journal, not the domain's in-memory projection. This proves
// replay after an acknowledged terminal return, not hardware power-loss safety.
func linuxVerifierCompletionProof(g *linuxCombinedRig, d *LinuxAdmissionDomain, out *MUOutcome, refusal error, calls int, timely bool) error {
	success := refusal == nil && out != nil && out.State == "succeeded" && len(out.Receipt) > 0
	deadline := linuxGenuineDeadlineCompletion(refusal)
	if (!success && !deadline) || (success && (calls != 1 || g.calls != 1 || !timely)) ||
		(deadline && (calls != 0 || g.calls != 0 || (out != nil && (out.State != "unknown" || len(out.Receipt) != 0)))) {
		return fmt.Errorf("completion/effect evidence mismatch: success=%t deadline=%t calls=%d timely=%t", success, deadline, calls, timely)
	}
	s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
	if err != nil {
		return fmt.Errorf("completion journal reopen: %w", err)
	}
	defer s.close()
	return linuxVerifierCompletionJournalProof(s, d, out, success)
}

func linuxVerifierCompletionJournalProof(s *muState, d *LinuxAdmissionDomain, out *MUOutcome, success bool) error {
	if len(s.highWater) != len(d.state.observations) || len(s.highWater) != 2 {
		return fmt.Errorf("missing signer observations")
	}
	for _, observation := range d.state.observations {
		if !s.highWater[observation.Signer].Equal(observation.IssuedAt) {
			return fmt.Errorf("signer high-water mismatch")
		}
		for _, entry := range observation.Entries {
			if !s.unions[observation.Signer][entry] {
				return fmt.Errorf("missing durable signer union")
			}
		}
	}
	uses := len(s.reservations)
	if uses > 1 || len(s.allowances) != uses || len(s.nonces) != uses || (success && uses != 1) || (out != nil && out.State == "unknown" && uses != 1) {
		return fmt.Errorf("reservation/nonce/once hold mismatch")
	}
	if uses == 0 {
		if len(s.verificationIDs) != 0 {
			return fmt.Errorf("verification commit without reservation")
		}
	} else {
		if len(s.verificationIDs) != 2 || len(d.state.view.input.State.IDJournal) != 2 {
			return fmt.Errorf("verification originals missing")
		}
		for id, wire := range d.state.view.input.State.IDJournal {
			if !bytes.Equal(s.verificationIDs[id], wire) {
				return fmt.Errorf("verification original mismatch")
			}
		}
	}
	for _, use := range s.reservations {
		if !use.once || s.allowances[use.allowance] != use || s.nonces[use.nonce] != use || use.complete != success || (success && !use.intent) || (out != nil && out.State == "unknown" && !use.intent) {
			return fmt.Errorf("durable intent/outcome or held use mismatch")
		}
	}
	return nil
}
