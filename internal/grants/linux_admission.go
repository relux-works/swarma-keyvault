package grants

import (
	"sort"
	"time"
)

var _ LinuxProjectedVerifier = (*LinuxVerifier)(nil)

// VerifyAdmission connects the real verifier to the durable receiver port.
// A candidate requires full request authorization. On refusal, independently
// verified snapshots from those same source reads still reach durable custody.
// No source is fetched again here; verifier refusal codes pass through unchanged.
func (p *LinuxVerifier) VerifyAdmission(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
	verified, err := p.VerifyProjectedWithSnapshots(e, now)
	if err != nil {
		return LinuxAdmission{Snapshots: verified.VerifiedSnapshots}, err
	}
	signers := make([]string, 0, len(verified.SnapshotMarks))
	for signer := range verified.SnapshotMarks {
		signers = append(signers, signer)
	}
	sort.Strings(signers)
	admission := LinuxAdmission{Decision: verified.Decision, plan: verified.plan}
	for _, signer := range signers {
		entries, ok := verified.SnapshotEntries[signer]
		if !ok {
			return LinuxAdmission{}, ErrMUState
		}
		admission.Snapshots = append(admission.Snapshots, LinuxVerifiedSnapshot{
			Signer: signer, IssuedAt: verified.SnapshotMarks[signer], Entries: entries,
		})
	}
	return admission, nil
}
