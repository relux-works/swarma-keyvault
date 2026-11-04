package grants

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"time"
)

// LocalOutcome is a local CLI observation, not an authenticated Matrix result
// or an instance-safe DELETE capability. Unknown outcomes retain the use.
type LocalOutcome struct {
	State        string `json:"state"`
	RepositoryID string `json:"repository_id,omitempty"`
	NodeID       string `json:"node_id,omitempty"`
	FullName     string `json:"full_name,omitempty"`
}

type LocalMediator struct {
	enrollment *LocalEnrollment
	provider   localProvider
	now        func() time.Time
	open       func(*LocalEnrollment) (*localState, error)
}

func NewLocalMediator(e *LocalEnrollment) *LocalMediator {
	if e == nil {
		return &LocalMediator{}
	}
	return &LocalMediator{enrollment: e, provider: localGHProvider{path: e.ghPath}, now: time.Now, open: openLocalState}
}

// Execute validates all request authority before opening/reserving state, then
// holds one local lock through durable reservation, intent, dispatch and receipt.
// Every provider failure after intent is UNKNOWN, with no automatic release.
func (m *LocalMediator) Execute(ctx context.Context, certificate, request []byte) (*LocalOutcome, error) {
	if m == nil || m.enrollment == nil || m.provider == nil || m.now == nil || m.open == nil {
		return nil, ErrLocalState
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrLocalState
	}
	checked, err := m.enrollment.check(certificate, request, m.now())
	if err != nil {
		return nil, err
	}
	state, err := m.open(m.enrollment)
	if err != nil {
		return nil, ErrLocalState
	}
	defer state.close()
	if prior, ok := state.certificates[checked.certificateID]; ok && !bytes.Equal(prior, checked.certificate) {
		return nil, ErrLocalCertificateCollision
	}
	if prior := state.requests[checked.request.requestID]; prior != nil && (!bytes.Equal(prior.checked.attestation, checked.attestation) || !bytes.Equal(prior.checked.certificate, checked.certificate)) {
		return nil, ErrLocalRequestCollision
	}
	if state.uses[checked.request.logicalUseKey()] != nil {
		return nil, ErrLocalUseHeld
	}
	if len(state.uses) >= 256 {
		return nil, ErrLocalState
	}
	// Recheck at lock acquisition: waiting for a concurrent operation cannot
	// make a request dispatched after its certificate/request interval expired.
	checked, err = m.enrollment.check(checked.certificate, checked.attestation, m.now())
	if err != nil {
		return nil, err
	}
	checked.observedAt, err = localObservedTime(checked.observedAt)
	if err != nil {
		return nil, err
	}
	reservation := state.link.sequence
	if err := state.append(journalReservation, encodeLocalReservation(checked)); err != nil {
		return nil, ErrLocalState
	}
	intent := binary.BigEndian.AppendUint64([]byte("LCI1"), reservation)
	if err := state.append(journalDispatchIntent, intent); err != nil {
		return nil, ErrLocalState
	}
	if err := ctx.Err(); err != nil {
		return &LocalOutcome{State: "unknown"}, ErrLocalUnknown
	}
	if _, err := m.enrollment.check(checked.certificate, checked.attestation, m.now()); err != nil {
		return &LocalOutcome{State: "unknown"}, ErrLocalUnknown
	}
	raw, err := m.provider.create(ctx, checked)
	if err != nil {
		return &LocalOutcome{State: "unknown"}, ErrLocalUnknown
	}
	receipt, err := parseLocalProviderReceipt(raw)
	if err != nil {
		return &LocalOutcome{State: "unknown"}, ErrLocalUnknown
	}
	body := binary.BigEndian.AppendUint64([]byte("LCO1"), reservation)
	body = binary.BigEndian.AppendUint32(body, uint32(len(receipt.raw)))
	body = append(body, receipt.raw...)
	if err := state.append(journalOutcome, body); err != nil {
		return &LocalOutcome{State: "unknown"}, ErrLocalUnknown
	}
	return localSuccessOutcome(receipt), nil
}

func localSuccessOutcome(r *localProviderReceipt) *LocalOutcome {
	return &LocalOutcome{State: "succeeded", RepositoryID: strconv.FormatUint(r.id, 10), NodeID: r.nodeID, FullName: LocalOrganization + "/" + LocalRepository}
}
