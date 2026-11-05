package grants

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// A2AOutcome reports local dispatch observation only. It is not portable Matrix
// attestation or a DELETE capability. UNKNOWN never releases a held allowance.
type A2AOutcome struct {
	State, RepositoryID, NodeID, FullName string
}

type a2aCheckedCreate struct {
	certificate *a2aCertificate
	request     *a2aRequest
}
type a2aProvider interface {
	create(context.Context, *a2aCheckedCreate) ([]byte, error)
}

type A2AMediator struct {
	receiver     *A2AReceiver
	state        A2AStateConfig
	providerPath string
	provider     a2aProvider
	now          func() time.Time
	open         func(context.Context, A2AStateConfig, *A2AReceiver) (*a2aState, error)
}

// NewA2AMediator does not initialize state, open credentials or call a provider.
// The caller admits the exact receiver/projection, provider and separate state
// configuration. A descriptive A2AVerifiedEnvelope cannot be passed to Execute.
func NewA2AMediator(receiver *A2AReceiver, state A2AStateConfig, providerPath string) *A2AMediator {
	return &A2AMediator{receiver: receiver, state: state, providerPath: providerPath, provider: a2aGHProvider{path: providerPath}, now: time.Now, open: openA2AState}
}

func (r *A2AReceiver) checkA2ACreate(event A2AEvent, now time.Time) (*a2aCheckedCreate, error) {
	verified, err := r.Verify(event, now)
	if err != nil {
		return nil, err
	}
	q, _, err := parseA2AEnvelope(event.Body)
	if err != nil {
		return nil, err
	}
	for _, c := range r.grants[event.SenderMXID] {
		if c.id == verified.CertificateID {
			return &a2aCheckedCreate{certificate: c, request: q}, nil
		}
	}
	return nil, ErrA2ANoGrant
}

// Execute copies the original event and rechecks it under one lock. The caller
// must supply an admitted authentic event observation, never requester-selected
// JSON masquerading as provenance. Locking and journal checks protect cooperating
// callers; they cannot prevent same-UID replacement, rollback or bypass.
func (m *A2AMediator) Execute(ctx context.Context, event A2AEvent) (*A2AOutcome, error) {
	if m == nil || m.receiver == nil || m.provider == nil || m.now == nil || m.open == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrA2AState
	}
	event.Body = bytes.Clone(event.Body)
	if _, err := m.receiver.checkA2ACreate(event, m.now()); err != nil {
		return nil, err
	}
	if err := checkLocalProviderExecutable(m.providerPath); err != nil {
		return nil, err
	}
	s, err := m.open(ctx, m.state, m.receiver)
	if err != nil {
		return nil, ErrA2AState
	}
	defer s.close()
	if ctx.Err() != nil {
		return nil, ErrA2AState
	}
	checked, err := m.receiver.checkA2ACreate(event, m.now())
	if err != nil {
		return nil, err
	}
	reservation := newA2AReservation(m.receiver, checked.certificate, checked.request)
	if prior, ok := s.certificates[reservation.certificateID]; ok && prior != reservation.certificateHash {
		return nil, ErrA2ACertificateCollision
	}
	// These independent indexes leave room for an explicitly versioned future
	// use policy. This G2 certificate still mandates exactly one grant use.
	if s.uses[reservation.use] != nil {
		return nil, ErrA2AUseHeld
	}
	if s.nonces[reservation.nonce] != nil {
		return nil, ErrA2ANonceHeld
	}
	if len(s.uses) >= 256 {
		return nil, ErrA2AState
	}
	if err := checkLocalProviderExecutable(m.providerPath); err != nil {
		return nil, err
	}
	sequence := s.link.sequence
	if err := s.append(journalReservation, encodeA2AReservation(reservation)); err != nil {
		return nil, ErrA2AState
	}
	intent := binary.BigEndian.AppendUint64([]byte("G2I1"), sequence)
	if err := s.append(journalDispatchIntent, intent); err != nil {
		return nil, ErrA2AState
	}
	unknown := func() (*A2AOutcome, error) { return &A2AOutcome{State: "unknown"}, ErrA2AUnknown }
	if ctx.Err() != nil {
		return unknown()
	}
	checked, err = m.receiver.checkA2ACreate(event, m.now())
	if err != nil {
		return unknown()
	}
	raw, err := m.provider.create(ctx, checked)
	if err != nil {
		return unknown()
	}
	receipt, err := parseRepositoryProviderReceipt(raw, A2ARepository)
	if err != nil {
		return unknown()
	}
	body := binary.BigEndian.AppendUint64([]byte("G2O1"), sequence)
	body = binary.BigEndian.AppendUint32(body, uint32(len(receipt.raw)))
	body = append(body, receipt.raw...)
	if err := s.append(journalOutcome, body); err != nil {
		return unknown()
	}
	return &A2AOutcome{State: "succeeded", RepositoryID: strconv.FormatUint(receipt.id, 10), NodeID: receipt.nodeID, FullName: LocalOrganization + "/" + A2ARepository}, nil
}

type a2aGHProvider struct{ path string }

func (p a2aGHProvider) create(ctx context.Context, checked *a2aCheckedCreate) ([]byte, error) {
	if checked == nil || checked.certificate == nil || checked.request == nil {
		return nil, errLocalProvider
	}
	// Reparse the already checked closed action: no generic argv or endpoint
	// comes from a request, human header, receipt or registry field.
	n, err := parseCanonical(checked.request.actionPayload, a2aActionWire)
	if err != nil || a2aTarget(n) != nil {
		return nil, errLocalProvider
	}
	input, err := json.Marshal(map[string]any{"name": A2ARepository, "private": true})
	if err != nil {
		return nil, errLocalProvider
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, p.path, "api", "--hostname", "github.com", "-X", "POST", "orgs/"+LocalOrganization+"/repos", "--input", "-")
	command.Stdin = bytes.NewReader(input)
	command.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	stdout := &boundedLocalOutput{maximum: localReceiptLimit}
	stderr := &boundedLocalOutput{maximum: 8192}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = subprocessWaitDelay
	if err := command.Run(); err != nil {
		return nil, errLocalProvider
	}
	return bytes.Clone(stdout.Bytes()), nil
}
