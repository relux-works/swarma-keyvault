package publishergate

import (
	"bytes"
	"context"
	"time"
)

// Code is a bounded public refusal; native errors, paths and policy contents
// must never be copied into these diagnostics.
type Code string

const (
	CallerRefused     Code = "caller_refused"
	OperationRefused  Code = "operation_refused"
	PolicyUnavailable Code = "policy_unavailable"
	PolicyStale       Code = "policy_stale"
	ClockRefused      Code = "clock_refused"
	ResourceLimit     Code = "resource_limit"
	NativeUnavailable Code = "native_unavailable"
)

type Refusal struct{ Code Code }

func (r *Refusal) Error() string { return string(r.Code) }
func refusal(code Code) error    { return &Refusal{Code: code} }

// Receiver is deliberately opaque. No caller-supplied JSON, PID, path, hash,
// environment, connection token or policy file can construct its boundary.
// There is currently no native implementation on any platform, including Mac.
type Receiver struct{ boundary admissionBoundary }

// NewReceiver refuses until a separately reviewed native adapter and protected
// policy authority exist. It does not inspect the host, load policy or fall back
// to the generic CLI/helper. A zero Receiver also refuses.
func NewReceiver() (*Receiver, error) { return nil, refusal(NativeUnavailable) }

// AdmittedRequest records only message admission, not private-operation
// authorization. A future publisher must still enforce exclusive custody,
// protected replay reservation, actual-key binding and the final revoke fence.
// There is no constructor from Request and no signing API in this package.
type AdmittedRequest struct{ request Request }

func (a *AdmittedRequest) Request() Request {
	if a == nil {
		return Request{}
	}
	return a.request
}

// admissionPolicy is a projection of independently protected, current policy.
// The boundary must validate its signature, anti-rollback epoch and authority,
// not load this projection from a shared-UID writable file. This projection is
// deliberately insufficient to configure a signer or select a custody route.
type admissionPolicy struct {
	scope              string
	epoch              uint64
	enabled            bool
	notBefore, expires time.Time
}

// admissionBoundary is the missing OS/protected-authority seam. Implementations
// must authenticate each original received message against the current external
// code requirement, exact reviewed builds and hardening policy. They must bind
// the copied payload to that same message and reject all FD/endpoint attachments.
// Each protected epoch identifies an immutable complete policy, including the
// code requirements omitted from this projection; any change advances the epoch.
// A connect-time identity followed by arbitrary stream bytes is insufficient.
// No production implementation or public injection hook exists. Test doubles
// prove only the Go ordering and closed-schema logic, never these OS properties.
type admissionBoundary interface {
	currentPolicy(context.Context) (admissionPolicy, error)
	authenticateAndCopyMessage(context.Context, admissionPolicy) ([]byte, error)
	now() time.Time
}

// Admit receives one authenticated immutable message from its sealed boundary.
// It cannot admit bytes supplied by an ordinary Go/CLI caller. Expiry is an
// exclusive upper bound. The result must be revalidated at any future private
// entry fence; retaining this object does not retain policy authority.
func (r *Receiver) Admit(ctx context.Context) (*AdmittedRequest, error) {
	if r == nil || r.boundary == nil {
		return nil, refusal(NativeUnavailable)
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, refusal(OperationRefused)
	}
	p, err := r.boundary.currentPolicy(ctx)
	if err != nil || !validScope(p.scope) || p.epoch == 0 || !p.enabled || p.notBefore.IsZero() || !p.expires.After(p.notBefore) {
		return nil, refusal(PolicyUnavailable)
	}
	if err := checkTime(p, r.boundary.now()); err != nil {
		return nil, err
	}
	raw, err := r.boundary.authenticateAndCopyMessage(ctx, p)
	if err != nil {
		// Do not leak arbitrary boundary/native error strings.
		return nil, refusal(CallerRefused)
	}
	if len(raw) > MaxRequestBytes {
		return nil, refusal(ResourceLimit)
	}
	req, err := DecodeRequest(bytes.Clone(raw))
	if err != nil {
		return nil, err
	}
	if req.scope != p.scope {
		return nil, refusal(OperationRefused)
	}
	if req.epoch != p.epoch {
		return nil, refusal(PolicyStale)
	}
	if ctx.Err() != nil {
		return nil, refusal(OperationRefused)
	}
	current, err := r.boundary.currentPolicy(ctx)
	if err != nil {
		return nil, refusal(PolicyUnavailable)
	}
	if current.scope != p.scope || current.epoch != p.epoch || current.enabled != p.enabled || !current.notBefore.Equal(p.notBefore) || !current.expires.Equal(p.expires) {
		return nil, refusal(PolicyStale)
	}
	// A receive/identity check may block across the validity end. This recheck
	// covers admission only; it is not a private-entry commit fence.
	if err := checkTime(p, r.boundary.now()); err != nil {
		return nil, err
	}
	// Either final boundary call may complete successfully after cancellation.
	// Recheck after both callbacks and before publishing the admitted request.
	if ctx.Err() != nil {
		return nil, refusal(OperationRefused)
	}
	return &AdmittedRequest{request: req}, nil
}

func checkTime(p admissionPolicy, now time.Time) error {
	if now.IsZero() || now.Before(p.notBefore) || !now.Before(p.expires) {
		return refusal(ClockRefused)
	}
	return nil
}
