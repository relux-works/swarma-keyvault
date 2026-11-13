package keyvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// rootGrantsGrantV3Attempt is helper-local engine state, not a presence or review
// capability. Native code must independently present the complete plan, reload
// policy/record, qualify fresh presence and unwrap before this private call.
// There is no production constructor/CLI/ABI route until those gates dock.
type rootGrantsGrantV3Attempt struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	plan          *RootGrantsGrantV3Plan
	loadAuthority func(RootGrantsAddress) ([]byte, error)
	consumed      bool
}

// Closed effect information is separate from public-math parser errors. Once
// signing could have produced a signature, losing it is UNKNOWN, never retryable.
type RootGrantsGrantV3Failure struct {
	Code    string `json:"code"`
	Phase   string `json:"phase"`
	Outcome string `json:"outcome"`
	Message string `json:"message"`
}

type rootGrantsGrantV3Failure = RootGrantsGrantV3Failure

func (f *RootGrantsGrantV3Failure) Error() string { return "Root grants signature refused: " + f.Code }

func rootGrantsGrantV3Failed(code, phase string, signed bool) error {
	outcome := "not_applied"
	if signed {
		outcome = "unknown"
	}
	return &rootGrantsGrantV3Failure{Code: code, Phase: phase, Outcome: outcome, Message: "Root grants signature attempt ended"}
}

func newRootGrantsGrantV3Attempt(ctx context.Context, plan *RootGrantsGrantV3Plan) (*rootGrantsGrantV3Attempt, error) {
	if ctx == nil || plan == nil || len(plan.grant) == 0 {
		return nil, rootGrantsGrantV3Failed("invalid_arguments", "preflight", false)
	}
	// One absolute budget begins here, BEFORE a native display or fresh presence.
	// An earlier caller deadline wins. No later phase can renew it.
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	return &rootGrantsGrantV3Attempt{ctx: ctx, cancel: cancel, plan: plan}, nil
}

func (a *rootGrantsGrantV3Attempt) close() {
	if a != nil && a.cancel != nil {
		a.cancel()
	}
}

func (a *rootGrantsGrantV3Attempt) check(signed bool) error {
	if errors.Is(a.ctx.Err(), context.DeadlineExceeded) {
		return rootGrantsGrantV3Failed("timeout", "sign", signed)
	}
	if a.ctx.Err() != nil {
		return rootGrantsGrantV3Failed("canceled", "sign", signed)
	}
	return nil
}

// sign consumes every attempt, including malformed input, cancellation and random
// failure. It consumes/clears the owned 68-byte KVG1 buffer on EVERY exit. The
// sole result is a verified signature; there is no scalar getter or signer hook.
func (a *rootGrantsGrantV3Attempt) sign(ownedPlaintext []byte) ([]byte, error) {
	return a.signWithRandom(ownedPlaintext, rand.Reader)
}

// Private entropy seam, never a runtime switch or reusable signer callback.
func (a *rootGrantsGrantV3Attempt) signWithRandom(ownedPlaintext []byte, random io.Reader) ([]byte, error) {
	return a.signWithTestHooks(ownedPlaintext, random, nil, nil)
}

// signWithTestHooks keeps scheduling and math-boundary instrumentation package
// private. Production always calls this with nil hooks.
func (a *rootGrantsGrantV3Attempt) signWithTestHooks(ownedPlaintext []byte, random io.Reader,
	afterFinalRevalidation, beforePrivateMath func()) ([]byte, error) {
	defer clear(ownedPlaintext)
	if a == nil {
		return nil, rootGrantsGrantV3Failed("operation_unavailable", "sign", false)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.consumed {
		return nil, rootGrantsGrantV3Failed("operation_unavailable", "sign", false)
	}
	a.consumed = true // No refusal can revive the reviewed attempt.
	defer a.close()
	if err := a.check(false); err != nil {
		return nil, err
	}
	if len(ownedPlaintext) != 68 || random == nil {
		return nil, rootGrantsGrantV3Failed("invalid_envelope", "sign", false)
	}
	r, err := ParseRootGrantsRecord(a.plan.record)
	if err != nil {
		return nil, rootGrantsGrantV3Failed("binding_mismatch", "sign", false)
	}
	plain := &rootGrantsPlaintext{buffer: new([68]byte)}
	defer plain.clear()
	copy(plain.buffer[:], ownedPlaintext)
	clear(ownedPlaintext)
	if err := plain.validate(r); err != nil {
		// The scalar and all binding details remain inside this engine.
		return nil, rootGrantsGrantV3Failed("binding_mismatch", "sign", false)
	}
	var aux [32]byte
	defer clear(aux[:])
	if _, err := io.ReadFull(random, aux[:]); err != nil {
		return nil, rootGrantsGrantV3Failed("operation_unavailable", "sign", false)
	}
	if err := a.check(false); err != nil {
		return nil, err
	}
	// Revalidate the immutable plan against current host-time validity. Native
	// policy/record reload and actual code/presence admission are separate gates.
	var authority RootGrantsAuthority
	if DecodeSingleJSON(a.plan.authority, &authority) != nil {
		return nil, rootGrantsGrantV3Failed("review_changed", "sign", false)
	}
	current, err := PrepareRootGrantsGrantV3(a.plan.grant, a.plan.contract, a.plan.authority, a.plan.record, authority.OwnerPrincipal, time.Now())
	if err != nil || !bytes.Equal(current.grant, a.plan.grant) || current.message != a.plan.message {
		return nil, rootGrantsGrantV3Failed("review_changed", "sign", false)
	}
	// Cancellation/expiry can race the final public validation itself. Check the
	// original attempt context at its return before any further private-use step.
	if afterFinalRevalidation != nil {
		afterFinalRevalidation()
	}
	if err := a.check(false); err != nil {
		return nil, err
	}
	if a.loadAuthority != nil {
		policyErr := rootGrantsGrantV3RequireInstalledAuthority(a.plan, a.loadAuthority)
		if err := a.check(false); err != nil {
			return nil, err
		}
		if policyErr != nil {
			return nil, policyErr
		}
	}
	// The second context gate follows the helper-local policy reload directly
	// before BIP-340 math. Any refusal after math may begin remains unknown.
	if err := a.check(false); err != nil {
		return nil, err
	}
	if beforePrivateMath != nil {
		beforePrivateMath()
	}
	signature, err := signNostrWithAux(plain.buffer[36:], a.plan.message[:], aux)
	plain.clear()
	clear(aux[:])
	if err != nil {
		return nil, rootGrantsGrantV3Failed("signature_verification_failed", "sign", true)
	}
	keep := false
	defer func() {
		if !keep {
			clear(signature)
		}
	}()
	if err := a.check(true); err != nil {
		return nil, err
	}
	if a.plan.VerifySignature(signature) != nil {
		return nil, rootGrantsGrantV3Failed("signature_verification_failed", "sign", true)
	}
	keep = true
	return signature, nil
}
