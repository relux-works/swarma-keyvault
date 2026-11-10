package keyvault

import (
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

const RecoveryOutcomeUnknownCode = signerclient.CodeRecoveryOutcomeUnknown

// RecoveryNotAppliedError is a backend guarantee that the requested mutation
// had no effect. Backends must not use it for a failed/lost post-effect reply.
type RecoveryNotAppliedError struct{ Err error }

func (e *RecoveryNotAppliedError) Error() string { return e.Err.Error() }
func (e *RecoveryNotAppliedError) Unwrap() error { return e.Err }

// RecoveryOutcomeUnknown carries only an UNCONFIRMED public reference. It is
// neither evidence of creation/deletion nor authority to retry or delete.
type RecoveryOutcomeUnknown struct {
	Outcome   string         `json:"outcome"`
	Operation string         `json:"operation"`
	Reference RecoveryRecord `json:"reference"`
}

func (e *RecoveryOutcomeUnknown) Error() string {
	return "Recovery mutation outcome is unknown; public reference is UNCONFIRMED"
}
func (e *RecoveryOutcomeUnknown) Unwrap() error {
	return &Refusal{Code: RecoveryOutcomeUnknownCode, Message: e.Error(), Hint: "reconcile the UNCONFIRMED public reference; do not retry or delete", Failure: true}
}
func recoveryMutationError(operation string, r RecoveryRecord, err error) error {
	var noEffect *RecoveryNotAppliedError
	if errors.As(err, &noEffect) {
		return err
	}
	// Deliberately discard the underlying diagnostic: a backend error can carry
	// sensitive details and cannot establish whether the mutation took effect.
	return &RecoveryOutcomeUnknown{Outcome: "unknown", Operation: operation, Reference: r}
}

// Native phase comes from the synchronous bridge, which sets it immediately
// before the sole add/delete call. Status alone cannot prove a failed effect.
func recoveryNativeMutationError(op string, status int, attempted bool) error {
	if status == 0 {
		return nil
	}
	var err error = &StatusError{Op: op, Status: status}
	duplicate := op == "recovery create" && status == -25299
	if duplicate {
		err = recoveryRefuse("duplicate")
	}
	if !attempted || duplicate {
		return &RecoveryNotAppliedError{Err: err}
	}
	return err
}
