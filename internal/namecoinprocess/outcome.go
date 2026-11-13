// Package namecoinprocess contains public process policy. It has no process,
// native-store, biometric or signing capability. Adapter observations are not
// themselves proof of native custody; only a qualified adapter may supply them.
package namecoinprocess

import (
	"bytes"
	"encoding/base64"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// MaxProcessResultBytes is the independent process consumer limit. It does not
// widen the request/PSBT limits or change the existing wire decoder's limit.
const MaxProcessResultBytes = 6291456

type RunnerMode uint8

const (
	RunnerSign RunnerMode = iota + 1
	RunnerReconcile
	RunnerInitialize
)

// RunnerContext is independently selected, already frozen public context from
// admission (or the original historical attempt for reconcile). Its matching
// public values grant no native authority. Initialization uses no candidate.
// One PublicAttempt supplies all candidate/review/selection bindings. It is
// public consistency evidence, not fresh signing or native/history authority.
// No current clock is invented to check a historical result.
type RunnerContext struct {
	Mode    RunnerMode
	Attempt namecoinpsbt.PublicAttempt
}

// Outcome releases bytes only when Done is true. An adapter emits Line exactly
// once in response to RunnerEmitOutcome, rather than on every observation.
// Accessors copy buffers so a consumer cannot change a retained verdict.
type Outcome struct {
	done, success                  bool
	line, result, finalTransaction []byte
	exit                           int
	txid                           string
}

func (o Outcome) Done() bool               { return o.done }
func (o Outcome) Success() bool            { return o.done && o.success }
func (o Outcome) Line() []byte             { return bytes.Clone(o.line) }
func (o Outcome) Result() []byte           { return bytes.Clone(o.result) }
func (o Outcome) FinalTransaction() []byte { return bytes.Clone(o.finalTransaction) }
func (o Outcome) TxID() string             { return o.txid }
func (o Outcome) Exit() (int, bool)        { return o.exit, o.done }

func refusedOutcome(f namecoinwire.Failure) Outcome {
	return Outcome{done: true, line: f.Bytes(), exit: f.Exit()}
}

// verifyProcessResult performs public verification, never native authentication.
// Candidate checks the original unsigned txid and signed maps; Assemble keeps
// that stripped transaction unchanged and supplies the finalized witness bytes.
// This deliberately reuses the existing signature/transaction implementation.
func verifyProcessResult(c RunnerContext, line, raw []byte) (Outcome, error) {
	candidate, review, selection := c.Attempt.Candidate(), c.Attempt.ReviewDigest(), c.Attempt.Selection()
	unknown := namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true)
	if len(raw) == 0 || len(raw) > MaxProcessResultBytes || namecoinwire.VerifyAcknowledgement(line, raw) != nil {
		return Outcome{}, unknown
	}
	if _, err := candidate.VerifyResult(raw, review); err != nil {
		return Outcome{}, unknown
	}
	decoded, err := namecoinwire.DecodeResult(raw)
	if err != nil {
		return Outcome{}, unknown
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(decoded.SignedPSBT)
	if err != nil {
		return Outcome{}, unknown
	}
	signatures, err := candidate.VerifySignedPSBT(signed)
	if err != nil || candidate.CheckFinalFeeRate(signatures, selection) != nil {
		return Outcome{}, unknown
	}
	_, final, err := candidate.Assemble(signatures)
	if err != nil {
		return Outcome{}, unknown
	}
	return Outcome{done: true, success: true, line: bytes.Clone(line), result: bytes.Clone(raw),
		finalTransaction: final, txid: candidate.View().UnsignedTxID}, nil
}

func validRunnerContext(c RunnerContext, deadline time.Duration) bool {
	if deadline <= 0 || deadline > time.Hour {
		return false
	}
	if c.Mode == RunnerInitialize {
		return len(c.Attempt.Descriptor()) == 0 && len(c.Attempt.Candidate().SignatureHashes()) == 0
	}
	if c.Mode != RunnerSign && c.Mode != RunnerReconcile {
		return false
	}
	// Actual file/profile admission belongs to preparation and the native side;
	// reject empty public state here without pretending to repeat that admission.
	_, err := namecoinpsbt.DecodeAttempt(c.Attempt.Descriptor())
	return err == nil
}
