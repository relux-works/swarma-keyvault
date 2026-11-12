// Package namecoinwire implements the closed public Namecoin signing formats.
// Parsing and formatting do not establish account ownership, consent, protected
// journal provenance, signature production or permission to release a transaction.
package namecoinwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Code string

const (
	InvalidRequest      Code = "invalid_request"
	UnsupportedPSBT     Code = "unsupported_psbt"
	UnsupportedScript   Code = "unsupported_script"
	DisplayRefused      Code = "display_refused"
	AccountMismatch     Code = "account_mismatch"
	PathRefused         Code = "path_refused"
	PrevoutMismatch     Code = "prevout_mismatch"
	IntentMismatch      Code = "intent_mismatch"
	SighashRefused      Code = "sighash_refused"
	FeeRefused          Code = "fee_refused"
	RequestExpired      Code = "request_expired"
	ReplayRefused       Code = "replay_refused"
	AccountBusy         Code = "account_busy"
	AuthRefused         Code = "auth_refused"
	PresenceUnavailable Code = "presence_unavailable"
	AdoptionRequired    Code = "adoption_required"
	HelperNotAdmitted   Code = "helper_not_admitted"
	PolicyRefused       Code = "policy_refused"
	OutcomeUnknown      Code = "outcome_unknown"
	JournalUnavailable  Code = "journal_unavailable"
	OutputUnavailable   Code = "output_unavailable"
)

type Failure struct{ code Code }

var (
	ErrInvalidRequest = Failure{InvalidRequest}
	ErrIntentMismatch = Failure{IntentMismatch}
)

// NewFailure takes only a closed code. After possible private effect no
// underlying error, even a normally presign refusal, can report REFUSED.
func NewFailure(code Code, effectPossible bool) Failure {
	if effectPossible || !knownCode(code) {
		code = OutcomeUnknown
	}
	return Failure{code}
}

func knownCode(code Code) bool {
	switch code {
	case InvalidRequest, UnsupportedPSBT, UnsupportedScript, DisplayRefused,
		AccountMismatch, PathRefused, PrevoutMismatch, IntentMismatch,
		SighashRefused, FeeRefused, RequestExpired, ReplayRefused, AccountBusy,
		AuthRefused, PresenceUnavailable, AdoptionRequired, HelperNotAdmitted,
		PolicyRefused, OutcomeUnknown, JournalUnavailable, OutputUnavailable:
		return true
	}
	return false
}

func (f Failure) Code() Code {
	if !knownCode(f.code) {
		return OutcomeUnknown
	}
	return f.code
}
func (f Failure) Error() string { return "Namecoin signing " + string(f.Code()) + "." }
func (f Failure) Status() string {
	if f.Code() == OutcomeUnknown {
		return "UNKNOWN"
	}
	return "REFUSED"
}
func (f Failure) Exit() int {
	switch f.Code() {
	case InvalidRequest, UnsupportedPSBT, UnsupportedScript:
		return 2
	case AccountBusy, PresenceUnavailable, OutcomeUnknown, JournalUnavailable, OutputUnavailable:
		return 1
	default:
		return 3
	}
}

// Bytes is the exact ordered machine error line, with one final LF.
func (f Failure) Bytes() []byte {
	o := struct {
		Schema  string `json:"schema"`
		Code    Code   `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}{"keyvault-namecoin-psbt-error/2", f.Code(), f.Status(), f.Error()}
	raw, _ := json.Marshal(o)
	return append(raw, '\n')
}

// Acknowledgement formats an already authenticated complete SIGNED result.
// This formatter supplies no evidence that its caller actually obtained one.
func Acknowledgement(resultSHA256 [32]byte) []byte {
	o := struct {
		Schema string `json:"schema"`
		Status string `json:"status"`
		Hash   string `json:"result_sha256"`
	}{"keyvault-namecoin-psbt-ack/2", "SIGNED", hex.EncodeToString(resultSHA256[:])}
	raw, _ := json.Marshal(o)
	return append(raw, '\n')
}

func DecodeAcknowledgement(raw []byte) ([32]byte, error) {
	var o struct {
		Schema string `json:"schema"`
		Status string `json:"status"`
		Hash   string `json:"result_sha256"`
	}
	var hash [32]byte
	if decodeClosed(raw, &o, 256) != nil || !hexString(o.Hash, 32, 32) {
		return hash, ErrInvalidRequest
	}
	_, _ = hex.Decode(hash[:], []byte(o.Hash))
	if !bytes.Equal(raw, Acknowledgement(hash)) {
		return [32]byte{}, ErrInvalidRequest
	}
	return hash, nil
}

// VerifyAcknowledgement checks byte correlation only. The caller separately
// verifies signatures and the admitted endpoint/protected journal provenance.
func VerifyAcknowledgement(raw, exactResult []byte) error {
	hash, err := DecodeAcknowledgement(raw)
	if err != nil || len(exactResult) == 0 || hash != sha256.Sum256(exactResult) {
		return ErrInvalidRequest
	}
	return nil
}

func DecodeFailure(raw []byte) (Failure, error) {
	var o struct {
		Schema  string `json:"schema"`
		Code    Code   `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if decodeClosed(raw, &o, 512) != nil || !knownCode(o.Code) {
		return Failure{}, ErrInvalidRequest
	}
	f := NewFailure(o.Code, false)
	if !bytes.Equal(raw, f.Bytes()) {
		return Failure{}, ErrInvalidRequest
	}
	return f, nil
}
