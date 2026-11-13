//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// SigningFiles contains explicit public selectors from the trusted launcher.
// Paths and the independently retained profile hash never come from a request.
// This preparation step has no output descriptor, protected-state or helper
// capability. Retained-record/code admission and native consent remain required.
type SigningFiles struct {
	Group, Account                             string
	ProfilePath, ProfileSHA256                 string
	AccountPinPath, RevealPinPath, RequestPath string
}

// PreparedSigning owns once-read public snapshots and the fully checked fresh
// candidate. Its existence is not custody provenance or permission to dispatch.
type PreparedSigning struct {
	profile, pin, request []byte
	config                NativeSelection
	attempt               PublicAttempt
}

func PrepareSigningFiles(files SigningFiles, now time.Time) (PreparedSigning, error) {
	var empty PreparedSigning
	profile, err := namecoinfiles.ReadInput(files.ProfilePath, 4<<20)
	if err != nil {
		return empty, failure(namecoinwire.PolicyRefused)
	}
	config, err := SelectNativeProfile(profile, files.ProfileSHA256)
	if err != nil {
		return empty, err
	}
	if files.Group != config.Selection.Group || files.Account != config.Selection.Account {
		return empty, failure(namecoinwire.AccountMismatch)
	}
	pin, err := namecoinfiles.ReadInput(files.AccountPinPath, 32768)
	if err != nil {
		return empty, failure(namecoinwire.AccountMismatch)
	}
	hash := sha256.Sum256(pin)
	if hex.EncodeToString(hash[:]) != config.Selection.AccountPinSHA256 {
		return empty, failure(namecoinwire.AccountMismatch)
	}
	request, err := namecoinfiles.ReadInput(files.RequestPath, namecoinwire.MaxRequestBytes)
	if err != nil {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	snapshot, err := namecoinwire.Decode(request)
	if err != nil {
		return empty, err
	}
	switch snapshot.Request().Slot {
	case "A", "B":
		if files.RevealPinPath != "" || len(config.Selection.RevealValuesPin) != 0 {
			return empty, failure(namecoinwire.IntentMismatch)
		}
	case "C", "D":
		reveal, err := namecoinfiles.ReadInput(files.RevealPinPath, 1<<20)
		if err != nil || len(config.Selection.RevealValuesPin) == 0 || !bytes.Equal(reveal, config.Selection.RevealValuesPin) {
			return empty, failure(namecoinwire.IntentMismatch)
		}
	default:
		return empty, failure(namecoinwire.InvalidRequest)
	}
	attempt, err := PrepareAttempt(request, pin, config.Selection, now)
	if err != nil {
		return empty, err
	}
	if err := sessionBinding(attempt, config.Sidecar); err != nil {
		return empty, err
	}
	return PreparedSigning{profile: profile, pin: pin, request: request, config: config, attempt: attempt}, nil
}

func (p PreparedSigning) ProfileBytes() []byte   { return bytes.Clone(p.profile) }
func (p PreparedSigning) PinBytes() []byte       { return bytes.Clone(p.pin) }
func (p PreparedSigning) RequestBytes() []byte   { return bytes.Clone(p.request) }
func (p PreparedSigning) Attempt() PublicAttempt { return p.attempt }
func (p PreparedSigning) NativeSelection() NativeSelection {
	c := p.config
	c.Selection.RevealValuesPin = bytes.Clone(c.Selection.RevealValuesPin)
	return c
}

// PrepareSigningInput completes public preparation from an already admitted
// profile/pin snapshot and owned request/reveal bytes. It does no file I/O and
// has no helper, output or protected-state capability. A nil reveal means no
// separate reveal input; even an empty non-nil reveal is supplied for A/B.
// Process callers enforce their narrower transport bounds before this library
// seam. Existing library request/PSBT limits are unchanged.
func PrepareSigningInput(public PreparedInitialization, request, reveal []byte, now time.Time) (PreparedSigning, error) {
	var empty PreparedSigning
	if len(public.profile) == 0 || len(public.pin) == 0 {
		return empty, failure(namecoinwire.PolicyRefused)
	}
	request = bytes.Clone(request)
	reveal = bytes.Clone(reveal)
	snapshot, err := namecoinwire.Decode(request)
	if err != nil {
		return empty, err
	}
	config := public.NativeSelection()
	switch snapshot.Request().Slot {
	case "A", "B":
		if reveal != nil || len(config.Selection.RevealValuesPin) != 0 {
			return empty, failure(namecoinwire.IntentMismatch)
		}
	case "C", "D":
		if len(config.Selection.RevealValuesPin) == 0 || !bytes.Equal(reveal, config.Selection.RevealValuesPin) {
			return empty, failure(namecoinwire.IntentMismatch)
		}
	default:
		return empty, failure(namecoinwire.InvalidRequest)
	}
	attempt, err := PrepareAttempt(request, public.pin, config.Selection, now)
	if err != nil {
		return empty, err
	}
	if err := sessionBinding(attempt, config.Sidecar); err != nil {
		return empty, err
	}
	return PreparedSigning{profile: bytes.Clone(public.profile), pin: bytes.Clone(public.pin), request: request, config: config, attempt: attempt}, nil
}

// PrepareReconcileInput checks only a supplied historical descriptor against
// the closed query and separately frozen public configuration. The native vault
// retrieves it from its fixed store; this seam opens no store and applies no
// fresh clock. It supplies neither genuine membership nor native completion.
func PrepareReconcileInput(public PreparedInitialization, query namecoinwire.ReconcileQuery, descriptor []byte) (PublicAttempt, error) {
	var empty PublicAttempt
	// Reapply the closed query grammar even for direct library callers.
	rawQuery, err := json.Marshal(query)
	if err != nil {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	if _, err = namecoinwire.DecodeReconcile(rawQuery); err != nil {
		return empty, err
	}
	if len(public.profile) == 0 || len(public.pin) == 0 {
		return empty, failure(namecoinwire.PolicyRefused)
	}
	a, err := DecodeAttempt(descriptor)
	if err != nil {
		return empty, failure(namecoinwire.OutcomeUnknown)
	}
	r := a.candidate.snapshot.Request()
	if query.RequestID != r.RequestID || query.PlanSHA256 != r.PlanSHA256 || query.Slot != r.Slot {
		return empty, failure(namecoinwire.IntentMismatch)
	}
	selected, historical := public.config.Selection, a.selected
	if selected.Group != historical.Group || selected.Account != historical.Account || selected.AccountPinSHA256 != historical.AccountPinSHA256 {
		return empty, failure(namecoinwire.AccountMismatch)
	}
	if selected.Network != historical.Network || selected.Genesis != historical.Genesis || selected.Policy != historical.Policy {
		return empty, failure(namecoinwire.PolicyRefused)
	}
	if !bytes.Equal(selected.RevealValuesPin, historical.RevealValuesPin) {
		return empty, failure(namecoinwire.IntentMismatch)
	}
	if err := sessionBinding(a, public.config.Sidecar); err != nil {
		return empty, err
	}
	return a, nil
}
