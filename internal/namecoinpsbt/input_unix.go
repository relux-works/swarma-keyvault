//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
