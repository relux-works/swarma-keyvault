//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// InitializationFiles selects only independently retained PUBLIC initialization
// inputs. It cannot express a signing request, output or private-material source.
type InitializationFiles struct {
	Group, Account             string
	ProfilePath, ProfileSHA256 string
	AccountPinPath             string
}

// PreparedInitialization owns validated public snapshots, not consent or a
// journal reservation. The qualified helper still owns review, fresh presence,
// actual private-account correspondence and create-only journal initialization.
type PreparedInitialization struct {
	profile, pin []byte
	config       NativeSelection
}

func PrepareInitializationFiles(files InitializationFiles) (PreparedInitialization, error) {
	var empty PreparedInitialization
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
	if _, err := initializationAccount(config, pin); err != nil {
		return empty, err
	}
	return PreparedInitialization{profile: profile, pin: pin, config: config}, nil
}

func (p PreparedInitialization) ProfileBytes() []byte { return bytes.Clone(p.profile) }
func (p PreparedInitialization) PinBytes() []byte     { return bytes.Clone(p.pin) }
func (p PreparedInitialization) NativeSelection() NativeSelection {
	c := p.config
	c.Selection.RevealValuesPin = bytes.Clone(c.Selection.RevealValuesPin)
	return c
}
