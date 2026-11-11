// Package ownerkey defines the exact native owner-key address and prompt
// policy without depending on any grant or principal format.
package ownerkey

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

const GrantPurpose = "grants-owner-v1"

var ErrAddress = errors.New("explicit exact grants-owner-v1 key address required")

// PublicPin represents the configured key address and exact public DER hash.
// An independent verifier obtains the same line from its trusted enrollment.
func PublicPin(a signerclient.Address, publicDER []byte) string {
	return fmt.Sprintf("%s/%s/%s@%d sha256:%x\n", a.Kind, a.Service, a.Purpose, a.Version, sha256.Sum256(publicDER))
}

// ValidateAddress is the native key boundary, independent of the owner's
// Matrix principal. Exact public-pin, store, extraction and presence checks
// remain mandatory where the resolved key is used.
func ValidateAddress(a signerclient.Address) error {
	if a.Kind != signerclient.KindKey || a.Purpose != GrantPurpose || a.Version < 1 || a.Version > 2147483647 || signerclient.ValidateName("service", signerclient.CodeInvalidService, a.Service) != nil {
		return ErrAddress
	}
	return nil
}

func Display(a signerclient.Address) (string, error) {
	if ValidateAddress(a) != nil {
		return "", ErrAddress
	}
	return fmt.Sprintf("%s/%s v%d", a.Service, a.Purpose, a.Version), nil
}

// CheckPresenceReason rejects a complete native reason that would require the
// helper to strip controls or truncate any of the description or key address.
func CheckPresenceReason(a signerclient.Address, description string) error {
	display, err := Display(a)
	if err != nil {
		return err
	}
	reason := "mac-keyvault: " + description + " with " + display
	if description == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 200 {
		return ErrPresenceReason
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ErrPresenceReason
		}
	}
	return nil
}

var ErrPresenceReason = errors.New("complete presence reason exceeds the native display policy")
