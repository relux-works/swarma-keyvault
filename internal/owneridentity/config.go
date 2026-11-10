// Package owneridentity binds an explicitly configured grant owner to one
// exact supported vault key generation. It supplies no default or enrollment.
package owneridentity

import (
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

var ErrConfig = errors.New("explicit valid owner principal and exact supported owner key required")

type Config struct {
	Principal string
	Address   signerclient.Address
}

// New accepts only the existing grant-owner purpose. A new root policy needs
// its own qualification; changing the service or generation grants no policy.
func New(principal, service, purpose string, generation int) (Config, error) {
	c := Config{Principal: principal, Address: signerclient.Address{Kind: signerclient.KindKey, Service: service, Purpose: purpose, Version: generation}}
	if c.Validate() != nil {
		return Config{}, ErrConfig
	}
	return c, nil
}

func (c Config) Validate() error {
	if grants.ValidateOwnerPrincipal(c.Principal) != nil || ownerkey.ValidateAddress(c.Address) != nil {
		return ErrConfig
	}
	return nil
}
