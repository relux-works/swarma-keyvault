package main

import (
	"errors"
	"flag"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
	"github.com/relux-works/swarma-keyvault/internal/owneridentity"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

const ownerAddressUsage = " --owner-key SERVICE/grants-owner-v1 --owner-key-version N"
const ownerIdentityUsage = " --owner-mxid MXID" + ownerAddressUsage

type ownerAddressFlags struct{ key, version onceString }

func addOwnerAddressFlags(f *flag.FlagSet) *ownerAddressFlags {
	o := &ownerAddressFlags{}
	f.Var(&o.key, "owner-key", "exact supported owner service/purpose")
	f.Var(&o.version, "owner-key-version", "one explicit owner key generation")
	return o
}

func (o *ownerAddressFlags) address() (signerclient.Address, error) {
	if o == nil || !o.key.set || !o.version.set {
		return signerclient.Address{}, owneridentity.ErrConfig
	}
	service, purpose, ok := strings.Cut(o.key.value, "/")
	v, err := strconv.Atoi(o.version.value)
	if !ok || err != nil || strconv.Itoa(v) != o.version.value {
		return signerclient.Address{}, owneridentity.ErrConfig
	}
	a := signerclient.Address{Kind: signerclient.KindKey, Service: service, Purpose: purpose, Version: v}
	if err := ownerkey.ValidateAddress(a); err != nil {
		return signerclient.Address{}, err
	}
	return a, nil
}

type ownerFlags struct {
	principal onceString
	key       *ownerAddressFlags
}

func addOwnerFlags(f *flag.FlagSet) *ownerFlags {
	o := &ownerFlags{key: addOwnerAddressFlags(f)}
	f.Var(&o.principal, "owner-mxid", "independently configured full owner Matrix account")
	return o
}

func (o *ownerFlags) config() (owneridentity.Config, error) {
	if o == nil || !o.principal.set {
		return owneridentity.Config{}, owneridentity.ErrConfig
	}
	address, err := o.key.address()
	if err != nil {
		return owneridentity.Config{}, err
	}
	return owneridentity.New(o.principal.value, address.Service, address.Purpose, address.Version)
}

const muOwnerPreparationUsage = ownerAddressUsage + " --owner-spki-der FILE"

type muOwnerPreparationFlags struct {
	addressFlags *ownerAddressFlags
	publicDER    onceString
}

func addMUOwnerPreparationFlags(f *flag.FlagSet) *muOwnerPreparationFlags {
	o := &muOwnerPreparationFlags{addressFlags: addOwnerAddressFlags(f)}
	f.Var(&o.publicDER, "owner-spki-der", "independently expected owner root public key, SPKI DER")
	return o
}

func (o *muOwnerPreparationFlags) validate() error {
	if _, err := o.addressFlags.address(); err != nil {
		return err
	}
	if !o.publicDER.set || o.publicDER.value == "" || o.publicDER.value == "-" {
		return owneridentity.ErrConfig
	}
	return nil
}

func (o *muOwnerPreparationFlags) pin(issuer string) (string, error) {
	address, err := o.addressFlags.address()
	if err != nil {
		return "", err
	}
	der, err := readInput(o.publicDER.value, nil, muSPKIMax)
	if err != nil {
		return "", errors.New("cannot read bounded owner public key")
	}
	root, err := mugrant.KeyIDFromSPKI(der)
	if err != nil || root != issuer {
		return "", errors.New("specification refused: issuer is not the given owner root")
	}
	return ownerkey.PublicPin(address, der), nil
}
