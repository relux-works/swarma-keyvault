//go:build !darwin || !cgo

package keyvault

import (
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

func RootQualificationMarkerRead(codesignpolicy.Role, rootqualification.Request) (rootqualification.Result, error) {
	return rootqualification.Unqualified, errors.New("public marker qualification requires macOS with cgo")
}

func RootQualificationSnapshot(rootqualification.Request) (rootqualification.Projection, error) {
	return rootqualification.Projection{}, errors.New("public marker qualification requires macOS with cgo")
}

func RootQualificationCreate(*rootqualification.CreationReservation) (rootqualification.NativeCreation, error) {
	return rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused}, errors.New("public marker qualification requires macOS with cgo")
}

func RootQualificationCode(codesignpolicy.Role, int, string) error {
	return errors.New("public marker qualification requires macOS with cgo")
}

func RootQualificationDelete(*rootqualification.CleanupReservation) (rootqualification.CleanupOutcome, error) {
	return rootqualification.CleanupRefused, errors.New("public marker qualification requires macOS with cgo")
}
