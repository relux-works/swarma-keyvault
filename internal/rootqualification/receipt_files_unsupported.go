//go:build !darwin && !linux

package rootqualification

import "errors"

func ReserveCreation() (*CreationReservation, error) {
	return nil, errors.New("public qualification receipts require a supported Unix filesystem")
}

func LoadCreatedReceipt(string, Candidate) (*LoadedReceipt, error) {
	return nil, errors.New("public qualification receipts require a supported Unix filesystem")
}
