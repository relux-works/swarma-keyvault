//go:build !darwin && !linux

package rootqualification

import (
	"context"
	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
)

type ObservedCandidate struct{}

func ObserveCandidate(context.Context, string, string) (*ObservedCandidate, error) {
	return nil, ErrReceipt
}
func (*ObservedCandidate) Candidate() (Candidate, error) { return Candidate{}, ErrReceipt }
func (*ObservedCandidate) Child(codesignpolicy.Role) (string, string, error) {
	return "", "", ErrReceipt
}
func (*ObservedCandidate) Close() error { return nil }
