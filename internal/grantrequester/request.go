// Package grantrequester binds the local request attestation to its separately
// provisioned non-presence Enclave key. It enrolls no Matrix identity or grant.
package grantrequester

import (
	"bytes"
	"errors"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

var ErrRequesterKeyMismatch = errors.New("requester key does not match the local request signer")

type Prepared struct {
	plan   *grants.LocalRequestSigning
	public []byte
}

func Prepare(payload, public []byte) (*Prepared, error) {
	plan, err := grants.PrepareLocalRequest(payload, public)
	if err != nil {
		return nil, err
	}
	return &Prepared{plan: plan, public: bytes.Clone(public)}, nil
}

// Sign makes one attempt only after checking the actual selected generation,
// purpose, store, absence of presence, extraction policy and exact public pin.
func (p *Prepared) Sign(manager *keyvault.Manager) ([]byte, error) {
	if p == nil || p.plan == nil || manager == nil {
		return nil, ErrRequesterKeyMismatch
	}
	address := keyvault.Address{Kind: keyvault.KindKey, Service: "swarma-grants", Purpose: "requester-local-v1", Version: 1}
	digest := p.plan.Digest()
	result, err := manager.SignIfKey(address, digest[:], func(key keyvault.ResolvedSigningKey) error {
		if key.Address != address || key.Store != keyvault.StoreEnclave || key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, p.public) {
			return ErrRequesterKeyMismatch
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	signature, err := result.Signature.Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		return nil, err
	}
	return p.plan.SignedEnvelope(signature)
}
