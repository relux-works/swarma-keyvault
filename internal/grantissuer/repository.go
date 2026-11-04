// Package grantissuer binds complete typed grant preparation to a purpose- and
// generation-specific owner-presence key. It implements no enrollment or effects.
package grantissuer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grants"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const OwnerMXID = "@alexis:gr.relux.works"
const Organization = "relux-works"
const Repository = "matrix-grants-poc-261031"

var ErrOwnerKeyMismatch = errors.New("owner presence key does not match the typed grant issuer")

// Prepared binds one exact payload and independently expected public pin. The
// fixed first-slice scope does not expose a generic digest-signing interface.
type Prepared struct {
	plan   *grants.RepositoryIssuance
	public []byte
	local  bool
}

func Prepare(payload, expectedPublicDER []byte) (*Prepared, error) {
	plan, err := grants.NewRepositoryIssuance(payload, OwnerMXID, expectedPublicDER, Organization, Repository)
	if err != nil {
		return nil, err
	}
	return &Prepared{plan: plan, public: bytes.Clone(expectedPublicDER)}, nil
}

// PrepareLocal binds a distinct local certificate to independently expected
// owner and requester public keys before constructing any private operation.
func PrepareLocal(payload, expectedOwnerDER, expectedRequesterDER []byte) (*Prepared, error) {
	plan, err := grants.NewLocalRepositoryIssuance(payload, OwnerMXID, expectedOwnerDER, expectedRequesterDER, Organization, Repository)
	if err != nil {
		return nil, err
	}
	return &Prepared{plan: plan, public: bytes.Clone(expectedOwnerDER), local: true}, nil
}

// Prompt names only the digest this exact typed preparation will sign. The
// helper's presence dialog still names its selected key separately.
func (p *Prepared) Prompt(digest []byte) string {
	want := p.plan.Digest()
	if !bytes.Equal(digest, want[:]) {
		return ""
	}
	prefix := "grant repository.create "
	if p.local {
		prefix = "grant local repository.create "
	}
	return prefix + Organization + "/" + Repository + " sha256 " + hex.EncodeToString(want[:6])
}

// Sign displays the full exact review only after normal vault policy and the
// actual resolved owner-key gate pass, immediately before the private call.
// A failed or short review write performs no private operation. This method
// neither creates a key nor stores/activates a signed certificate.
func (p *Prepared) Sign(manager *keyvault.Manager, review io.Writer) ([]byte, error) {
	if p == nil || p.plan == nil || manager == nil || review == nil {
		return nil, errors.New("typed issuer input unavailable")
	}
	digest := p.plan.Digest()
	address := keyvault.Address{Kind: keyvault.KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1}
	result, err := manager.SignIfKey(address, digest[:], func(key keyvault.ResolvedSigningKey) error {
		if key.Address != address || key.Store != keyvault.StoreEnclave || !key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, p.public) {
			return ErrOwnerKeyMismatch
		}
		text := p.plan.Review()
		if n, err := io.WriteString(review, text); err != nil {
			return err
		} else if n != len(text) {
			return io.ErrShortWrite
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
