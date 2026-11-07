package ownerdocument

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// Historical contract prototype, retained only as a synthetic test model.
// Production uses signNative and the same-process typed native protocol.
type completeReview interface {
	// ReviewAndConfirm must render the complete supplied buffer unchanged,
	// refuse unsupported layout/truncation/cancel, and return the exact bytes
	// the human explicitly confirmed. A digest/boolean alone cannot substitute.
	ReviewAndConfirm(context.Context, []byte) ([]byte, error)
}

func (p *Prepared) signWithReview(ctx context.Context, manager *keyvault.Manager, review completeReview, source func() ([]byte, error)) ([]byte, error) {
	if p == nil || len(p.document) == 0 || ctx == nil || manager == nil || review == nil || source == nil {
		return nil, ErrInput
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := source()
		if err != nil {
			return err
		}
		if err := p.CheckSource(current); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := check(); err != nil {
		return nil, err
	}
	// Give the manager its own digest buffer: callbacks cannot mutate the plan.
	digest := p.digest
	admitted := false
	result, err := manager.SignIfKey(ownerAddress, digest[:], func(key keyvault.ResolvedSigningKey) error {
		if key.Address != ownerAddress || key.Store != keyvault.StoreEnclave || !key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, p.public) {
			return ErrPublic
		}
		if err := check(); err != nil {
			return err
		}
		confirmed, err := review.ReviewAndConfirm(ctx, bytes.Clone(p.document))
		if err != nil {
			return err
		}
		if !bytes.Equal(confirmed, p.document) {
			return ErrConfirmation
		}
		if err := check(); err != nil {
			return err
		}
		admitted = true
		return nil
	})
	if err != nil {
		if admitted {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		return nil, err
	}
	// A change/cancel after dispatch releases no signature. The native attempt
	// might already have signed: callers must report uncertainty and never retry.
	if err := check(); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	der, err := result.Signature.Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := p.Verify(der); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return der, nil
}
