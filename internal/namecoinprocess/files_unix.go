//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Prepared owns public once-frozen inputs only. It neither opens a journal nor
// creates output, starts a child, supplies native custody or authorizes use.
type Prepared struct {
	mode                Mode
	profile, pin, input []byte
	config              namecoinpsbt.NativeSelection
	attempt             namecoinpsbt.PublicAttempt
	adoption            string
}

func (p Prepared) Mode() Mode                          { return p.mode }
func (p Prepared) ProfileBytes() []byte                { return bytes.Clone(p.profile) }
func (p Prepared) PinBytes() []byte                    { return bytes.Clone(p.pin) }
func (p Prepared) InputBytes() []byte                  { return bytes.Clone(p.input) }
func (p Prepared) Attempt() namecoinpsbt.PublicAttempt { return p.attempt }
func (p Prepared) AdoptionPlanSHA256() string          { return p.adoption }
func (p Prepared) NativeSelection() namecoinpsbt.NativeSelection {
	c := p.config
	c.Selection.RevealValuesPin = bytes.Clone(c.Selection.RevealValuesPin)
	return c
}

func preparePublic(a Args, mode Mode) (namecoinpsbt.PreparedInitialization, error) {
	if a.Mode != mode || a.validate() != nil {
		return namecoinpsbt.PreparedInitialization{}, namecoinwire.ErrInvalidRequest
	}
	return namecoinpsbt.PrepareInitializationFiles(namecoinpsbt.InitializationFiles{
		Group: a.Group, Account: a.Account, ProfilePath: a.ProfilePath, ProfileSHA256: a.ProfileSHA256, AccountPinPath: a.AccountPinPath,
	})
}

func publicPrepared(mode Mode, p namecoinpsbt.PreparedInitialization) Prepared {
	return Prepared{mode: mode, profile: p.ProfileBytes(), pin: p.PinBytes(), config: p.NativeSelection()}
}

func PrepareSigningFiles(a Args, now time.Time) (Prepared, error) {
	public, err := preparePublic(a, SignPSBT)
	if err != nil {
		return Prepared{}, err
	}
	// ReadInput checks size before allocation/read, not after an 8 MiB load.
	request, err := namecoinfiles.ReadInput(a.RequestPath, MaxProcessRequestBytes)
	if err != nil {
		return Prepared{}, namecoinwire.ErrInvalidRequest
	}
	h := sha256.Sum256(request)
	if hex.EncodeToString(h[:]) != a.RequestSHA256 {
		return Prepared{}, namecoinwire.ErrInvalidRequest
	}
	if err := CheckRequestLimits(request); err != nil {
		return Prepared{}, err
	}
	snapshot, err := namecoinwire.Decode(request)
	if err != nil {
		return Prepared{}, err
	}
	var reveal []byte
	if snapshot.Request().Slot == "A" || snapshot.Request().Slot == "B" {
		if a.RevealPinPath != "" {
			return Prepared{}, namecoinwire.NewFailure(namecoinwire.IntentMismatch, false)
		}
	} else {
		reveal, err = namecoinfiles.ReadInput(a.RevealPinPath, 1<<20)
		if err != nil {
			return Prepared{}, namecoinwire.NewFailure(namecoinwire.IntentMismatch, false)
		}
	}
	signing, err := namecoinpsbt.PrepareSigningInput(public, request, reveal, now)
	if err != nil {
		return Prepared{}, err
	}
	p := publicPrepared(SignPSBT, public)
	p.input, p.attempt = signing.RequestBytes(), signing.Attempt()
	return p, nil
}

func PrepareInitializationFiles(a Args) (Prepared, error) {
	public, err := preparePublic(a, InitializeJournal)
	if err != nil {
		return Prepared{}, err
	}
	p := publicPrepared(InitializeJournal, public)
	p.adoption = a.AdoptionPlanSHA256
	return p, nil
}

// ReconcileInput owns the admitted query and public selection before the
// Mac-owned fixed-store lookup. No caller-selectable root or lookup callback
// exists here. The returned query is public correlation, not store membership.
type ReconcileInput struct {
	public namecoinpsbt.PreparedInitialization
	query  namecoinwire.ReconcileQuery
}

func PrepareReconcileFiles(a Args) (ReconcileInput, error) {
	public, err := preparePublic(a, Reconcile)
	if err != nil {
		return ReconcileInput{}, err
	}
	raw, err := namecoinfiles.ReadInput(a.QueryPath, 4096)
	if err != nil {
		return ReconcileInput{}, namecoinwire.ErrInvalidRequest
	}
	query, err := namecoinwire.DecodeReconcile(raw)
	if err != nil {
		return ReconcileInput{}, err
	}
	return ReconcileInput{public: public, query: query}, nil
}

func (r ReconcileInput) Query() namecoinwire.ReconcileQuery { return r.query }

// WithDescriptor accepts only the exact supplied historical bytes. Missing or
// corrupt historical state is UNKNOWN; explicit different IDs intent_mismatch.
// Native lookup and final native membership/completion remain separate checks.
func (r ReconcileInput) WithDescriptor(descriptor []byte) (Prepared, error) {
	a, err := namecoinpsbt.PrepareReconcileInput(r.public, r.query, descriptor)
	if err != nil {
		return Prepared{}, err
	}
	p := publicPrepared(Reconcile, r.public)
	p.input, p.attempt = a.Descriptor(), a
	return p, nil
}
