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
	mode                           Mode
	profile, pin, input            []byte
	config                         namecoinpsbt.NativeSelection
	attempt                        namecoinpsbt.PublicAttempt
	adoption                       string
	profileSHA256, operationSHA256 [32]byte
	hasOperationSHA256             bool
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
	profile := p.ProfileBytes()
	config := p.NativeSelection()
	return Prepared{mode: mode, profile: profile, pin: p.PinBytes(), config: config,
		profileSHA256: sha256.Sum256(profile)}
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
	p.operationSHA256, p.hasOperationSHA256 = h, true
	return p, nil
}

func PrepareInitializationFiles(a Args) (Prepared, error) {
	public, err := preparePublic(a, InitializeJournal)
	if err != nil {
		return Prepared{}, err
	}
	p := publicPrepared(InitializeJournal, public)
	p.adoption = a.AdoptionPlanSHA256
	if _, err := hex.Decode(p.operationSHA256[:], []byte(a.AdoptionPlanSHA256)); err != nil {
		return Prepared{}, namecoinwire.ErrInvalidRequest
	}
	p.hasOperationSHA256 = true
	return p, nil
}

// ReconcileInput owns the admitted query and public selection before the
// Mac-owned fixed-store lookup. No caller-selectable root or lookup callback
// exists here. The returned query is public correlation, not store membership.
type ReconcileInput struct {
	public         namecoinpsbt.PreparedInitialization
	query          namecoinwire.ReconcileQuery
	querySHA256    [32]byte
	hasQuerySHA256 bool
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
	return ReconcileInput{public: public, query: query, querySHA256: sha256.Sum256(raw), hasQuerySHA256: true}, nil
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
	p.operationSHA256, p.hasOperationSHA256 = r.querySHA256, true
	return p, nil
}
