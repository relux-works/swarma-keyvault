package namecoinpsbt

import (
	"encoding/hex"
	"math/bits"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Selection comes from independently selected local configuration and public
// setup/value receipts, never from request/manifest display or policy fields.
// It is public data, not a biometric approval or authenticated journal state.
type Selection struct {
	Network, Genesis, Group, Account, AccountPinSHA256 string
	Policy                                             namecoinwire.Policy
	RevealValuesPin                                    []byte
}

// Admit compares the public candidate with a separate selection and current
// clock. The private engine supplies its actual clock and repeats expiry checks
// immediately before dispatch. Protected predecessor/replay checks are separate.
func (c Candidate) Admit(selected Selection, now time.Time) error {
	if len(c.digests) == 0 {
		return failure(namecoinwire.InvalidRequest)
	}
	r, p := c.snapshot.Request(), c.snapshot.Plan()
	if selected.Network != p.Network || selected.Genesis != p.Genesis || selected.Group != p.Group || selected.Account != p.Account || selected.AccountPinSHA256 != p.AccountPinSHA256 || selected.Policy != p.Policy {
		return failure(namecoinwire.PolicyRefused)
	}
	policy := selected.Policy
	if now.Unix() < 0 {
		return failure(namecoinwire.RequestExpired)
	}
	seconds := uint64(now.Unix())
	if seconds >= r.ExpiresAt || r.ExpiresAt-seconds > 600 {
		return failure(namecoinwire.RequestExpired)
	}
	if policy.CreatedAt > seconds || policy.ReleaseNotAfter <= seconds || policy.ReleaseNotAfter <= policy.CreatedAt || policy.ReleaseNotAfter-policy.CreatedAt > 86400 || policy.FinalConfirmations < 1 {
		return failure(namecoinwire.PolicyRefused)
	}
	cap, ok := namecoinwire.Decimal(policy.PerTxFeeCap)
	total, totalOK := namecoinwire.Decimal(policy.TotalFeeCap)
	minRate, minOK := namecoinwire.Decimal(policy.MinFeeRate)
	maxRate, maxOK := namecoinwire.Decimal(policy.MaxFeeRate)
	dust, dustOK := namecoinwire.Decimal(policy.DustRelayFee)
	if !ok || !totalOK || !minOK || !maxOK || !dustOK || cap > 100000 || total > 400000 || total < cap || minRate == 0 || maxRate < minRate || dust == 0 {
		return failure(namecoinwire.PolicyRefused)
	}
	var phaseFees uint64
	for _, tx := range p.Transactions {
		fee, ok := namecoinwire.Decimal(tx.Fee)
		if !ok || fee > cap || fee > total-phaseFees {
			return failure(namecoinwire.FeeRefused)
		}
		phaseFees += fee
	}
	if c.view.Fee > cap {
		return failure(namecoinwire.FeeRefused)
	}
	for _, out := range c.packet.tx.outputs {
		// Core's native witness dust size uses the complete serialized output
		// plus67 discounted spend bytes, including any full name prefix.
		size := uint64(len(serializeOutput(nil, out)) + 67)
		threshold, overflow := mulDiv(dust, size, 1000)
		if overflow {
			return failure(namecoinwire.PolicyRefused)
		}
		if threshold == 0 {
			threshold = 1
		}
		if out.amount < threshold {
			return failure(namecoinwire.FeeRefused)
		}
	}
	// Obvious fee-rate violations refuse before private use. Exact final size
	// is rechecked after public signature assembly; no guessed signature size
	// is treated as the actual finalized transaction's size.
	base := uint64(len(c.packet.tx.serialize(false)))
	inputs := uint64(len(c.packet.inputs))
	minVSize := (base*4 + 2 + 45*inputs + 3) / 4
	maxVSize := (base*4 + 2 + 108*inputs + 3) / 4
	if compareProducts(c.view.Fee, 1000, minRate, minVSize) < 0 || compareProducts(c.view.Fee, 1000, maxRate, maxVSize) > 0 {
		return failure(namecoinwire.FeeRefused)
	}
	if p.Kind == "reveal" {
		pin, err := namecoinwire.DecodeRevealPin(selected.RevealValuesPin)
		if err != nil || pin.ReservationPlanSHA256 != r.ReservationPlanSHA256 {
			return failure(namecoinwire.IntentMismatch)
		}
		for i, reg := range p.Registrations {
			trusted := pin.Registrations[i]
			if reg.NameHex != trusted.NameHex || reg.ValueHex != trusted.ValueHex || reg.ValueSHA256 != trusted.ValueSHA256 {
				return failure(namecoinwire.IntentMismatch)
			}
		}
	}
	return nil
}

// CheckFinalFeeRate requires the actual independently verified signatures.
// A private engine calling this after dispatch reports any failure UNKNOWN,
// rather than claim no private effect merely because no result was exported.
func (c Candidate) CheckFinalFeeRate(signatures [][]byte, selected Selection) error {
	_, final, err := c.Assemble(signatures)
	if err != nil {
		return err
	}
	minRate, minOK := namecoinwire.Decimal(selected.Policy.MinFeeRate)
	maxRate, maxOK := namecoinwire.Decimal(selected.Policy.MaxFeeRate)
	if !minOK || !maxOK || selected.Policy != c.snapshot.Plan().Policy {
		return failure(namecoinwire.PolicyRefused)
	}
	base := uint64(len(c.packet.tx.serialize(false)))
	vsize := (3*base + uint64(len(final)) + 3) / 4
	if compareProducts(c.view.Fee, 1000, minRate, vsize) < 0 || compareProducts(c.view.Fee, 1000, maxRate, vsize) > 0 {
		return failure(namecoinwire.FeeRefused)
	}
	return nil
}
func compareProducts(a, b, c, d uint64) int {
	ah, al := bits.Mul64(a, b)
	ch, cl := bits.Mul64(c, d)
	if ah < ch || ah == ch && al < cl {
		return -1
	}
	if ah > ch || ah == ch && al > cl {
		return 1
	}
	return 0
}
func mulDiv(a, b, d uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	if d == 0 || hi >= d {
		return 0, true
	}
	q, _ := bits.Div64(hi, lo, d)
	return q, false
}

// AccountPublic returns only the independently selected compressed account
// point and chain code (already public in xpub), for same-process private key
// correspondence checks. It never contains an account scalar or child secret.
func (c Candidate) AccountPublic() (point [33]byte, chain [32]byte) {
	return c.account.point, c.account.chain
}
func (c Candidate) ReviewContext(selected Selection) (namecoinwire.ReviewContext, error) {
	var hash [32]byte
	if len(c.digests) == 0 || len(selected.AccountPinSHA256) != 64 {
		return namecoinwire.ReviewContext{}, failure(namecoinwire.PolicyRefused)
	}
	if _, err := hex.Decode(hash[:], []byte(selected.AccountPinSHA256)); err != nil {
		return namecoinwire.ReviewContext{}, failure(namecoinwire.PolicyRefused)
	}
	cap, ok := namecoinwire.Decimal(selected.Policy.PerTxFeeCap)
	if !ok {
		return namecoinwire.ReviewContext{}, failure(namecoinwire.PolicyRefused)
	}
	return namecoinwire.ReviewContext{Group: selected.Group, Account: selected.Account, Network: selected.Network, Genesis: selected.Genesis, AccountPinSHA256: hash, PolicyRevision: selected.Policy.Revision, PerTxFeeCap: cap}, nil
}
