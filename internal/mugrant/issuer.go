package mugrant

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

// CaveatsLang is the caveat language that carries the signed use policy
// (contract r3 X5). It is a proposed ENV v-next value until the envelope lane
// publishes it; v0 verifiers refuse it, which is the intended fail-closed state.
const CaveatsLang = "caveats/v2"

// Use policies (contract r3 section 3).
const (
	UseOnce        = "once"
	UseUntilExpiry = "until_expiry"
)

// ReasonLimit is the Touch ID reason bound in Unicode scalars (decision 154,
// Meta Q-M2): refuse when longer, never truncate.
const ReasonLimit = 200

var (
	ErrGrantSpec      = errors.New("mugrant-grant-spec-invalid")
	ErrGrantInterval  = errors.New("mugrant-grant-interval-invalid")
	ErrReasonOverflow = errors.New("mugrant-reason-not-displayable")
)

// Action is one entry of the closed vocabulary v2 (contract r3 section 6).
type Action struct {
	Name, TargetKind, Short, Long string
}

// vocabularyV2 is a positive allowlist; anything absent is refused.
var vocabularyV2 = []Action{
	{"work.assign", "product", "задачи", "tasks"},
	{"work.require", "product", "требования", "requirements"},
	{"work.contract", "product", "контракты", "contracts"},
	{"work.prioritize", "product", "приоритеты", "priorities"},
	{"work.land-order", "product", "посадки", "landing order"},
	{"work.accept", "product", "приёмка", "acceptance and return of work"},
	{"account.manage", "account-scope", "учётки", "create, rename, retire agent accounts"},
	{"room.membership", "room-scope", "комнаты", "invite to and remove from rooms"},
}

func lookupAction(name string) (Action, int, bool) {
	for i, a := range vocabularyV2 {
		if a.Name == name {
			return a, i, true
		}
	}
	return Action{}, -1, false
}

// Target is one typed grant target.
type Target struct{ Kind, ID string }

// Entry pairs one action with the target it applies to.
type Entry struct {
	Action string
	Target Target
}

// GrantSpec is what the owner chooses at signing time.
type GrantSpec struct {
	Issuer, Subject string // p256 key ids
	SubjectMXID     string // expected grantee; must equal the attested MXID
	// SubjectAttestation is the owner-root Mac agent attestation of Subject;
	// the grantee MXID shown and put into the reason is taken from it.
	SubjectAttestation []byte
	// PublisherAttestation is the owner-root grant revocation publisher
	// attestation; its key is shown in the rendering (r5 constraint 6).
	PublisherAttestation []byte
	Audience             string
	Entries              []Entry
	NotBefore, Expires   time.Time
	Use                  string
	Nonce                []byte // 16 CSPRNG bytes in production; fixed only in tests
}

// Grant is a prepared, unsigned grant/1 with its signing plan.
type Grant struct {
	spec             GrantSpec
	plan             *Plan
	agent, publisher *AttestedKey
}

func wireTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func printableToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validMXID(s string) bool {
	local, server, ok := strings.Cut(strings.TrimPrefix(s, "@"), ":")
	return strings.HasPrefix(s, "@") && ok && local != "" && server != "" && printableToken(s, 255)
}

func validInterval(nb, ex time.Time) bool {
	if nb.Location() != time.UTC || ex.Location() != time.UTC || nb.Nanosecond() != 0 || ex.Nanosecond() != 0 {
		return false
	}
	if nb.Year() < 1970 || ex.Year() > 9999 || !ex.After(nb) {
		return false
	}
	// Hard cap 1 year, chosen per grant by the owner (contract r3 X4).
	return !ex.After(nb.AddDate(1, 0, 0))
}

// BuildGrant validates the spec against the closed vocabulary and the interval
// and policy rules, builds the canonical grant/1 body with the platform codec
// and prepares its signing plan. Nothing is signed.
func BuildGrant(spec GrantSpec) (*Grant, error) {
	if spec.Issuer == spec.Subject || record.ValidateKey(spec.Issuer) != nil || record.ValidateKey(spec.Subject) != nil {
		return nil, ErrGrantSpec
	}
	if !validMXID(spec.SubjectMXID) || !printableToken(spec.Audience, 255) || len(spec.Nonce) != 16 {
		return nil, ErrGrantSpec
	}
	if spec.Use != UseOnce && spec.Use != UseUntilExpiry {
		return nil, ErrGrantSpec
	}
	if !validInterval(spec.NotBefore, spec.Expires) {
		return nil, ErrGrantInterval
	}
	if len(spec.Entries) == 0 || len(spec.Entries) > 64 {
		return nil, ErrGrantSpec
	}
	// The grantee MXID comes from the verified attestation of the subject key
	// (contract section 5); a different expected MXID refuses. Both
	// attestations must cover the whole grant interval.
	agent, err := VerifyMacAgentAttestation(spec.SubjectAttestation, spec.Issuer)
	if err != nil || agent.Key != spec.Subject || agent.MXID != spec.SubjectMXID || !agent.covers(spec.NotBefore, spec.Expires) {
		return nil, ErrGrantSpec
	}
	publisher, err := VerifyPublisherAttestation(spec.PublisherAttestation, spec.Issuer)
	if err != nil || publisher.Key == spec.Subject || !publisher.covers(spec.NotBefore, spec.Expires) {
		return nil, ErrGrantSpec
	}
	actions := map[string]bool{}
	targets := map[Target]bool{}
	pairs := map[Entry]bool{}
	for _, e := range spec.Entries {
		a, _, ok := lookupAction(e.Action)
		if !ok || e.Target.Kind != a.TargetKind || !printableToken(e.Target.ID, 255) || pairs[e] {
			return nil, ErrGrantSpec
		}
		pairs[e] = true
		actions[e.Action] = true
		targets[e.Target] = true
	}
	actionList := make([]string, 0, len(actions))
	for a := range actions {
		actionList = append(actionList, a)
	}
	sort.Strings(actionList)
	targetList := make([]Target, 0, len(targets))
	for t := range targets {
		targetList = append(targetList, t)
	}
	sort.Slice(targetList, func(i, j int) bool {
		if targetList[i].Kind != targetList[j].Kind {
			return targetList[i].Kind < targetList[j].Kind
		}
		return targetList[i].ID < targetList[j].ID
	})
	wireActions := make([]any, len(actionList))
	for i, a := range actionList {
		wireActions[i] = a
	}
	wireTargets := make([]any, len(targetList))
	for i, t := range targetList {
		wireTargets[i] = map[string]any{"kind": t.Kind, "id": t.ID}
	}
	nb, ex := wireTime(spec.NotBefore), wireTime(spec.Expires)
	body := map[string]any{
		"type": "grant/1", "aud": spec.Audience, "nonce": base64.RawURLEncoding.EncodeToString(spec.Nonce),
		"iat": nb, "exp": ex, "not_before": nb, "expires": ex,
		"issuer": spec.Issuer, "subject": spec.Subject,
		"actions": wireActions, "targets": wireTargets,
		"depth": int64(0), "parent": nil,
		"min_assurance": map[string]any{"level": "A2", "presence": false},
		"caveats":       map[string]any{"lang": CaveatsLang, "not_before": nb, "expires": ex, "use": spec.Use},
	}
	canonical, err := record.Canonical(body)
	if err != nil {
		return nil, ErrGrantSpec
	}
	plan, err := Prepare("grant/1", spec.Issuer, canonical)
	if err != nil {
		return nil, err
	}
	return &Grant{spec: spec, plan: plan, agent: agent, publisher: publisher}, nil
}

// Plan returns the grant's signing plan.
func (g *Grant) Plan() *Plan { return g.plan }

var msk = time.FixedZone("MSK", 3*60*60)

func mskInterval(nb, ex time.Time) string {
	clock := "15:04"
	if nb.Second() != 0 || ex.Second() != 0 {
		clock = "15:04:05"
	}
	return nb.In(msk).Format("02.01.2006 "+clock) + "–" + ex.In(msk).Format("02.01.2006 "+clock) + " MSK"
}

func policyLabel(use string) string {
	if use == UseOnce {
		return "1×"
	}
	return "до срока"
}

// orderedActions returns the grant's actions in vocabulary order.
func (g *Grant) orderedActions() []Action {
	seen := map[string]bool{}
	for _, e := range g.spec.Entries {
		seen[e.Action] = true
	}
	var out []Action
	for _, a := range vocabularyV2 {
		if seen[a.Name] {
			out = append(out, a)
		}
	}
	return out
}

// Reason returns the Touch ID reason (decision 154): policy, grantee MXID,
// interval in MSK, every entry label and the digest tail. It refuses with
// ErrReasonOverflow instead of truncating.
func (g *Grant) Reason() (string, error) {
	labels := make([]string, 0, len(g.spec.Entries))
	for _, a := range g.orderedActions() {
		labels = append(labels, a.Short)
	}
	d := g.plan.Digest()
	r := fmt.Sprintf("%s · %s · %s · %s · SHA256 %x", policyLabel(g.spec.Use), g.agent.MXID, mskInterval(g.spec.NotBefore, g.spec.Expires), strings.Join(labels, ", "), d[26:])
	if !utf8.ValidString(r) || utf8.RuneCountInString(r) > ReasonLimit {
		return "", ErrReasonOverflow
	}
	for _, c := range r {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return "", ErrReasonOverflow
		}
	}
	return r, nil
}

// Rendering returns the full pre-sign rendering the issuer prints before the
// prompt: every field of the record that will be signed.
func (g *Grant) Rendering() string {
	var b strings.Builder
	d := g.plan.Digest()
	fmt.Fprintf(&b, "grant/1 owner grant, to be signed under Touch ID\n")
	fmt.Fprintf(&b, "issuer: %s\n", g.spec.Issuer)
	fmt.Fprintf(&b, "grantee: %s (generation %d, from attestation %s)\n", g.agent.MXID, g.agent.Generation, g.agent.ContentID)
	fmt.Fprintf(&b, "grantee key: %s\n", g.spec.Subject)
	fmt.Fprintf(&b, "grantee key fingerprint (as mac-keyvault prints it): %s\n", g.agent.Fingerprint)
	fmt.Fprintf(&b, "revocation publisher key: %s (attestation %s)\n", g.publisher.Key, g.publisher.ContentID)
	fmt.Fprintf(&b, "revocation publisher key fingerprint (as mac-keyvault prints it): %s\n", g.publisher.Fingerprint)
	fmt.Fprintf(&b, "audience: %s\n", g.spec.Audience)
	fmt.Fprintf(&b, "use policy: %s\n", g.spec.Use)
	fmt.Fprintf(&b, "interval UTC: %s – %s\n", wireTime(g.spec.NotBefore), wireTime(g.spec.Expires))
	fmt.Fprintf(&b, "interval MSK: %s\n", mskInterval(g.spec.NotBefore, g.spec.Expires))
	fmt.Fprintf(&b, "delegation depth: 0 (no re-delegation)\n")
	fmt.Fprintf(&b, "request assurance: A2, no presence\n")
	for _, a := range g.orderedActions() {
		for _, e := range g.spec.Entries {
			if e.Action == a.Name {
				fmt.Fprintf(&b, "entry: %s (%s) on %s/%s\n", a.Name, a.Long, e.Target.Kind, e.Target.ID)
			}
		}
	}
	fmt.Fprintf(&b, "content id: %s\n", g.plan.ContentID())
	fmt.Fprintf(&b, "signing digest: %x\n", d[:])
	return b.String()
}
