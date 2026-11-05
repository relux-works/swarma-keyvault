package mugrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const metaMXID = "@meta-keeper.keeper-sirius:gr.relux.works"

func metaSpec(t *testing.T) GrantSpec {
	t.Helper()
	_, issuer := testKey(t)
	_, subject := testKey(t)
	product := Target{"product", "swarma-platform"}
	var entries []Entry
	for _, a := range []string{"work.assign", "work.require", "work.contract", "work.prioritize", "work.land-order", "work.accept"} {
		entries = append(entries, Entry{a, product})
	}
	entries = append(entries, Entry{"account.manage", Target{"account-scope", "owner:alexis"}}, Entry{"room.membership", Target{"room-scope", "swarma-space"}})
	spec := GrantSpec{
		Issuer: issuer, Subject: subject, SubjectMXID: metaMXID, Audience: "swarma-keyvault-receiver",
		Entries:   entries,
		NotBefore: time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC), Expires: time.Date(2027, 11, 5, 13, 0, 0, 0, time.UTC),
		Use: UseUntilExpiry, Nonce: bytes.Repeat([]byte{0x11}, 16),
	}
	attestSpec(t, &spec)
	return spec
}

// Claim: the Meta delegation builds a canonical grant/1 body with sorted
// actions, sorted typed targets, depth 0, no parent, A2 without presence and the
// signed until_expiry policy in caveats/v2, and its Touch ID reason shows the
// policy, grantee, MSK interval and all eight labels within 200 scalars.
func TestBuildMetaDelegation(t *testing.T) {
	g, err := BuildGrant(metaSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(g.Plan().Body(), &b); err != nil {
		t.Fatal(err)
	}
	actions, _ := json.Marshal(b["actions"])
	if string(actions) != `["account.manage","room.membership","work.accept","work.assign","work.contract","work.land-order","work.prioritize","work.require"]` {
		t.Fatal("actions", string(actions))
	}
	targets, _ := json.Marshal(b["targets"])
	if string(targets) != `[{"id":"owner:alexis","kind":"account-scope"},{"id":"swarma-platform","kind":"product"},{"id":"swarma-space","kind":"room-scope"}]` {
		t.Fatal("targets", string(targets))
	}
	caveats, _ := json.Marshal(b["caveats"])
	if string(caveats) != `{"expires":"2027-11-05T13:00:00Z","lang":"caveats/v2","not_before":"2026-11-05T13:00:00Z","use":"until_expiry"}` {
		t.Fatal("caveats", string(caveats))
	}
	if b["depth"] != float64(0) || b["parent"] != nil || b["iat"] != "2026-11-05T13:00:00Z" || b["expires"] != "2027-11-05T13:00:00Z" || b["nonce"] != "EREREREREREREREREREREQ" {
		t.Fatal("common members", b)
	}
	r, err := g.Reason()
	if err != nil {
		t.Fatal(err)
	}
	want := "до срока · " + metaMXID + " · 05.11.2026 16:00–05.11.2027 16:00 MSK · задачи, требования, контракты, приоритеты, посадки, приёмка, учётки, комнаты · SHA256 "
	if !strings.HasPrefix(r, want) || utf8.RuneCountInString(r) > ReasonLimit || utf8.RuneCountInString(r) != utf8.RuneCountInString(want)+12 {
		t.Fatal("reason", utf8.RuneCountInString(r), r)
	}
	rendering := g.Rendering()
	for _, s := range []string{metaMXID, "until_expiry", "2026-11-05T13:00:00Z – 2027-11-05T13:00:00Z", "account.manage (create, rename, retire agent accounts) on account-scope/owner:alexis", "room.membership (invite to and remove from rooms) on room-scope/swarma-space", "work.accept (acceptance and return of work) on product/swarma-platform", g.Plan().ContentID(), "delegation depth: 0"} {
		if !strings.Contains(rendering, s) {
			t.Fatal("rendering misses", s)
		}
	}
}

// Claim: the interval cap is exactly one calendar year chosen per grant; one
// second more, an empty or reversed interval, a non-UTC or fractional time are
// refused.
func TestGrantIntervalCap(t *testing.T) {
	spec := metaSpec(t)
	if _, err := BuildGrant(spec); err != nil {
		t.Fatal("exact one-year interval refused", err)
	}
	short := spec
	short.Expires = short.NotBefore.Add(time.Hour)
	if _, err := BuildGrant(short); err != nil {
		t.Fatal("one-hour interval refused", err)
	}
	cases := map[string]func(*GrantSpec){
		"year-plus-second": func(s *GrantSpec) { s.Expires = s.Expires.Add(time.Second) },
		"empty":            func(s *GrantSpec) { s.Expires = s.NotBefore },
		"reversed":         func(s *GrantSpec) { s.Expires = s.NotBefore.Add(-time.Hour) },
		"non-utc":          func(s *GrantSpec) { s.NotBefore = s.NotBefore.In(msk) },
		"fraction":         func(s *GrantSpec) { s.Expires = s.Expires.Add(-time.Millisecond) },
	}
	for name, mutate := range cases {
		s := metaSpec(t)
		mutate(&s)
		if _, err := BuildGrant(s); !errors.Is(err, ErrGrantInterval) {
			t.Fatal("interval admitted", name, err)
		}
	}
}

// Claim: the vocabulary is a closed allowlist and the spec is checked field by
// field; every refusal sits beside the valid Meta spec.
func TestGrantSpecRefusals(t *testing.T) {
	cases := map[string]func(*GrantSpec){
		"unknown-action":    func(s *GrantSpec) { s.Entries[0].Action = "repository.delete" },
		"v1-action":         func(s *GrantSpec) { s.Entries[0].Action = "agent.spawn" },
		"wrong-target-kind": func(s *GrantSpec) { s.Entries[0].Target.Kind = "account-scope" },
		"empty-target-id":   func(s *GrantSpec) { s.Entries[0].Target.ID = "" },
		"duplicate-entry":   func(s *GrantSpec) { s.Entries = append(s.Entries, s.Entries[0]) },
		"no-entries":        func(s *GrantSpec) { s.Entries = nil },
		"bad-mxid":          func(s *GrantSpec) { s.SubjectMXID = "meta-keeper" },
		"self-grant":        func(s *GrantSpec) { s.Subject = s.Issuer },
		"bad-subject-key":   func(s *GrantSpec) { s.Subject = "p256:AAAA" },
		"short-nonce":       func(s *GrantSpec) { s.Nonce = s.Nonce[:15] },
		"unknown-use":       func(s *GrantSpec) { s.Use = "unlimited" },
		"empty-use":         func(s *GrantSpec) { s.Use = "" },
		"audience-space":    func(s *GrantSpec) { s.Audience = "two words" },
	}
	for name, mutate := range cases {
		s := metaSpec(t)
		mutate(&s)
		if _, err := BuildGrant(s); !errors.Is(err, ErrGrantSpec) {
			t.Fatal("spec admitted", name, err)
		}
	}
}

// Claim: an over-long reason is refused, never truncated; a once grant shows
// its own policy label.
func TestGrantReasonBounds(t *testing.T) {
	s := metaSpec(t)
	s.SubjectMXID = "@" + strings.Repeat("m", 120) + ":gr.relux.works"
	attestSpec(t, &s)
	g, err := BuildGrant(s)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := g.Reason(); !errors.Is(err, ErrReasonOverflow) || r != "" {
		t.Fatal("overflowing reason returned", len(r), err)
	}
	once := metaSpec(t)
	once.Use = UseOnce
	g, err = BuildGrant(once)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := g.Reason(); err != nil || !strings.HasPrefix(r, "1× · ") {
		t.Fatal("once reason", r, err)
	}
}

// Claim: a grant built by the issuer can be signed by the issuer key (software
// stand-in) and assembled; a signature by the grantee key cannot.
func TestGrantSignAssemble(t *testing.T) {
	ik, issuer := testKey(t)
	sk, subject := testKey(t)
	s := metaSpec(t)
	s.Issuer, s.Subject = issuer, subject
	attestSpec(t, &s)
	g, err := BuildGrant(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleNative(g.Plan(), signDER(t, ik, g.Plan().Digest())); err != nil {
		t.Fatal("issuer signature refused", err)
	}
	if _, err := AssembleNative(g.Plan(), signDER(t, sk, g.Plan().Digest())); !errors.Is(err, ErrAssembly) {
		t.Fatal("grantee signature accepted as issuer", err)
	}
}
