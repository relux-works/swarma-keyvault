package keyvault

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// A complete local synthetic grant exercises all typed fields. The pinned source
// implementation's public fixture was checked read-only; its payload does not
// form part of this module's test corpus.
func TestRootGrantsGrantV3PinnedReference(t *testing.T) {
	f := grantV3FullFixture(t)
	raw := rootGrantsRaw13(t, f.g)
	if _, err := ParseRootGrantsGrantV3(raw, time.Unix(100, 0)); err != nil {
		t.Fatal("complete synthetic grant refused", err)
	}
	_, err := ParseRootGrantsGrantV3(raw, time.Unix(98, 0))
	rootGrantsWantRefusal(t, err, "consent_invalid")
}

// Every representation mutant refuses instead of being normalized. Tests use a
// valid adjacent synthetic control; refusals return no partial parsed authority.
func TestRootGrantsGrantV3CanonicalRefusals(t *testing.T) {
	f := grantV3FullFixture(t)
	raw := rootGrantsRaw13(t, f.g)
	s := string(raw)
	cases := []string{s + "\n", " " + s, s + "{}", s + "\x00", strings.Replace(s, `"version":3`, `"version":3,"version":3`, 1),
		strings.Replace(s, `"version":3`, `"version":3,"Version":3`, 1), strings.Replace(s, `"version":3`, `"version":3,"extra":0`, 1),
		strings.Replace(s, `"version":3`, `"version":3.0`, 1), strings.Replace(s, `"version":3`, `"version":null`, 1),
		strings.Replace(s, `"version":3`, `"Version":3`, 1), strings.Replace(s, `"version":3`, `"\u0076ersion":3`, 1),
		strings.Replace(s, `"scope":["pay"]`, `"scope":["pay","names.register"]`, 1),
		strings.Replace(s, `"scope":["pay"]`, `"scope":["pay","pay"]`, 1),
		strings.Replace(s, `"scope":["pay"]`, `"scope":null`, 1),
		strings.Replace(s, `"vout":1`, `"vout":4294967296`, 1),
		strings.Replace(s, `"grantee_key":`, `"grantee_name":"","grantee_key":`, 1),
		strings.Replace(s, `"consent":`, `"budget":null,"consent":`, 1)}
	for i, input := range cases {
		before := []byte(input)
		g, err := ParseRootGrantsGrantV3(before, time.Unix(100, 0))
		if err == nil || g.Version != 0 || !bytes.Equal(before, []byte(input)) {
			t.Fatalf("representation mutant %d accepted or mutated", i)
		}
	}
	if _, err := ParseRootGrantsGrantV3(raw, time.Unix(100, 0)); err != nil {
		t.Fatal("positive neighbor failed")
	}
}

func grantV3SignTestHash(t *testing.T, hash string, scalar byte) string {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = scalar // Public synthetic fixture, no product key input.
	defer clear(secret)
	sig, err := signNostrWithAux(secret, nostrTestHex(t, hash), [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig)
}

func grantV3TestConsent(t *testing.T, g *RootGrantsGrantV3) {
	t.Helper()
	e := &g.Consent.ConsentEvent
	b, err := rootGrantsEventBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	if err != nil {
		t.Fatal(err)
	}
	e.ID = rootGrantsHashHex(b)
	e.Sig = grantV3SignTestHash(t, e.ID, 2)
	g.Consent.ContractSHA256 = g.ContractSHA256
	g.Consent.LandlordSig = grantV3SignTestHash(t, g.ContractSHA256, 3)
}

type grantV3Fixture struct {
	g RootGrantsGrantV3
	c RootGrantsContractV1
	p RootGrantsAuthority
	r RootGrantsRecord
}

func grantV3FullFixture(t *testing.T) grantV3Fixture {
	t.Helper()
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	c := RootGrantsContractV1{Version: 1, BookingID: strings.Repeat("1", 64), RenterPubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		AgentPubkey: rootGrantsOtherXOnly, StationName: "id/example-agent", NotBefore: 100, NotAfter: 1000,
		Allowed: []string{"pay"}, Forbidden: []string{"deliver", "publish", "repository.push", "secret.release"}, BudgetSat: 0,
		TemplateID: "example", TemplateSHA256: strings.Repeat("2", 64), ProfileID: "example", ProfileVersion: "1",
		ProfileSHA256: strings.Repeat("3", 64), PriceUSDCents: 100, USDMicrosPerNMC: 1000000, RateAsOf: 50, PriceNMCSat: 100,
		PaymentPolicy: "advance", PaymentAddress: "N123456789123456789123456789", PrivacySHA256: strings.Repeat("4", 64)}
	cb, err := rootGrantsEventBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	g := RootGrantsGrantV3{Version: 3, Network: "regtest", Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		AgentName: c.StationName, LandlordName: "id/example-landlord", IssuerKey: r.PublicKey, GranteeKey: c.RenterPubkey,
		ContractSHA256: rootGrantsHashHex(cb), Scope: c.Allowed, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Seal: RootGrantsGrantPoint{TxID: strings.Repeat("5", 64), Vout: 1}}
	g.Consent.ConsentEvent = RootGrantsGrantEvent{Pubkey: g.GranteeKey, CreatedAt: 99, Kind: 8181,
		Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", g.ContractSHA256}, {"booking", c.BookingID}, {"privacy", c.PrivacySHA256}}}
	grantV3TestConsent(t, &g)
	p := RootGrantsAuthority{Schema: "namecoin-root-grants-authority/1", OwnerPrincipal: "owner:id/example-owner", LandlordName: g.LandlordName,
		Network: g.Network, Genesis: g.Genesis, Record: RootGrantsAuthorityRecord{Service: r.Service, Version: r.Version,
			MetadataSHA256: rootGrantsHashHex(rootGrantsRaw13(t, r)), PublicKey: r.PublicKey, SealScript: r.SealScript},
		Operations: []string{rootGrantsGrantV3Operation}, AgentName: g.AgentName, AgentKey: c.AgentPubkey, GranteeKey: g.GranteeKey,
		Scope: []string{"pay"}, NotBefore: 0, NotAfter: 2000, MaxGrantSeconds: 1000, MaxBudgetSat: 0, Seal: g.Seal, ObservationPolicy: RootGrantsOfflineReview}
	return grantV3Fixture{g, c, p, r}
}

func (f grantV3Fixture) prepare(t *testing.T) (*RootGrantsGrantV3Plan, error) {
	t.Helper()
	cb, err := rootGrantsEventBytes(f.c)
	if err != nil {
		t.Fatal(err)
	}
	return PrepareRootGrantsGrantV3(rootGrantsRaw13(t, f.g), cb, rootGrantsRaw13(t, f.p), rootGrantsRaw13(t, f.r), f.p.OwnerPrincipal, time.Unix(100, 0))
}

// A complete synthetic positive witness reaches a fully bound public review and
// verifies the final signature. Mutating source buffers cannot alter that plan.
func TestRootGrantsGrantV3FullPlan(t *testing.T) {
	f := grantV3FullFixture(t)
	grant, authority, metadata := rootGrantsRaw13(t, f.g), rootGrantsRaw13(t, f.p), rootGrantsRaw13(t, f.r)
	contract, _ := rootGrantsEventBytes(f.c)
	p, err := PrepareRootGrantsGrantV3(grant, contract, authority, metadata, f.p.OwnerPrincipal, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	review, err := p.ReviewJSON()
	if err != nil || !bytes.Contains(review, []byte(RootGrantsOfflineReview)) || !bytes.Contains(review, []byte(f.c.PaymentAddress)) || !bytes.Contains(review, []byte(f.p.OwnerPrincipal)) {
		t.Fatal("complete review missing terms or offline limitation")
	}
	hash, _ := rootGrantsGrantV3Digest(grant)
	sig := nostrTestHex(t, grantV3SignTestHash(t, hex.EncodeToString(hash[:]), 3))
	clear(grant)
	clear(contract)
	clear(authority)
	clear(metadata)
	after, _ := p.ReviewJSON()
	if !bytes.Equal(review, after) || p.VerifySignature(sig) != nil {
		t.Fatal("plan did not retain immutable binding")
	}
	sig[0] ^= 1
	rootGrantsWantRefusal(t, p.VerifySignature(sig), "signature_verification_failed")
}

// The compatibility table keeps every legitimate nullable/optional profile
// form beside the default-free allowlist: main network, present name/budget,
// all six sorted actions, and the valid empty-scope form all reach public review.
func TestRootGrantsGrantV3CompatibilityForms(t *testing.T) {
	for _, mode := range []string{"main-all-actions-optional-fields", "regtest-empty-scope-zero-budget"} {
		t.Run(mode, func(t *testing.T) {
			f := grantV3FullFixture(t)
			if mode == "main-all-actions-optional-fields" {
				f.p.Network, f.g.Network = "main", "main"
				f.p.Genesis, f.g.Genesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
				f.c.RenterName, f.g.GranteeName = "id/example-renter", "id/example-renter"
				f.p.GranteeName = "id/example-renter"
				budget := int64(250)
				f.g.Budget, f.c.BudgetSat, f.p.MaxBudgetSat = &budget, budget, budget
				f.c.Allowed = append([]string{}, rootGrantsGrantActions...)
				f.c.Forbidden = []string{}
				f.g.Scope = append([]string{}, rootGrantsGrantActions...)
				f.p.Scope = append([]string{}, rootGrantsGrantActions...)
			} else {
				f.c.Allowed = []string{}
				f.c.Forbidden = []string{"deliver", "pay", "publish", "repository.push", "secret.release"}
				f.g.Scope = []string{}
				f.p.Scope = []string{}
			}
			contract, err := rootGrantsEventBytes(f.c)
			if err != nil {
				t.Fatal(err)
			}
			f.g.ContractSHA256 = rootGrantsHashHex(contract)
			f.g.Consent.ConsentEvent.Tags[1][1] = f.g.ContractSHA256
			grantV3TestConsent(t, &f.g)
			plan, err := PrepareRootGrantsGrantV3(rootGrantsRaw13(t, f.g), contract, rootGrantsRaw13(t, f.p), rootGrantsRaw13(t, f.r), f.p.OwnerPrincipal, time.Unix(100, 0))
			if err != nil || plan == nil {
				t.Fatalf("reference-supported form refused: %v", err)
			}
		})
	}
}

// Every independent enrollment binding is enforced, with unchanged valid bytes
// beside each negative. This is a pure policy boundary, not native custody.
func TestRootGrantsGrantV3AuthorityRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(*grantV3Fixture)
	}{
		{"principal", func(f *grantV3Fixture) { f.p.OwnerPrincipal = "alias" }},
		{"landlord", func(f *grantV3Fixture) { f.p.LandlordName = "id/other" }},
		{"genesis", func(f *grantV3Fixture) { f.p.Genesis = strings.Repeat("1", 64) }},
		{"record-digest", func(f *grantV3Fixture) { f.p.Record.MetadataSHA256 = strings.Repeat("0", 64) }},
		{"generation", func(f *grantV3Fixture) { f.p.Record.Version++ }},
		{"record-service", func(f *grantV3Fixture) { f.p.Record.Service = "other" }},
		{"key", func(f *grantV3Fixture) {
			f.p.Record.PublicKey = rootGrantsOtherXOnly
			f.p.Record.SealScript = rootGrantsGrantSealScript(f.p.Record.PublicKey)
		}},
		{"seal-script", func(f *grantV3Fixture) { f.p.Record.SealScript = "00" }},
		{"operation", func(f *grantV3Fixture) { f.p.Operations = []string{"sign-digest"} }},
		{"agent", func(f *grantV3Fixture) { f.p.AgentName = "id/other-agent" }},
		{"agent-key", func(f *grantV3Fixture) { f.p.AgentKey = grantV3TestK }},
		{"grantee", func(f *grantV3Fixture) { f.p.GranteeKey = grantV3TestK }},
		{"grantee-name", func(f *grantV3Fixture) { f.p.GranteeName = "id/other-renter" }},
		{"scope", func(f *grantV3Fixture) { f.p.Scope = []string{} }},
		{"not-before", func(f *grantV3Fixture) { f.p.NotBefore = 101 }},
		{"not-after", func(f *grantV3Fixture) { f.p.NotAfter = 999 }},
		{"duration", func(f *grantV3Fixture) { f.p.MaxGrantSeconds = 899 }},
		{"budget", func(f *grantV3Fixture) { f.p.MaxBudgetSat = -1 }},
		{"seal", func(f *grantV3Fixture) { f.p.Seal.Vout++ }},
		{"unqualified-observation", func(f *grantV3Fixture) { f.p.ObservationPolicy = "caller-rpc-approved" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := grantV3FullFixture(t)
			c.edit(&f)
			if plan, err := f.prepare(t); err == nil || plan != nil {
				t.Fatal("changed enrollment reached review")
			}
			if _, err := grantV3FullFixture(t).prepare(t); err != nil {
				t.Fatal("positive neighbor refused", err)
			}
		})
	}
}
