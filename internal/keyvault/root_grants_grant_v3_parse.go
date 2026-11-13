package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Wire order and types match the pinned public landlord-grant profile and
// issuance contract. Parsing supplies no owner authority.
type RootGrantsGrantV3 struct {
	Version        int                    `json:"version"`
	Network        string                 `json:"network"`
	Genesis        string                 `json:"genesis"`
	AgentName      string                 `json:"agent_name"`
	LandlordName   string                 `json:"landlord_name"`
	IssuerKey      string                 `json:"issuer_key"`
	GranteeKey     string                 `json:"grantee_key"`
	GranteeName    string                 `json:"grantee_name,omitempty"`
	ContractSHA256 string                 `json:"contract_sha256"`
	Scope          []string               `json:"scope"`
	NotBefore      int64                  `json:"not_before"`
	NotAfter       int64                  `json:"not_after"`
	Seal           RootGrantsGrantPoint   `json:"seal"`
	Budget         *int64                 `json:"budget,omitempty"`
	Consent        RootGrantsGrantConsent `json:"consent"`
}

type RootGrantsGrantPoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type RootGrantsGrantConsent struct {
	ContractSHA256 string               `json:"contract_sha256"`
	ConsentEvent   RootGrantsGrantEvent `json:"consent_event"`
	LandlordSig    string               `json:"landlord_sig"`
}

type RootGrantsGrantEvent struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

const rootGrantsMaxMoney int64 = 21000000 * 100000000
const rootGrantsLastUnixSecond int64 = 253402300799

var rootGrantsGrantActions = []string{"deliver", "names.register", "pay", "publish", "repository.push", "secret.release"}

func rootGrantsNetwork(network, genesis string) bool {
	return network == "regtest" && genesis == "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" ||
		network == "main" && genesis == "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
}

func rootGrantsGrantName(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) <= 3 || len(s) > 255 {
		return false
	}
	for _, c := range []byte(s[3:]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func rootGrantsGrantKey(s string) bool {
	if !lowerHex(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, err := NostrNPub(b) // Existing x-only range/lift check, no private input.
	return err == nil
}

func rootGrantsGrantScope(scope []string) bool {
	if scope == nil || len(scope) > len(rootGrantsGrantActions) || !slices.IsSorted(scope) {
		return false
	}
	for i, action := range scope {
		if !slices.Contains(rootGrantsGrantActions, action) || i > 0 && scope[i-1] == action {
			return false
		}
	}
	return true
}

func rootGrantsPrintable(s string) bool {
	for _, b := range []byte(s) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// NIP-01 uses unescaped printable ASCII, unlike the grant's json.Marshal.
func rootGrantsEventBytes(value any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(value) != nil {
		return nil, recoveryRefuse("invalid_arguments")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

func rootGrantsHashHex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func rootGrantsVerifyHash(key, hash, signature string) bool {
	if !rootGrantsGrantKey(key) || !lowerHex(hash, 32) || !lowerHex(signature, 64) {
		return false
	}
	k, _ := hex.DecodeString(key)
	h, _ := hex.DecodeString(hash)
	s, _ := hex.DecodeString(signature)
	return VerifyNostr(k, h, s) == nil
}

// ParseRootGrantsGrantV3 admits exact complete canonical bytes. It never repairs
// a request, accepts a caller digest, resolves a name or observes the chain.
func ParseRootGrantsGrantV3(raw []byte, at time.Time) (RootGrantsGrantV3, error) {
	var g RootGrantsGrantV3
	fail := func(code string) (RootGrantsGrantV3, error) { return RootGrantsGrantV3{}, recoveryRefuse(code) }
	if len(raw) > rootGrantsGrantV3Limit {
		return fail("limit_exceeded")
	}
	if len(raw) == 0 || DecodeSingleJSON(raw, &g) != nil {
		return fail("invalid_arguments")
	}
	canonical, err := json.Marshal(g)
	if err != nil || !bytes.Equal(raw, canonical) {
		return fail("invalid_arguments")
	}
	if g.Version != 3 {
		return fail("unsupported_version")
	}
	if !rootGrantsNetwork(g.Network, g.Genesis) || !rootGrantsGrantName(g.AgentName) || !rootGrantsGrantName(g.LandlordName) ||
		g.AgentName == g.LandlordName || g.GranteeName != "" && !rootGrantsGrantName(g.GranteeName) ||
		!rootGrantsGrantKey(g.IssuerKey) || !rootGrantsGrantKey(g.GranteeKey) || !lowerHex(g.ContractSHA256, 32) ||
		!lowerHex(g.Seal.TxID, 32) || !rootGrantsGrantScope(g.Scope) || g.NotBefore < 0 || g.NotAfter <= g.NotBefore ||
		g.NotAfter > rootGrantsLastUnixSecond || g.Budget != nil && (*g.Budget < 0 || *g.Budget > rootGrantsMaxMoney) {
		return fail("invalid_arguments")
	}
	e := g.Consent.ConsentEvent
	if g.Consent.ContractSHA256 != g.ContractSHA256 || e.CreatedAt < 1 || e.CreatedAt > at.Unix() || e.CreatedAt >= g.NotAfter ||
		e.Pubkey != g.GranteeKey || e.Kind != 8181 || e.Content != "" || len(e.Tags) != 4 {
		return fail("consent_invalid")
	}
	// Compare every exact tag including order and lengths, with no event fields
	// silently projected away from the NIP-01 signature message.
	for _, tag := range e.Tags {
		if len(tag) != 2 || !rootGrantsPrintable(tag[0]) || !rootGrantsPrintable(tag[1]) || len(tag[1]) > 512 {
			return fail("consent_invalid")
		}
	}
	if !slices.Equal(e.Tags[0], []string{"t", "swarma-rental-consent-v1"}) ||
		!slices.Equal(e.Tags[1], []string{"contract", g.ContractSHA256}) ||
		e.Tags[2][0] != "booking" || !lowerHex(e.Tags[2][1], 32) || e.Tags[3][0] != "privacy" || !lowerHex(e.Tags[3][1], 32) {
		return fail("consent_invalid")
	}
	event, err := rootGrantsEventBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	if err != nil || rootGrantsHashHex(event) != e.ID || !rootGrantsVerifyHash(e.Pubkey, e.ID, e.Sig) ||
		!rootGrantsVerifyHash(g.IssuerKey, g.ContractSHA256, g.Consent.LandlordSig) {
		return fail("consent_invalid")
	}
	return g, nil
}

// RootGrantsContractV1 is the complete reference v1 terms object, not a hash-only
// substitute. Other contract versions require their own reviewed typed profile.
type RootGrantsContractV1 struct {
	Version         int      `json:"version"`
	BookingID       string   `json:"booking_id"`
	RenterPubkey    string   `json:"renter_pubkey"`
	RenterName      string   `json:"renter_name"`
	AgentPubkey     string   `json:"agent_pubkey"`
	StationName     string   `json:"station_name"`
	NotBefore       int64    `json:"not_before"`
	NotAfter        int64    `json:"not_after"`
	Allowed         []string `json:"allowed"`
	Forbidden       []string `json:"forbidden"`
	BudgetSat       int64    `json:"budget_sat"`
	TemplateID      string   `json:"template_id"`
	TemplateSHA256  string   `json:"template_sha256"`
	ProfileID       string   `json:"profile_id"`
	ProfileVersion  string   `json:"profile_version"`
	ProfileSHA256   string   `json:"profile_sha256"`
	PriceUSDCents   int64    `json:"price_usd_cents"`
	USDMicrosPerNMC int64    `json:"usd_micros_per_nmc"`
	RateAsOf        int64    `json:"rate_as_of"`
	PriceNMCSat     int64    `json:"price_nmc_sat"`
	PaymentPolicy   string   `json:"payment_policy"`
	PaymentAddress  string   `json:"payment_address"`
	PrivacySHA256   string   `json:"privacy_sha256"`
}

func rootGrantsParseContractV1(raw []byte, g RootGrantsGrantV3, agentKey string) (RootGrantsContractV1, error) {
	var c RootGrantsContractV1
	fail := func(code string) (RootGrantsContractV1, error) { return RootGrantsContractV1{}, recoveryRefuse(code) }
	if len(raw) > 65536 {
		return fail("limit_exceeded")
	}
	if len(raw) == 0 || DecodeSingleJSON(raw, &c) != nil {
		return fail("contract_mismatch")
	}
	canonical, err := rootGrantsEventBytes(c)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fail("contract_mismatch")
	}
	if c.Version != 1 {
		return fail("unsupported_version")
	}
	for _, s := range []string{c.BookingID, c.RenterPubkey, c.RenterName, c.AgentPubkey, c.StationName, c.TemplateID, c.TemplateSHA256,
		c.ProfileID, c.ProfileVersion, c.ProfileSHA256, c.PaymentPolicy, c.PaymentAddress, c.PrivacySHA256} {
		if !rootGrantsPrintable(s) {
			return fail("review_unrenderable")
		}
	}
	budget := int64(0)
	if g.Budget != nil {
		budget = *g.Budget
	}
	if rootGrantsHashHex(raw) != g.ContractSHA256 || c.BookingID != g.Consent.ConsentEvent.Tags[2][1] ||
		c.PrivacySHA256 != g.Consent.ConsentEvent.Tags[3][1] || c.RenterPubkey != g.GranteeKey || c.RenterName != g.GranteeName ||
		c.AgentPubkey != agentKey || c.StationName != g.AgentName || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter ||
		!slices.Equal(c.Allowed, g.Scope) || c.BudgetSat != budget || !rootGrantsGrantScope(c.Allowed) || !rootGrantsGrantScope(c.Forbidden) {
		return fail("contract_mismatch")
	}
	actions := 5
	if slices.Contains(c.Allowed, "names.register") || slices.Contains(c.Forbidden, "names.register") {
		actions = 6
	}
	if len(c.Allowed)+len(c.Forbidden) != actions {
		return fail("contract_mismatch")
	}
	for _, v := range c.Allowed {
		if slices.Contains(c.Forbidden, v) {
			return fail("contract_mismatch")
		}
	}
	if !lowerHex(c.BookingID, 32) || !lowerHex(c.TemplateSHA256, 32) || !lowerHex(c.ProfileSHA256, 32) || !lowerHex(c.PrivacySHA256, 32) ||
		c.TemplateID == "" || c.ProfileID == "" || c.ProfileVersion == "" || c.PriceNMCSat <= 0 || c.PriceNMCSat > rootGrantsMaxMoney ||
		c.PriceUSDCents <= 0 || c.USDMicrosPerNMC <= 0 || c.RateAsOf < 1 ||
		len(c.PaymentAddress) < 26 || len(c.PaymentAddress) > 40 || c.PaymentPolicy != "advance" && c.PaymentPolicy != "start_now" {
		return fail("contract_mismatch")
	}
	return c, nil
}
