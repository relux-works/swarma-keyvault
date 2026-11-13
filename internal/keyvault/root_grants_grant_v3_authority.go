package keyvault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// This proposed profile is explicitly offline. It cannot establish current
// names, seal unspentness, payment, issuance reservation or grant liveness.
const RootGrantsOfflineReview = "offline-document-review/1"

type RootGrantsAuthorityRecord struct {
	Service        string `json:"service"`
	Version        int    `json:"version"`
	MetadataSHA256 string `json:"metadata_sha256"`
	PublicKey      string `json:"public_key"`
	SealScript     string `json:"seal_script"`
}

// RootGrantsAuthority is independent owner enrollment, never derived from a
// grant, record, environment or caller-supplied policy path. Parsing this PUBLIC
// structure alone does not prove an independent installation or native custody.
type RootGrantsAuthority struct {
	Schema            string                    `json:"schema"`
	OwnerPrincipal    string                    `json:"owner_principal"`
	LandlordName      string                    `json:"landlord_name"`
	Network           string                    `json:"network"`
	Genesis           string                    `json:"genesis"`
	Record            RootGrantsAuthorityRecord `json:"record"`
	Operations        []string                  `json:"operations"`
	AgentName         string                    `json:"agent_name"`
	AgentKey          string                    `json:"agent_key"`
	GranteeKey        string                    `json:"grantee_key"`
	GranteeName       string                    `json:"grantee_name"`
	Scope             []string                  `json:"scope"`
	NotBefore         int64                     `json:"not_before"`
	NotAfter          int64                     `json:"not_after"`
	MaxGrantSeconds   int64                     `json:"max_grant_seconds"`
	MaxBudgetSat      int64                     `json:"max_budget_sat"`
	Seal              RootGrantsGrantPoint      `json:"seal"`
	ObservationPolicy string                    `json:"observation_policy"`
}

func rootGrantsOwnerPrincipal(s string) bool {
	const prefix = "owner:id/"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	label := strings.TrimPrefix(s, prefix)
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.Contains(label, "--") {
		return false
	}
	for _, b := range []byte(label) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}

func rootGrantsGrantSealScript(key string) string {
	if !rootGrantsGrantKey(key) {
		return ""
	}
	compressed, _ := hex.DecodeString("02" + key)
	return "76a914" + hex.EncodeToString(recoveryHash160(compressed)) + "88ac"
}

func ParseRootGrantsAuthority(raw []byte) (RootGrantsAuthority, error) {
	var p RootGrantsAuthority
	fail := func(code string) (RootGrantsAuthority, error) { return RootGrantsAuthority{}, recoveryRefuse(code) }
	if len(raw) > 32768 {
		return fail("limit_exceeded")
	}
	if len(raw) == 0 || DecodeSingleJSON(raw, &p) != nil {
		return fail("invalid_arguments")
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fail("invalid_arguments")
	}
	if p.Schema != "namecoin-root-grants-authority/1" {
		return fail("unsupported_version")
	}
	if !slices.Equal(p.Operations, []string{rootGrantsGrantV3Operation}) {
		return fail("unsupported_operation")
	}
	if p.ObservationPolicy != RootGrantsOfflineReview {
		return fail("operation_unavailable")
	}
	_, addressErr := (RootGrantsAddress{Service: p.Record.Service, Version: p.Record.Version}).Account()
	if addressErr != nil || !rootGrantsOwnerPrincipal(p.OwnerPrincipal) || !rootGrantsGrantName(p.LandlordName) ||
		!rootGrantsNetwork(p.Network, p.Genesis) || !lowerHex(p.Record.MetadataSHA256, 32) || !rootGrantsGrantKey(p.Record.PublicKey) ||
		p.Record.SealScript != rootGrantsGrantSealScript(p.Record.PublicKey) || !rootGrantsGrantName(p.AgentName) || p.AgentName == p.LandlordName ||
		!rootGrantsGrantKey(p.AgentKey) || !rootGrantsGrantKey(p.GranteeKey) || p.GranteeName != "" && !rootGrantsGrantName(p.GranteeName) ||
		!rootGrantsGrantScope(p.Scope) || p.NotBefore < 0 || p.NotAfter <= p.NotBefore || p.NotAfter > rootGrantsLastUnixSecond ||
		p.MaxGrantSeconds < 1 || p.MaxGrantSeconds > p.NotAfter-p.NotBefore || p.MaxBudgetSat < 0 || p.MaxBudgetSat > rootGrantsMaxMoney || !lowerHex(p.Seal.TxID, 32) {
		return fail("authority_mismatch")
	}
	return p, nil
}

// RootGrantsGrantV3Plan owns its exact PUBLIC snapshots. It contains no scalar,
// signing capability, confirmation or authentication context. All accessors
// return copies; an eventual helper must independently load/recheck authority.
type RootGrantsGrantV3Plan struct {
	grant, contract, authority, record []byte
	message                            [32]byte
}

func PrepareRootGrantsGrantV3(grant, contract, authority, metadata []byte, expectedOwner string, at time.Time) (*RootGrantsGrantV3Plan, error) {
	if len(grant) > 65536 || len(contract) > 65536 || len(authority) > 32768 || len(metadata) > 32768 {
		return nil, recoveryRefuse("limit_exceeded")
	}
	// Clone before parsing so every binding and later display uses the same owned
	// snapshot. Concurrent mutation by a caller is not an admitted input source.
	grant, contract, authority, metadata = bytes.Clone(grant), bytes.Clone(contract), bytes.Clone(authority), bytes.Clone(metadata)
	p, err := ParseRootGrantsAuthority(authority)
	if err != nil {
		return nil, err
	}
	if !rootGrantsOwnerPrincipal(expectedOwner) || p.OwnerPrincipal != expectedOwner {
		return nil, recoveryRefuse("authority_mismatch")
	}
	r, err := ParseRootGrantsRecord(metadata)
	if err != nil || rootGrantsHashHex(metadata) != p.Record.MetadataSHA256 || r.Service != p.Record.Service || r.Version != p.Record.Version ||
		r.PublicKey != p.Record.PublicKey || r.SealScript != p.Record.SealScript {
		return nil, recoveryRefuse("public_pin_mismatch")
	}
	g, err := ParseRootGrantsGrantV3(grant, at)
	if err != nil {
		return nil, err
	}
	budget := int64(0)
	if g.Budget != nil {
		budget = *g.Budget
	}
	if g.LandlordName != p.LandlordName || g.Network != p.Network || g.Genesis != p.Genesis || g.IssuerKey != p.Record.PublicKey ||
		g.AgentName != p.AgentName || g.GranteeKey != p.GranteeKey || g.GranteeName != p.GranteeName || g.Seal != p.Seal ||
		g.NotBefore < p.NotBefore || g.NotAfter > p.NotAfter || g.NotAfter-g.NotBefore > p.MaxGrantSeconds || budget > p.MaxBudgetSat ||
		at.Unix() < p.NotBefore || at.Unix() >= p.NotAfter || at.Unix() >= g.NotAfter {
		return nil, recoveryRefuse("authority_mismatch")
	}
	for _, scope := range g.Scope {
		if !slices.Contains(p.Scope, scope) {
			return nil, recoveryRefuse("authority_mismatch")
		}
	}
	if _, err := rootGrantsParseContractV1(contract, g, p.AgentKey); err != nil {
		return nil, err
	}
	hash, err := rootGrantsGrantV3Digest(grant)
	if err != nil {
		return nil, err
	}
	return &RootGrantsGrantV3Plan{grant: grant, contract: contract, authority: authority, record: metadata, message: hash}, nil
}

// ReviewJSON includes every complete document as a JSON value, not a truncated
// summary. It is a public display input, never proof of native presentation.
func (p *RootGrantsGrantV3Plan) ReviewJSON() ([]byte, error) {
	if p == nil || len(p.grant) == 0 {
		return nil, recoveryRefuse("operation_unavailable")
	}
	return json.Marshal(struct {
		Operation         string          `json:"operation"`
		Profile           string          `json:"profile"`
		ObservationPolicy string          `json:"observation_policy"`
		Grant             json.RawMessage `json:"grant"`
		Contract          json.RawMessage `json:"contract"`
		Authority         json.RawMessage `json:"authority"`
		Record            json.RawMessage `json:"record"`
		GrantBytes        int             `json:"grant_bytes"`
		ContractBytes     int             `json:"contract_bytes"`
		GrantSHA256       string          `json:"grant_sha256"`
		ContractSHA256    string          `json:"contract_sha256"`
		AuthoritySHA256   string          `json:"authority_sha256"`
		RecordSHA256      string          `json:"record_sha256"`
		MessageSHA256     string          `json:"message_sha256"`
	}{rootGrantsGrantV3Operation, rootGrantsProfile, RootGrantsOfflineReview, p.grant, p.contract, p.authority, p.record,
		len(p.grant), len(p.contract), rootGrantsHashHex(p.grant), rootGrantsHashHex(p.contract), rootGrantsHashHex(p.authority), rootGrantsHashHex(p.record), hex.EncodeToString(p.message[:])})
}

func (p *RootGrantsGrantV3Plan) VerifySignature(signature []byte) error {
	if p == nil {
		return recoveryRefuse("operation_unavailable")
	}
	var r RootGrantsRecord
	if DecodeSingleJSON(p.record, &r) != nil {
		return recoveryRefuse("private_protocol_error")
	}
	return rootGrantsVerifyGrantV3(p.grant, r.PublicKey, signature)
}
