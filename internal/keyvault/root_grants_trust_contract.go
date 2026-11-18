package keyvault

import (
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	rootGrantsTrustContractProfile = "swarma-trust-contract/2"
	rootGrantsTrustContractMaxSize = 8192
	rootGrantsTrustRepoMaxSize     = 200
	rootGrantsTrustMaxBudget       = int64(2100000000000000)
)

var rootGrantsTrustContractMembers = [...]string{
	"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos",
	"spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal",
	"delegate", "note",
}

var rootGrantsTrustProfileV1Members = [...]string{
	"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos",
	"spend_budget", "not_before", "not_after", "note",
}

var rootGrantsTrustActions = [...]string{"instruct", "land", "review", "spend"}

var rootGrantsTrustDelegateMembers = [...]string{"depth", "actions", "budget", "slots", "notaries", "checkpoint"}
var rootGrantsTrustSlotMembers = [...]string{"executor", "grantee", "cap", "notary"}
var rootGrantsTrustNotaryMembers = [...]string{"name", "registration", "owner"}
var rootGrantsTrustRegistrationMembers = [...]string{"txid", "vout"}

// RootGrantsTrustContract is a parsed, untrusted public trust/2 document.
// Parsing it establishes no issuer, child-authorization, or service permission.
type RootGrantsTrustContract struct {
	Profile         string                  `json:"profile"`
	Network         string                  `json:"network"`
	LandlordName    string                  `json:"landlord_name"`
	AgentName       string                  `json:"agent_name"`
	GranteeKey      string                  `json:"grantee_key"`
	Actions         []string                `json:"actions"`
	Repos           []string                `json:"repos"`
	SpendBudget     int64                   `json:"spend_budget"`
	NotBefore       int64                   `json:"not_before"`
	NotAfter        int64                   `json:"not_after"`
	ScopeTextSHA256 string                  `json:"scope_text_sha256"`
	ParentGrantID   string                  `json:"parent_grant_id"`
	Ordinal         int64                   `json:"ordinal"`
	Delegate        RootGrantsTrustDelegate `json:"delegate"`
	Note            string                  `json:"note"`
}

// RootGrantsTrustDelegate is the LIP-0014 re-delegation object.
type RootGrantsTrustDelegate struct {
	Depth      int64                         `json:"depth"`
	Actions    []string                      `json:"actions"`
	Budget     int64                         `json:"budget"`
	Slots      []RootGrantsTrustDelegateSlot `json:"slots"`
	Notaries   []RootGrantsTrustNotary       `json:"notaries"`
	Checkpoint string                        `json:"checkpoint"`
}

// RootGrantsTrustDelegateSlot is one finite child row in a delegation right.
type RootGrantsTrustDelegateSlot struct {
	Executor string `json:"executor"`
	Grantee  string `json:"grantee"`
	Cap      int64  `json:"cap"`
	Notary   string `json:"notary"`
}

// RootGrantsTrustNotary is one public notary registration and owner pin.
type RootGrantsTrustNotary struct {
	Name         string                      `json:"name"`
	Registration RootGrantsTrustRegistration `json:"registration"`
	Owner        string                      `json:"owner"`
}

// RootGrantsTrustRegistration identifies the public registration output.
type RootGrantsTrustRegistration struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// RootGrantsTrustError identifies a local parser or binder refusal. Rule is
// 1–9 for LIP findings and 0 for non-LIP public binding findings.
type RootGrantsTrustError struct {
	Code string
	Rule int
}

func (e *RootGrantsTrustError) Error() string {
	return "root trust contract refused"
}

func rootGrantsTrustFailure(code string, rule int) error {
	return &RootGrantsTrustError{Code: code, Rule: rule}
}

// ParseRootGrantsTrustContract accepts only exact canonical trust/2 bytes and
// reports the first local LIP-0014 finding. The input is read without mutation.
func ParseRootGrantsTrustContract(raw []byte) (RootGrantsTrustContract, error) {
	if len(raw) == 0 || len(raw) > rootGrantsTrustContractMaxSize {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}

	root, ok := rootGrantsTrustParseDocument(raw)
	if !ok || root.kind != rootGrantsTrustJSONObject || rootGrantsTrustHasRule1DuplicateMembers(root) || rootGrantsTrustHasRule1Literal(root) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}

	memberNames := rootGrantsTrustObjectNames(root)
	if slices.Equal(memberNames, rootGrantsTrustProfileV1Members[:]) {
		if !rootGrantsTrustTopLevelTypesMatch(root, memberNames) {
			return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
		}
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_PROFILE", 2)
	}
	if !slices.Equal(memberNames, rootGrantsTrustContractMembers[:]) || !rootGrantsTrustTopLevelTypesMatch(root, rootGrantsTrustContractMembers[:]) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}

	var c RootGrantsTrustContract
	c.Profile = rootGrantsTrustStringField(root, "profile")
	c.Network = rootGrantsTrustStringField(root, "network")
	c.LandlordName = rootGrantsTrustStringField(root, "landlord_name")
	c.AgentName = rootGrantsTrustStringField(root, "agent_name")
	c.GranteeKey = rootGrantsTrustStringField(root, "grantee_key")
	c.SpendBudget = rootGrantsTrustIntegerField(root, "spend_budget")
	c.NotBefore = rootGrantsTrustIntegerField(root, "not_before")
	c.NotAfter = rootGrantsTrustIntegerField(root, "not_after")
	c.ScopeTextSHA256 = rootGrantsTrustStringField(root, "scope_text_sha256")
	c.ParentGrantID = rootGrantsTrustStringField(root, "parent_grant_id")
	c.Ordinal = rootGrantsTrustIntegerField(root, "ordinal")
	c.Note = rootGrantsTrustStringField(root, "note")

	if c.Profile != rootGrantsTrustContractProfile {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_PROFILE", 2)
	}
	if (c.Network != "main" && c.Network != "regtest") || !rootGrantsGrantName(c.LandlordName) ||
		!rootGrantsGrantName(c.AgentName) || c.AgentName == c.LandlordName || !rootGrantsGrantKey(c.GranteeKey) ||
		(c.ScopeTextSHA256 != "" && !lowerHex(c.ScopeTextSHA256, 32)) || c.NotBefore > rootGrantsLastUnixSecond ||
		c.NotAfter <= c.NotBefore || c.NotAfter > rootGrantsLastUnixSecond {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_FIELD", 3)
	}

	var actionsOK bool
	c.Actions, actionsOK = rootGrantsTrustStringArray(rootGrantsTrustField(root, "actions"))
	if !actionsOK || !rootGrantsTrustActionsValid(c.Actions) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_ACTIONS", 4)
	}
	var reposOK bool
	c.Repos, reposOK = rootGrantsTrustStringArray(rootGrantsTrustField(root, "repos"))
	if !reposOK || !rootGrantsTrustReposValid(c.Repos, c.Actions) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_REPOS", 5)
	}
	if c.SpendBudget < 0 || c.SpendBudget > rootGrantsTrustMaxBudget ||
		(slices.Contains(c.Actions, "spend") != (c.SpendBudget > 0)) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_BUDGET", 6)
	}
	if len(c.Note) > 280 {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_NOTE", 7)
	}

	delegateValue := rootGrantsTrustField(root, "delegate")
	depth, depthReadable := rootGrantsTrustFirstDelegateDepth(delegateValue)
	parentValid := c.ParentGrantID == "" || lowerHex(c.ParentGrantID, 32)
	ordinalValid := c.Ordinal >= 0 && c.Ordinal <= 16
	parentOrdinalMatch := (c.ParentGrantID == "") == (c.Ordinal == 0)
	if !parentValid || !ordinalValid || !parentOrdinalMatch ||
		(c.ParentGrantID != "" && depthReadable && depth != 0) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_PARENT", 8)
	}

	delegateOuterShape, delegateDepth, notaryCount := rootGrantsTrustDelegateOuterShape(delegateValue)
	if !delegateOuterShape {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_DELEGATE", 9)
	}
	if delegateDepth == 1 && notaryCount == 0 {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("DELEGATE_NO_NOTARY", 9)
	}
	if !rootGrantsTrustDelegateNestedShape(delegateValue) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_DELEGATE", 9)
	}
	var delegateOK bool
	c.Delegate, delegateOK = rootGrantsTrustDecodeDelegate(delegateValue)
	if !delegateOK {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_DELEGATE", 9)
	}
	if !rootGrantsTrustDelegateValid(c.Delegate, c.Actions, c.LandlordName) {
		return RootGrantsTrustContract{}, rootGrantsTrustFailure("CONTRACT_DELEGATE", 9)
	}
	return c, nil
}

// CanonicalRootGrantsTrustContract returns a fresh canonical serialization of
// a model that satisfies the trust/2 grammar and LIP-0014 rules.
func CanonicalRootGrantsTrustContract(c RootGrantsTrustContract) ([]byte, error) {
	if err := rootGrantsTrustModelValid(c); err != nil {
		return nil, err
	}
	encoded, ok := rootGrantsTrustEncode(c)
	if !ok || len(encoded) > rootGrantsTrustContractMaxSize {
		return nil, rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}
	return encoded, nil
}

type rootGrantsTrustJSONKind uint8

const (
	rootGrantsTrustJSONObject rootGrantsTrustJSONKind = iota + 1
	rootGrantsTrustJSONArray
	rootGrantsTrustJSONString
	rootGrantsTrustJSONInteger
	rootGrantsTrustJSONOther
)

type rootGrantsTrustJSONMember struct {
	name  string
	value rootGrantsTrustJSON
}

type rootGrantsTrustJSON struct {
	kind    rootGrantsTrustJSONKind
	object  []rootGrantsTrustJSONMember
	array   []rootGrantsTrustJSON
	text    string
	integer int64
}

type rootGrantsTrustJSONParser struct {
	raw []byte
	i   int
}

func rootGrantsTrustParseDocument(raw []byte) (rootGrantsTrustJSON, bool) {
	p := rootGrantsTrustJSONParser{raw: raw}
	value, ok := p.value()
	return value, ok && p.i == len(raw)
}

func (p *rootGrantsTrustJSONParser) value() (rootGrantsTrustJSON, bool) {
	if p.i >= len(p.raw) {
		return rootGrantsTrustJSON{}, false
	}
	switch p.raw[p.i] {
	case '{':
		return p.objectValue()
	case '[':
		return p.arrayValue()
	case '"':
		value, ok := p.stringValue()
		return rootGrantsTrustJSON{kind: rootGrantsTrustJSONString, text: value}, ok
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		value, ok := p.integerValue()
		return rootGrantsTrustJSON{kind: rootGrantsTrustJSONInteger, integer: value}, ok
	case 't':
		return p.literalValue("true")
	case 'f':
		return p.literalValue("false")
	case 'n':
		return p.literalValue("null")
	default:
		return rootGrantsTrustJSON{}, false
	}
}

func (p *rootGrantsTrustJSONParser) literalValue(literal string) (rootGrantsTrustJSON, bool) {
	if len(p.raw)-p.i < len(literal) || string(p.raw[p.i:p.i+len(literal)]) != literal {
		return rootGrantsTrustJSON{}, false
	}
	p.i += len(literal)
	return rootGrantsTrustJSON{kind: rootGrantsTrustJSONOther}, true
}

func (p *rootGrantsTrustJSONParser) objectValue() (rootGrantsTrustJSON, bool) {
	p.i++
	value := rootGrantsTrustJSON{kind: rootGrantsTrustJSONObject, object: make([]rootGrantsTrustJSONMember, 0)}
	if p.i < len(p.raw) && p.raw[p.i] == '}' {
		p.i++
		return value, true
	}
	for {
		if p.i >= len(p.raw) || p.raw[p.i] != '"' {
			return rootGrantsTrustJSON{}, false
		}
		name, ok := p.stringValue()
		if !ok || p.i >= len(p.raw) || p.raw[p.i] != ':' {
			return rootGrantsTrustJSON{}, false
		}
		p.i++
		memberValue, ok := p.value()
		if !ok {
			return rootGrantsTrustJSON{}, false
		}
		value.object = append(value.object, rootGrantsTrustJSONMember{name: name, value: memberValue})
		if p.i >= len(p.raw) {
			return rootGrantsTrustJSON{}, false
		}
		switch p.raw[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return value, true
		default:
			return rootGrantsTrustJSON{}, false
		}
	}
}

func (p *rootGrantsTrustJSONParser) arrayValue() (rootGrantsTrustJSON, bool) {
	p.i++
	value := rootGrantsTrustJSON{kind: rootGrantsTrustJSONArray, array: make([]rootGrantsTrustJSON, 0)}
	if p.i < len(p.raw) && p.raw[p.i] == ']' {
		p.i++
		return value, true
	}
	for {
		item, ok := p.value()
		if !ok {
			return rootGrantsTrustJSON{}, false
		}
		value.array = append(value.array, item)
		if p.i >= len(p.raw) {
			return rootGrantsTrustJSON{}, false
		}
		switch p.raw[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return value, true
		default:
			return rootGrantsTrustJSON{}, false
		}
	}
}

func (p *rootGrantsTrustJSONParser) stringValue() (string, bool) {
	p.i++
	value := make([]byte, 0)
	for p.i < len(p.raw) {
		b := p.raw[p.i]
		p.i++
		switch {
		case b == '"':
			return string(value), true
		case b == '\\':
			if p.i >= len(p.raw) || (p.raw[p.i] != '"' && p.raw[p.i] != '\\') {
				return "", false
			}
			value = append(value, p.raw[p.i])
			p.i++
		case b < 0x20 || b > 0x7e:
			return "", false
		default:
			value = append(value, b)
		}
	}
	return "", false
}

func (p *rootGrantsTrustJSONParser) integerValue() (int64, bool) {
	start := p.i
	if p.raw[p.i] == '0' {
		p.i++
		if p.i < len(p.raw) && p.raw[p.i] >= '0' && p.raw[p.i] <= '9' {
			return 0, false
		}
	} else {
		for p.i < len(p.raw) && p.raw[p.i] >= '0' && p.raw[p.i] <= '9' {
			p.i++
		}
	}
	value, err := strconv.ParseInt(string(p.raw[start:p.i]), 10, 64)
	return value, err == nil
}

func rootGrantsTrustHasDuplicateMembers(value rootGrantsTrustJSON) bool {
	switch value.kind {
	case rootGrantsTrustJSONObject:
		seen := make(map[string]struct{}, len(value.object))
		for _, member := range value.object {
			if _, exists := seen[member.name]; exists {
				return true
			}
			seen[member.name] = struct{}{}
			if rootGrantsTrustHasDuplicateMembers(member.value) {
				return true
			}
		}
	case rootGrantsTrustJSONArray:
		for _, item := range value.array {
			if rootGrantsTrustHasDuplicateMembers(item) {
				return true
			}
		}
	}
	return false
}

func rootGrantsTrustHasRule1DuplicateMembers(root rootGrantsTrustJSON) bool {
	seen := make(map[string]struct{}, len(root.object))
	for _, member := range root.object {
		if _, exists := seen[member.name]; exists {
			return true
		}
		seen[member.name] = struct{}{}
		if member.name != "delegate" && rootGrantsTrustHasDuplicateMembers(member.value) {
			return true
		}
	}
	return false
}

// Rule 1 owns null and boolean values outside delegate; delegate type ownership
// remains with rule 9, including its nested rows.
func rootGrantsTrustHasRule1Literal(root rootGrantsTrustJSON) bool {
	for _, member := range root.object {
		if member.name == "delegate" {
			continue
		}
		if rootGrantsTrustContainsOtherLiteral(member.value) {
			return true
		}
	}
	return false
}

func rootGrantsTrustContainsOtherLiteral(value rootGrantsTrustJSON) bool {
	if value.kind == rootGrantsTrustJSONOther {
		return true
	}
	for _, member := range value.object {
		if rootGrantsTrustContainsOtherLiteral(member.value) {
			return true
		}
	}
	for _, item := range value.array {
		if rootGrantsTrustContainsOtherLiteral(item) {
			return true
		}
	}
	return false
}

func rootGrantsTrustObjectNames(value rootGrantsTrustJSON) []string {
	names := make([]string, 0, len(value.object))
	for _, member := range value.object {
		names = append(names, member.name)
	}
	return names
}

func rootGrantsTrustTopLevelTypesMatch(root rootGrantsTrustJSON, members []string) bool {
	for _, name := range members {
		field := rootGrantsTrustField(root, name)
		switch name {
		case "profile", "network", "landlord_name", "agent_name", "grantee_key", "scope_text_sha256", "parent_grant_id", "note":
			if field.kind != rootGrantsTrustJSONString {
				return false
			}
		case "actions", "repos":
			if field.kind != rootGrantsTrustJSONArray {
				return false
			}
		case "spend_budget", "not_before", "not_after", "ordinal":
			if field.kind != rootGrantsTrustJSONInteger {
				return false
			}
		case "delegate":
			// Rule 9 owns every delegate type and value.
		default:
			return false
		}
	}
	return true
}

func rootGrantsTrustField(root rootGrantsTrustJSON, name string) rootGrantsTrustJSON {
	for _, member := range root.object {
		if member.name == name {
			return member.value
		}
	}
	return rootGrantsTrustJSON{}
}

func rootGrantsTrustStringField(root rootGrantsTrustJSON, name string) string {
	return rootGrantsTrustField(root, name).text
}

func rootGrantsTrustIntegerField(root rootGrantsTrustJSON, name string) int64 {
	return rootGrantsTrustField(root, name).integer
}

func rootGrantsTrustStringArray(value rootGrantsTrustJSON) ([]string, bool) {
	if value.kind != rootGrantsTrustJSONArray {
		return nil, false
	}
	items := make([]string, 0, len(value.array))
	for _, item := range value.array {
		if item.kind != rootGrantsTrustJSONString {
			return nil, false
		}
		items = append(items, item.text)
	}
	return items, true
}

func rootGrantsTrustActionsValid(actions []string) bool {
	if actions == nil || len(actions) == 0 || !slices.IsSorted(actions) {
		return false
	}
	for i, action := range actions {
		if !slices.Contains(rootGrantsTrustActions[:], action) || (i > 0 && actions[i-1] == action) {
			return false
		}
	}
	return true
}

func rootGrantsTrustReposValid(repos, actions []string) bool {
	land := slices.Contains(actions, "land")
	if repos == nil || len(repos) > 16 || (land != (len(repos) > 0)) || !slices.IsSorted(repos) {
		return false
	}
	for i, repo := range repos {
		if !rootGrantsTrustRepository(repo) || (i > 0 && repos[i-1] == repo) {
			return false
		}
	}
	return true
}

func rootGrantsTrustRepository(value string) bool {
	if len(value) == 0 || len(value) > rootGrantsTrustRepoMaxSize || !strings.HasPrefix(value, "https://") {
		return false
	}
	rest := value[len("https://"):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return false
	}
	host, path := rest[:slash], rest[slash+1:]
	if len(host) > 253 || strings.ContainsAny(host, "@:?#%") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, b := range []byte(segment) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
				return false
			}
		}
	}
	return true
}

func rootGrantsTrustFirstDelegateDepth(value rootGrantsTrustJSON) (int64, bool) {
	if value.kind != rootGrantsTrustJSONObject || len(value.object) == 0 || value.object[0].name != "depth" || value.object[0].value.kind != rootGrantsTrustJSONInteger {
		return 0, false
	}
	return value.object[0].value.integer, true
}

func rootGrantsTrustDelegateOuterShape(value rootGrantsTrustJSON) (bool, int64, int) {
	if value.kind != rootGrantsTrustJSONObject || !slices.Equal(rootGrantsTrustObjectNames(value), rootGrantsTrustDelegateMembers[:]) {
		return false, 0, 0
	}
	depth := rootGrantsTrustField(value, "depth")
	actions := rootGrantsTrustField(value, "actions")
	budget := rootGrantsTrustField(value, "budget")
	slots := rootGrantsTrustField(value, "slots")
	notaries := rootGrantsTrustField(value, "notaries")
	checkpoint := rootGrantsTrustField(value, "checkpoint")
	if depth.kind != rootGrantsTrustJSONInteger || actions.kind != rootGrantsTrustJSONArray || budget.kind != rootGrantsTrustJSONInteger ||
		slots.kind != rootGrantsTrustJSONArray || notaries.kind != rootGrantsTrustJSONArray || checkpoint.kind != rootGrantsTrustJSONString {
		return false, 0, 0
	}
	return true, depth.integer, len(notaries.array)
}

func rootGrantsTrustDelegateShape(value rootGrantsTrustJSON) (bool, int64, int) {
	outerShape, depth, notaryCount := rootGrantsTrustDelegateOuterShape(value)
	return outerShape && rootGrantsTrustDelegateNestedShape(value), depth, notaryCount
}

func rootGrantsTrustDelegateNestedShape(value rootGrantsTrustJSON) bool {
	if value.kind != rootGrantsTrustJSONObject {
		return false
	}
	for _, slot := range rootGrantsTrustField(value, "slots").array {
		if !rootGrantsTrustSlotShape(slot) {
			return false
		}
	}
	for _, notary := range rootGrantsTrustField(value, "notaries").array {
		if !rootGrantsTrustNotaryShape(notary) {
			return false
		}
	}
	return true
}

func rootGrantsTrustSlotShape(value rootGrantsTrustJSON) bool {
	if value.kind != rootGrantsTrustJSONObject || !slices.Equal(rootGrantsTrustObjectNames(value), rootGrantsTrustSlotMembers[:]) {
		return false
	}
	return rootGrantsTrustField(value, "executor").kind == rootGrantsTrustJSONString &&
		rootGrantsTrustField(value, "grantee").kind == rootGrantsTrustJSONString &&
		rootGrantsTrustField(value, "cap").kind == rootGrantsTrustJSONInteger &&
		rootGrantsTrustField(value, "notary").kind == rootGrantsTrustJSONString
}

func rootGrantsTrustNotaryShape(value rootGrantsTrustJSON) bool {
	if value.kind != rootGrantsTrustJSONObject || !slices.Equal(rootGrantsTrustObjectNames(value), rootGrantsTrustNotaryMembers[:]) {
		return false
	}
	name := rootGrantsTrustField(value, "name")
	registration := rootGrantsTrustField(value, "registration")
	owner := rootGrantsTrustField(value, "owner")
	if name.kind != rootGrantsTrustJSONString || registration.kind != rootGrantsTrustJSONObject || owner.kind != rootGrantsTrustJSONString ||
		!slices.Equal(rootGrantsTrustObjectNames(registration), rootGrantsTrustRegistrationMembers[:]) {
		return false
	}
	return rootGrantsTrustField(registration, "txid").kind == rootGrantsTrustJSONString &&
		rootGrantsTrustField(registration, "vout").kind == rootGrantsTrustJSONInteger
}

func rootGrantsTrustDecodeDelegate(value rootGrantsTrustJSON) (RootGrantsTrustDelegate, bool) {
	shape, _, _ := rootGrantsTrustDelegateShape(value)
	if !shape {
		return RootGrantsTrustDelegate{}, false
	}
	depth := rootGrantsTrustField(value, "depth")
	actions := rootGrantsTrustField(value, "actions")
	budget := rootGrantsTrustField(value, "budget")
	slots := rootGrantsTrustField(value, "slots")
	notaries := rootGrantsTrustField(value, "notaries")
	checkpoint := rootGrantsTrustField(value, "checkpoint")
	if depth.kind != rootGrantsTrustJSONInteger || actions.kind != rootGrantsTrustJSONArray || budget.kind != rootGrantsTrustJSONInteger ||
		slots.kind != rootGrantsTrustJSONArray || notaries.kind != rootGrantsTrustJSONArray || checkpoint.kind != rootGrantsTrustJSONString {
		return RootGrantsTrustDelegate{}, false
	}
	delegate := RootGrantsTrustDelegate{Depth: depth.integer, Budget: budget.integer, Checkpoint: checkpoint.text}
	var ok bool
	delegate.Actions, ok = rootGrantsTrustStringArray(actions)
	if !ok {
		return RootGrantsTrustDelegate{}, false
	}
	delegate.Slots = make([]RootGrantsTrustDelegateSlot, 0, len(slots.array))
	for _, slotValue := range slots.array {
		slot, slotOK := rootGrantsTrustDecodeSlot(slotValue)
		if !slotOK {
			return RootGrantsTrustDelegate{}, false
		}
		delegate.Slots = append(delegate.Slots, slot)
	}
	delegate.Notaries = make([]RootGrantsTrustNotary, 0, len(notaries.array))
	for _, notaryValue := range notaries.array {
		notary, notaryOK := rootGrantsTrustDecodeNotary(notaryValue)
		if !notaryOK {
			return RootGrantsTrustDelegate{}, false
		}
		delegate.Notaries = append(delegate.Notaries, notary)
	}
	return delegate, true
}

func rootGrantsTrustDecodeSlot(value rootGrantsTrustJSON) (RootGrantsTrustDelegateSlot, bool) {
	if value.kind != rootGrantsTrustJSONObject || !slices.Equal(rootGrantsTrustObjectNames(value), rootGrantsTrustSlotMembers[:]) {
		return RootGrantsTrustDelegateSlot{}, false
	}
	executor := rootGrantsTrustField(value, "executor")
	grantee := rootGrantsTrustField(value, "grantee")
	capValue := rootGrantsTrustField(value, "cap")
	notary := rootGrantsTrustField(value, "notary")
	if executor.kind != rootGrantsTrustJSONString || grantee.kind != rootGrantsTrustJSONString || capValue.kind != rootGrantsTrustJSONInteger || notary.kind != rootGrantsTrustJSONString {
		return RootGrantsTrustDelegateSlot{}, false
	}
	return RootGrantsTrustDelegateSlot{Executor: executor.text, Grantee: grantee.text, Cap: capValue.integer, Notary: notary.text}, true
}

func rootGrantsTrustDecodeNotary(value rootGrantsTrustJSON) (RootGrantsTrustNotary, bool) {
	if value.kind != rootGrantsTrustJSONObject || !slices.Equal(rootGrantsTrustObjectNames(value), rootGrantsTrustNotaryMembers[:]) {
		return RootGrantsTrustNotary{}, false
	}
	name := rootGrantsTrustField(value, "name")
	registration := rootGrantsTrustField(value, "registration")
	owner := rootGrantsTrustField(value, "owner")
	if name.kind != rootGrantsTrustJSONString || registration.kind != rootGrantsTrustJSONObject || owner.kind != rootGrantsTrustJSONString ||
		!slices.Equal(rootGrantsTrustObjectNames(registration), rootGrantsTrustRegistrationMembers[:]) {
		return RootGrantsTrustNotary{}, false
	}
	txid := rootGrantsTrustField(registration, "txid")
	vout := rootGrantsTrustField(registration, "vout")
	if txid.kind != rootGrantsTrustJSONString || vout.kind != rootGrantsTrustJSONInteger || vout.integer < 0 || vout.integer > int64(^uint32(0)) {
		return RootGrantsTrustNotary{}, false
	}
	return RootGrantsTrustNotary{
		Name:         name.text,
		Registration: RootGrantsTrustRegistration{TxID: txid.text, Vout: uint32(vout.integer)},
		Owner:        owner.text,
	}, true
}

func rootGrantsTrustDelegateValid(delegate RootGrantsTrustDelegate, parentActions []string, landlord string) bool {
	if delegate.Depth == 0 {
		return len(delegate.Actions) == 0 && delegate.Budget == 0 && len(delegate.Slots) == 0 && len(delegate.Notaries) == 0 && delegate.Checkpoint == ""
	}
	if delegate.Depth != 1 || len(delegate.Actions) == 0 || !slices.IsSorted(delegate.Actions) ||
		delegate.Budget != 0 || len(delegate.Slots) == 0 || len(delegate.Slots) > 16 || len(delegate.Notaries) == 0 || len(delegate.Notaries) > 4 ||
		!lowerHex(delegate.Checkpoint, 32) {
		return false
	}
	for i, action := range delegate.Actions {
		if !slices.Contains(rootGrantsTrustActions[:], action) || action == "spend" || !slices.Contains(parentActions, action) || (i > 0 && delegate.Actions[i-1] == action) {
			return false
		}
	}
	notaryNames := make([]string, 0, len(delegate.Notaries))
	for i, notary := range delegate.Notaries {
		if !rootGrantsGrantName(notary.Name) || !lowerHex(notary.Registration.TxID, 32) || !rootGrantsTrustCompressedKey(notary.Owner) ||
			(i > 0 && delegate.Notaries[i-1].Name >= notary.Name) {
			return false
		}
		notaryNames = append(notaryNames, notary.Name)
	}
	for _, slot := range delegate.Slots {
		if !rootGrantsGrantName(slot.Executor) || slot.Executor == landlord || !rootGrantsGrantKey(slot.Grantee) || slot.Cap != 0 ||
			!slices.Contains(notaryNames, slot.Notary) {
			return false
		}
	}
	return true
}

func rootGrantsTrustCompressedKey(value string) bool {
	if len(value) != 66 || (value[:2] != "02" && value[:2] != "03") || !lowerHex(value, 33) {
		return false
	}
	encoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	_, err = btcec.ParsePubKey(encoded)
	return err == nil
}

func rootGrantsTrustModelValid(c RootGrantsTrustContract) error {
	if c.Actions == nil || c.Repos == nil || c.Delegate.Actions == nil || c.Delegate.Slots == nil || c.Delegate.Notaries == nil ||
		!rootGrantsTrustStringsASCII(c.Profile, c.Network, c.LandlordName, c.AgentName, c.GranteeKey, c.ScopeTextSHA256, c.ParentGrantID, c.Note, c.Delegate.Checkpoint) ||
		!rootGrantsTrustStringsASCII(c.Actions...) || !rootGrantsTrustStringsASCII(c.Repos...) || !rootGrantsTrustStringsASCII(c.Delegate.Actions...) {
		return rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}
	for _, slot := range c.Delegate.Slots {
		if slot.Cap < 0 || !rootGrantsTrustStringsASCII(slot.Executor, slot.Grantee, slot.Notary) {
			return rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
		}
	}
	for _, notary := range c.Delegate.Notaries {
		if !rootGrantsTrustStringsASCII(notary.Name, notary.Registration.TxID, notary.Owner) {
			return rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
		}
	}
	if c.SpendBudget < 0 || c.NotBefore < 0 || c.NotAfter < 0 || c.Ordinal < 0 || c.Delegate.Depth < 0 || c.Delegate.Budget < 0 {
		return rootGrantsTrustFailure("CONTRACT_ENCODING", 1)
	}
	if c.Profile != rootGrantsTrustContractProfile {
		return rootGrantsTrustFailure("CONTRACT_PROFILE", 2)
	}
	if (c.Network != "main" && c.Network != "regtest") || !rootGrantsGrantName(c.LandlordName) || !rootGrantsGrantName(c.AgentName) ||
		c.AgentName == c.LandlordName || !rootGrantsGrantKey(c.GranteeKey) || (c.ScopeTextSHA256 != "" && !lowerHex(c.ScopeTextSHA256, 32)) ||
		c.NotBefore > rootGrantsLastUnixSecond || c.NotAfter <= c.NotBefore || c.NotAfter > rootGrantsLastUnixSecond {
		return rootGrantsTrustFailure("CONTRACT_FIELD", 3)
	}
	if !rootGrantsTrustActionsValid(c.Actions) {
		return rootGrantsTrustFailure("CONTRACT_ACTIONS", 4)
	}
	if !rootGrantsTrustReposValid(c.Repos, c.Actions) {
		return rootGrantsTrustFailure("CONTRACT_REPOS", 5)
	}
	if c.SpendBudget > rootGrantsTrustMaxBudget || (slices.Contains(c.Actions, "spend") != (c.SpendBudget > 0)) {
		return rootGrantsTrustFailure("CONTRACT_BUDGET", 6)
	}
	if len(c.Note) > 280 {
		return rootGrantsTrustFailure("CONTRACT_NOTE", 7)
	}
	if (c.ParentGrantID != "" && !lowerHex(c.ParentGrantID, 32)) || c.Ordinal > 16 ||
		((c.ParentGrantID == "") != (c.Ordinal == 0)) || (c.ParentGrantID != "" && c.Delegate.Depth != 0) {
		return rootGrantsTrustFailure("CONTRACT_PARENT", 8)
	}
	if c.Delegate.Depth == 1 && len(c.Delegate.Notaries) == 0 {
		return rootGrantsTrustFailure("DELEGATE_NO_NOTARY", 9)
	}
	if !rootGrantsTrustDelegateValid(c.Delegate, c.Actions, c.LandlordName) {
		return rootGrantsTrustFailure("CONTRACT_DELEGATE", 9)
	}
	return nil
}

func rootGrantsTrustStringsASCII(values ...string) bool {
	for _, value := range values {
		for _, b := range []byte(value) {
			if b < 0x20 || b > 0x7e {
				return false
			}
		}
	}
	return true
}

func rootGrantsTrustEncode(c RootGrantsTrustContract) ([]byte, bool) {
	out := make([]byte, 0, 1024)
	appendString := func(value string) bool {
		var ok bool
		out, ok = rootGrantsTrustAppendString(out, value)
		return ok
	}
	appendStrings := func(values []string) bool {
		out = append(out, '[')
		for i, value := range values {
			if i > 0 {
				out = append(out, ',')
			}
			if !appendString(value) {
				return false
			}
		}
		out = append(out, ']')
		return true
	}
	out = append(out, `{"profile":`...)
	if !appendString(c.Profile) {
		return nil, false
	}
	out = append(out, `,"network":`...)
	if !appendString(c.Network) {
		return nil, false
	}
	out = append(out, `,"landlord_name":`...)
	if !appendString(c.LandlordName) {
		return nil, false
	}
	out = append(out, `,"agent_name":`...)
	if !appendString(c.AgentName) {
		return nil, false
	}
	out = append(out, `,"grantee_key":`...)
	if !appendString(c.GranteeKey) {
		return nil, false
	}
	out = append(out, `,"actions":`...)
	if !appendStrings(c.Actions) {
		return nil, false
	}
	out = append(out, `,"repos":`...)
	if !appendStrings(c.Repos) {
		return nil, false
	}
	out = append(out, `,"spend_budget":`...)
	out = strconv.AppendInt(out, c.SpendBudget, 10)
	out = append(out, `,"not_before":`...)
	out = strconv.AppendInt(out, c.NotBefore, 10)
	out = append(out, `,"not_after":`...)
	out = strconv.AppendInt(out, c.NotAfter, 10)
	out = append(out, `,"scope_text_sha256":`...)
	if !appendString(c.ScopeTextSHA256) {
		return nil, false
	}
	out = append(out, `,"parent_grant_id":`...)
	if !appendString(c.ParentGrantID) {
		return nil, false
	}
	out = append(out, `,"ordinal":`...)
	out = strconv.AppendInt(out, c.Ordinal, 10)
	out = append(out, `,"delegate":{"depth":`...)
	out = strconv.AppendInt(out, c.Delegate.Depth, 10)
	out = append(out, `,"actions":`...)
	if !appendStrings(c.Delegate.Actions) {
		return nil, false
	}
	out = append(out, `,"budget":`...)
	out = strconv.AppendInt(out, c.Delegate.Budget, 10)
	out = append(out, `,"slots":[`...)
	for i, slot := range c.Delegate.Slots {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, `{"executor":`...)
		if !appendString(slot.Executor) {
			return nil, false
		}
		out = append(out, `,"grantee":`...)
		if !appendString(slot.Grantee) {
			return nil, false
		}
		out = append(out, `,"cap":`...)
		out = strconv.AppendInt(out, slot.Cap, 10)
		out = append(out, `,"notary":`...)
		if !appendString(slot.Notary) {
			return nil, false
		}
		out = append(out, '}')
	}
	out = append(out, `],"notaries":[`...)
	for i, notary := range c.Delegate.Notaries {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, `{"name":`...)
		if !appendString(notary.Name) {
			return nil, false
		}
		out = append(out, `,"registration":{"txid":`...)
		if !appendString(notary.Registration.TxID) {
			return nil, false
		}
		out = append(out, `,"vout":`...)
		out = strconv.AppendUint(out, uint64(notary.Registration.Vout), 10)
		out = append(out, `},"owner":`...)
		if !appendString(notary.Owner) {
			return nil, false
		}
		out = append(out, '}')
	}
	out = append(out, `],"checkpoint":`...)
	if !appendString(c.Delegate.Checkpoint) {
		return nil, false
	}
	out = append(out, `},"note":`...)
	if !appendString(c.Note) {
		return nil, false
	}
	out = append(out, '}')
	return out, true
}

func rootGrantsTrustAppendString(out []byte, value string) ([]byte, bool) {
	out = append(out, '"')
	for _, b := range []byte(value) {
		if b < 0x20 || b > 0x7e {
			return nil, false
		}
		if b == '"' || b == '\\' {
			out = append(out, '\\')
		}
		out = append(out, b)
	}
	return append(out, '"'), true
}
