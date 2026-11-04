package grants

import "errors"

var (
	errBadEncoding = errors.New("bad-encoding")
	errInputLimit  = errors.New("input-limit-exceeded")
)

type wireProfile uint8

const (
	certificateWire wireProfile = iota + 1
	certificateEnvelopeWire
	requestWire
	resultWire
	revocationWire
	revocationEnvelopeWire
	localRequestEnvelopeWire
	localEnrollmentWire
)

type wireKind uint8

const (
	objectValue wireKind = iota + 1
	arrayValue
	stringValue
	booleanValue
	integerValue
)

type wireMember struct {
	name  string
	value *wireValue
}
type wireValue struct {
	kind     wireKind
	text     string
	boolean  bool
	members  []wireMember
	elements []*wireValue
}

type canonicalParser struct {
	raw      []byte
	position int
	tokens   int
	members  int
	profile  wireProfile
}

// parseCanonical checks only the NEW grants profile's lexical grammar and
// scanning budgets. It does not validate closed typed schemas, base64/DER,
// identity, time, signatures, receiver evidence or authority. Matrix plaintext
// uses a different grammar and must not pass through this scanner.
// The caller already holds raw; these limits do not bound earlier ingress or
// crypto allocation. No invalid input is repaired, normalized or reserialized.
func parseCanonical(raw []byte, profile wireProfile) (*wireValue, error) {
	maximum := 0
	switch profile {
	case certificateWire:
		maximum = 65536
	case certificateEnvelopeWire:
		maximum = 98304
	case requestWire, resultWire, revocationEnvelopeWire:
		maximum = 8192
	case revocationWire:
		maximum = 4096
	case localRequestEnvelopeWire:
		maximum = 12288
	case localEnrollmentWire:
		maximum = 8192
	default:
		return nil, errBadEncoding
	}
	if len(raw) > maximum {
		return nil, errInputLimit
	}
	parser := canonicalParser{raw: raw, profile: profile}
	node, err := parser.readValue(0, 1024)
	if err != nil {
		return nil, err
	}
	if parser.position != len(raw) {
		return nil, errBadEncoding
	}
	return node, nil
}

func (p *canonicalParser) takeToken() error {
	if p.tokens >= 4096 {
		return errInputLimit
	}
	p.tokens++
	return nil
}
func (p *canonicalParser) takeMember() error {
	if p.members >= 2048 {
		return errInputLimit
	}
	p.members++
	return nil
}
func (p *canonicalParser) at(value byte) bool {
	return p.position < len(p.raw) && p.raw[p.position] == value
}

func (p *canonicalParser) readValue(depth, stringLimit int) (*wireValue, error) {
	if p.position >= len(p.raw) {
		return nil, errBadEncoding
	}
	switch p.raw[p.position] {
	case '{':
		return p.readObject(depth + 1)
	case '[':
		return p.readArray(depth + 1)
	}
	if err := p.takeToken(); err != nil {
		return nil, err
	}
	switch p.raw[p.position] {
	case '"':
		text, err := p.readString(stringLimit)
		if err != nil {
			return nil, err
		}
		return &wireValue{kind: stringValue, text: text}, nil
	case 't':
		if len(p.raw)-p.position < 4 || string(p.raw[p.position:p.position+4]) != "true" {
			return nil, errBadEncoding
		}
		p.position += 4
		return &wireValue{kind: booleanValue, boolean: true}, nil
	case 'f':
		if len(p.raw)-p.position < 5 || string(p.raw[p.position:p.position+5]) != "false" {
			return nil, errBadEncoding
		}
		p.position += 5
		return &wireValue{kind: booleanValue}, nil
	default:
		start := p.position
		if p.at('0') {
			p.position++
			if p.position < len(p.raw) && p.raw[p.position] >= '0' && p.raw[p.position] <= '9' {
				return nil, errBadEncoding
			}
		} else {
			if p.raw[p.position] < '1' || p.raw[p.position] > '9' {
				return nil, errBadEncoding
			}
			for p.position < len(p.raw) && p.raw[p.position] >= '0' && p.raw[p.position] <= '9' {
				p.position++
			}
		}
		// Preserve integer spelling without float conversion. Initial typed
		// fields do not accept JSON numbers; that is a later schema refusal.
		return &wireValue{kind: integerValue, text: string(p.raw[start:p.position])}, nil
	}
}

func (p *canonicalParser) readString(limit int) (string, error) {
	if !p.at('"') {
		return "", errBadEncoding
	}
	p.position++
	var decoded []byte
	for p.position < len(p.raw) {
		value := p.raw[p.position]
		p.position++
		if value == '"' {
			return string(decoded), nil
		}
		if value == '\\' {
			if p.position >= len(p.raw) {
				return "", errBadEncoding
			}
			value = p.raw[p.position]
			p.position++
			if value != '"' && value != '\\' {
				return "", errBadEncoding
			}
		} else if value < 0x20 || value > 0x7e {
			return "", errBadEncoding
		}
		if len(decoded) >= limit {
			return "", errInputLimit
		}
		decoded = append(decoded, value)
	}
	return "", errBadEncoding
}

func (p *canonicalParser) fieldStringLimit(depth int, name string) int {
	if depth == 1 && p.profile == localRequestEnvelopeWire {
		if name == "payload" {
			return 10923
		}
		if name == "signature" {
			return 96
		}
	}
	if depth == 1 && p.profile == localEnrollmentWire && (name == "owner_spki" || name == "requester_spki") {
		return 1366
	}
	if depth == 1 && (p.profile == certificateEnvelopeWire || p.profile == revocationEnvelopeWire) {
		if name == "signature" {
			return 96
		}
		if name == "payload" {
			if p.profile == certificateEnvelopeWire {
				return 87382
			}
			return 5462
		}
	}
	return 1024
}

func (p *canonicalParser) readObject(depth int) (*wireValue, error) {
	if depth > 12 {
		return nil, errInputLimit
	}
	if err := p.takeToken(); err != nil {
		return nil, err
	}
	p.position++
	node := &wireValue{kind: objectValue}
	if !p.at('}') {
		for {
			if len(node.members) >= 16 {
				return nil, errInputLimit
			}
			if err := p.takeMember(); err != nil {
				return nil, err
			}
			if err := p.takeToken(); err != nil {
				return nil, err
			}
			name, err := p.readString(1024)
			if err != nil {
				return nil, err
			}
			if len(node.members) > 0 && name <= node.members[len(node.members)-1].name {
				return nil, errBadEncoding
			}
			if !p.at(':') {
				return nil, errBadEncoding
			}
			p.position++
			value, err := p.readValue(depth, p.fieldStringLimit(depth, name))
			if err != nil {
				return nil, err
			}
			node.members = append(node.members, wireMember{name: name, value: value})
			if !p.at(',') {
				break
			}
			p.position++
		}
	}
	if !p.at('}') {
		return nil, errBadEncoding
	}
	if err := p.takeToken(); err != nil {
		return nil, err
	}
	p.position++
	return node, nil
}

func (p *canonicalParser) readArray(depth int) (*wireValue, error) {
	if depth > 12 {
		return nil, errInputLimit
	}
	if err := p.takeToken(); err != nil {
		return nil, err
	}
	p.position++
	node := &wireValue{kind: arrayValue}
	if !p.at(']') {
		for {
			value, err := p.readValue(depth, 1024)
			if err != nil {
				return nil, err
			}
			node.elements = append(node.elements, value)
			if !p.at(',') {
				break
			}
			p.position++
		}
	}
	if !p.at(']') {
		return nil, errBadEncoding
	}
	if err := p.takeToken(); err != nil {
		return nil, err
	}
	p.position++
	return node, nil
}
