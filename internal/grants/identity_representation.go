package grants

import "strings"

// These helpers consume representations only. Matrix v1.19 historical account
// consumption differs from new registration; the new grants wire additionally
// restricts all strings to printable ASCII. Exact enrolled account/device/key
// binding must still come from the authenticated trust and receiver boundary.
func parseMatrixAccountRepresentation(value string) (string, error) {
	if len(value) > 512 {
		return "", errInputLimit
	}
	if len(value) < 3 || len(value) > 255 || value[0] != '@' {
		return "", errBadSchema
	}
	for i := range value {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "", errBadSchema
		}
	}
	colon := strings.IndexByte(value, ':')
	if colon < 1 || !matrixServerRepresentation(value[colon+1:]) {
		return "", errBadSchema
	}
	return value, nil
}
func parseDeviceIDRepresentation(value string) (string, error) {
	if len(value) > 128 {
		return "", errInputLimit
	}
	if value == "" {
		return "", errBadSchema
	}
	for i := range value {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "", errBadSchema
		}
	}
	return value, nil
}

func matrixPortRepresentation(value string) bool {
	if len(value) < 1 || len(value) > 5 {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
func matrixIPv4Representation(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) < 1 || len(part) > 3 {
			return false
		}
		n := 0
		for i := range part {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
			n = n*10 + int(part[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
func matrixIPv6Units(value string, dotted bool) (int, bool) {
	if value == "" {
		return 0, true
	}
	parts := strings.Split(value, ":")
	units := 0
	for i, part := range parts {
		if strings.Contains(part, ".") {
			if !dotted || i != len(parts)-1 || !matrixIPv4Representation(part) {
				return 0, false
			}
			units += 2
			continue
		}
		if len(part) < 1 || len(part) > 4 {
			return 0, false
		}
		for j := range part {
			b := part[j]
			if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
				return 0, false
			}
		}
		units++
	}
	return units, true
}
func matrixIPv6Representation(value string) bool {
	if len(value) < 2 || len(value) > 45 {
		return false
	}
	if strings.Count(value, "::") > 1 {
		return false
	}
	if at := strings.Index(value, "::"); at >= 0 {
		left, okLeft := matrixIPv6Units(value[:at], false)
		right, okRight := matrixIPv6Units(value[at+2:], true)
		return okLeft && okRight && left+right < 8
	}
	units, ok := matrixIPv6Units(value, true)
	return ok && units == 8
}
func matrixServerRepresentation(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '[' {
		end := strings.IndexByte(value, ']')
		if end < 0 || !matrixIPv6Representation(value[1:end]) {
			return false
		}
		rest := value[end+1:]
		return rest == "" || rest[0] == ':' && matrixPortRepresentation(rest[1:])
	}
	host := value
	if at := strings.IndexByte(value, ':'); at >= 0 {
		host = value[:at]
		if !matrixPortRepresentation(value[at+1:]) {
			return false
		}
	}
	if len(host) < 1 || len(host) > 255 {
		return false
	}
	for i := range host {
		b := host[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '-' || b == '.') {
			return false
		}
	}
	// Numeric dotted quads are address literals and must satisfy their range;
	// invalid address components are never repaired or accepted as DNS aliases.
	parts := strings.Split(host, ".")
	numericQuad := len(parts) == 4
	for _, part := range parts {
		if part == "" {
			numericQuad = false
		}
		for i := range part {
			if part[i] < '0' || part[i] > '9' {
				numericQuad = false
			}
		}
	}
	return !numericQuad || matrixIPv4Representation(host)
}
