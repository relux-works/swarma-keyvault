package grants

import "encoding/base64"

// These helpers validate individual fields after the canonical scanner. They
// neither normalize identities nor validate a complete schema, enrollment,
// signatures, lifecycle state, receiver evidence or execution authority.
func parseOpaqueID(value string) (string, error) {
	if len(value) > 128 {
		return "", errInputLimit
	}
	if len(value) == 0 {
		return "", errBadSchema
	}
	alphanumeric := func(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
	if !alphanumeric(value[0]) {
		return "", errBadSchema
	}
	for i := 1; i < len(value); i++ {
		b := value[i]
		if !alphanumeric(b) && b != '.' && b != '_' && b != ':' && b != '/' && b != '-' {
			return "", errBadSchema
		}
	}
	return value, nil
}

func parseWireDigest(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != 64 {
		return result, errBadSchema
	}
	nibble := func(b byte) (byte, bool) {
		if b >= '0' && b <= '9' {
			return b - '0', true
		}
		if b >= 'a' && b <= 'f' {
			return b - 'a' + 10, true
		}
		return 0, false
	}
	for i := range result {
		high, okHigh := nibble(value[i*2])
		low, okLow := nibble(value[i*2+1])
		if !okHigh || !okLow {
			return [32]byte{}, errBadSchema
		}
		result[i] = high<<4 | low
	}
	return result, nil
}

func parsePositiveDecimal(value string) (uint64, error) {
	if len(value) == 0 || len(value) > 20 || value[0] < '1' || value[0] > '9' {
		return 0, errBadSchema
	}
	var result uint64
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b < '0' || b > '9' {
			return 0, errBadSchema
		}
		digit := uint64(b - '0')
		if result > (^uint64(0)-digit)/10 {
			return 0, errBadSchema
		}
		result = result*10 + digit
	}
	return result, nil
}

func parseDevicePublicBytes(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != 43 {
		return result, errBadSchema
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return result, errBadSchema
	}
	copy(result[:], decoded)
	return result, nil
}
