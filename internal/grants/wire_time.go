package grants

import (
	"errors"
	"time"
)

var errBadSchema = errors.New("bad-schema")

// parseWireTime checks the signed Time field spelling after lexical decoding.
// It accepts only real Gregorian UTC whole seconds in years1..9999. It reads
// no clock and supplies no interval, freshness or authority decision. Input
// aliases are refused, never trimmed, shifted, rounded or reserialized.
func parseWireTime(value string) (time.Time, error) {
	if len(value) != 20 {
		return time.Time{}, errBadSchema
	}
	for i := 0; i < len(value); i++ {
		switch i {
		case 4, 7:
			if value[i] != '-' {
				return time.Time{}, errBadSchema
			}
		case 10:
			if value[i] != 'T' {
				return time.Time{}, errBadSchema
			}
		case 13, 16:
			if value[i] != ':' {
				return time.Time{}, errBadSchema
			}
		case 19:
			if value[i] != 'Z' {
				return time.Time{}, errBadSchema
			}
		default:
			if value[i] < '0' || value[i] > '9' {
				return time.Time{}, errBadSchema
			}
		}
	}
	result, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || result.Year() < 1 || result.Year() > 9999 {
		return time.Time{}, errBadSchema
	}
	return result.UTC(), nil
}
