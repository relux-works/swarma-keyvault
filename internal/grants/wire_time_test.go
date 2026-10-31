package grants

import (
	"errors"
	"testing"
	"time"
)

// Literal field values prove these representative real Gregorian instants are
// preserved as whole UTC seconds. Year1 is allowed even though it is Go's zero
// Time value. No clock trust, interval authority or whole-wire verdict is tested.
func TestParseWireTimeControls(t *testing.T) {
	tests := []struct {
		raw                       string
		year                      int
		month                     time.Month
		day, hour, minute, second int
	}{
		{"2026-10-31T12:34:56Z", 2026, time.October, 31, 12, 34, 56},
		{"2024-02-29T23:59:59Z", 2024, time.February, 29, 23, 59, 59},
		{"2034-02-28T23:59:59Z", 2034, time.February, 28, 23, 59, 59},
		{"2026-04-30T00:00:00Z", 2026, time.April, 30, 0, 0, 0},
		{"0001-01-01T00:00:00Z", 1, time.January, 1, 0, 0, 0},
		{"9999-12-31T23:59:59Z", 9999, time.December, 31, 23, 59, 59},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := parseWireTime(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Year() != test.year || got.Month() != test.month || got.Day() != test.day || got.Hour() != test.hour || got.Minute() != test.minute || got.Second() != test.second || got.Nanosecond() != 0 || got.Location() != time.UTC {
				t.Fatalf("changed instant: %v", got)
			}
		})
	}
}

// Field-semantic refusals return bad-schema and no parsed time. The earlier
// lexical layer owns invalid JSON/non-ASCII classification; this helper does
// not normalize a received alias or establish any trusted observation.
func TestParseWireTimeRefusals(t *testing.T) {
	for _, raw := range []string{
		"2023-02-29T23:59:59Z", "2034-02-29T23:59:59Z", "2026-04-31T00:00:00Z",
		"2026-10-31T24:00:00Z", "2026-10-31T23:60:00Z", "2026-10-31T23:59:60Z",
		"0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "2026-00-31T12:34:56Z",
		"2026-13-31T12:34:56Z", "2026-10-00T12:34:56Z", "2026-10-32T12:34:56Z",
		"2026-10-31T12:34:56+00:00", "2026-10-31T12:34:56.0Z", "2026-10-31T12:34:56.000000001Z",
		"2026-10-31T12:34:56z", "2026-10-31t12:34:56Z", "2026-10-31 12:34:56Z",
		"2026-1-31T12:34:56Z", "2026-10-3T12:34:56Z", "2026-10-31T2:34:56Z",
		"2026-10-31T12:34:56Z ", " 2026-10-31T12:34:56Z", "2026-10-31T12:34:56Z\n",
		"2026-10-31T12:34:56Zx", "2026-10-31T12:34:56", "",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := parseWireTime(raw)
			if !errors.Is(err, errBadSchema) || !got.IsZero() {
				t.Fatalf("got %v/%v, want zero and bad-schema", got, err)
			}
		})
	}
	if _, err := parseWireTime("2024-02-29T23:59:59Z"); err != nil {
		t.Fatalf("nearby valid leap control: %v", err)
	}
}
