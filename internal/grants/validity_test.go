package grants

import (
	"errors"
	"testing"
	"time"
)

func parsedTime(t *testing.T, value string) time.Time {
	t.Helper()
	result, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("invalid test time %q: %v", value, err)
	}
	return result
}

// These literal date pairs check the agreed ten-calendar-year cap, including
// Feb 29 clamping and year limits; they do not qualify a clock or parse a wire.
func TestValidateInterval(t *testing.T) {
	tests := []struct {
		name, notBefore, expiresAt string
		want                       error
	}{
		{"ordinary exact cap", "2026-10-31T12:34:56Z", "2036-10-31T12:34:56Z", nil},
		{"short validity", "2026-10-31T12:34:56Z", "2026-10-31T12:34:57Z", nil},
		{"one second beyond cap", "2026-10-31T12:34:56Z", "2036-10-31T12:34:57Z", ErrLifetimeExceeded},
		{"leap day clamped cap", "2024-02-29T12:34:56Z", "2034-02-28T12:34:56Z", nil},
		{"leap clamp plus one second", "2024-02-29T12:34:56Z", "2034-02-28T12:34:57Z", ErrLifetimeExceeded},
		{"March rollover forbidden", "2024-02-29T12:34:56Z", "2034-03-01T12:34:56Z", ErrLifetimeExceeded},
		{"century neighbor", "2092-02-29T23:59:59Z", "2102-02-28T23:59:59Z", nil},
		{"first Gregorian year", "0001-01-01T00:00:00Z", "0011-01-01T00:00:00Z", nil},
		{"last supported anniversary", "9989-12-31T23:59:59Z", "9999-12-31T23:59:59Z", nil},
		{"anniversary outside supported years", "9990-01-01T00:00:00Z", "9991-01-01T00:00:00Z", ErrLifetimeExceeded},
		{"equal endpoints", "2026-10-31T12:34:56Z", "2026-10-31T12:34:56Z", ErrInvalidInterval},
		{"reversed endpoints", "2026-10-31T12:34:56Z", "2026-10-31T12:34:55Z", ErrInvalidInterval},
		{"fractional start", "2026-10-31T12:34:56.000000001Z", "2026-10-31T12:34:57Z", ErrInvalidInterval},
		{"fractional expiry", "2026-10-31T12:34:56Z", "2026-10-31T12:34:57.000000001Z", ErrInvalidInterval},
		{"year zero", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z", ErrInvalidInterval},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateInterval(parsedTime(t, test.notBefore), parsedTime(t, test.expiresAt))
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateInterval returned %v, want %v", err, test.want)
			}
		})
	}
}

// These observations check [notBefore, expiresAt) at exact and nanosecond
// neighbors. Passing supplied times is not proof of trusted time or authority.
func TestCheckIntervalAt(t *testing.T) {
	notBefore := parsedTime(t, "2026-10-31T12:00:00Z")
	expiresAt := parsedTime(t, "2026-10-31T13:00:00Z")
	tests := []struct {
		name, observation string
		want              error
	}{
		{"before start", "2026-10-31T11:59:59.999999999Z", ErrNotYetValid},
		{"at start", "2026-10-31T12:00:00Z", nil},
		{"inside", "2026-10-31T12:30:00Z", nil},
		{"last nanosecond", "2026-10-31T12:59:59.999999999Z", nil},
		{"at expiry", "2026-10-31T13:00:00Z", ErrExpired},
		{"after expiry", "2026-10-31T13:00:00.000000001Z", ErrExpired},
		{"unsupported observation year", "0000-01-01T00:00:00Z", ErrInvalidObservation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CheckIntervalAt(notBefore, expiresAt, parsedTime(t, test.observation))
			if !errors.Is(err, test.want) {
				t.Fatalf("CheckIntervalAt returned %v, want %v", err, test.want)
			}
		})
	}
}

// Invalid policy must not be accepted merely because the observation falls
// between its endpoints, or be misclassified as a valid-but-expired interval.
func TestCheckIntervalAtRejectsInvalidPolicy(t *testing.T) {
	notBefore := parsedTime(t, "2024-02-29T12:34:56Z")
	expiresAt := parsedTime(t, "2034-03-01T12:34:56Z")
	for _, observation := range []string{"2026-10-31T12:00:00Z", "2035-01-01T00:00:00Z"} {
		if err := CheckIntervalAt(notBefore, expiresAt, parsedTime(t, observation)); !errors.Is(err, ErrLifetimeExceeded) {
			t.Errorf("invalid lifetime at %s: got %v, want %v", observation, err, ErrLifetimeExceeded)
		}
	}
}
